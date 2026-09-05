import { afterEach, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { calls, makeFakeBin, runScript, sequence } from "./lib/fakes";

const script = join(import.meta.dir, "../agent-entrypoint.sh");
const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((c) => c()));
});

// setpriv is the privilege-drop seam. Its fake records the call, then runs the
// command it was asked to drop into (`env HOME=... PATH=... <cmd>`), so the
// commands the entrypoint runs "as agent" are themselves recorded as fakes.
const SETPRIV_BODY = `
while [ $# -gt 0 ]; do
  case "$1" in
    --no-new-privs) shift; break;;
    *) shift;;
  esac
done
exec "$@"
`;

// A stand-in for the CMD: records argv/env like every fake and reports how
// many bytes reached its stdin.
const FINAL_BODY = `printf 'stdin_bytes=%s stdin_is_devnull=%s\\n' "$(cat | wc -c | tr -d ' ')" "$([ /dev/stdin -ef /dev/null ] && echo 1 || echo 0)"`;

// git: symbolic-ref answers with FAKE_GIT_DEFAULT_BRANCH; check-ref-format
// refuses names starting with '-'; everything else succeeds silently.
const GIT_BODY = `
case "$*" in
  *"symbolic-ref --short refs/remotes/origin/HEAD"*) printf 'origin/%s\\n' "\${FAKE_GIT_DEFAULT_BRANCH-main}";;
  *"check-ref-format --branch -"*) exit 1;;
esac
exit 0
`;

// gh: `auth login --with-token` consumes stdin; record what it received so the
// test can prove the token travelled on stdin and nowhere else.
const GH_BODY = `
case "$*" in
  *"auth login --with-token"*) cat > "$FAKE_LOG/gh-login-stdin";;
esac
exit 0
`;

// stat -c %u <path>: FAKE_STAT_UIDS="<path>=<uid>;<path>=<uid>" per path, else FAKE_STAT_UID, else 1000.
const STAT_BODY = `
u="$(printf '%s\\n' "\${FAKE_STAT_UIDS-}" | tr ';' '\\n' | awk -F= -v p="$3" '$1==p{print $2}')"
printf '%s\\n' "\${u:-\${FAKE_STAT_UID-1000}}"`;
const ID_BODY = `printf '1000\\n'`;

const FAKES = [
  "init-firewall",
  "setpriv",
  "final",
  "git",
  "gh",
  "stat",
  "id",
  "chown",
];

async function fixture(options: { git?: boolean; files?: string[] } = {}) {
  const fake = await makeFakeBin(FAKES, {
    setpriv: SETPRIV_BODY,
    final: FINAL_BODY,
    git: GIT_BODY,
    gh: GH_BODY,
    stat: STAT_BODY,
    id: ID_BODY,
  });
  const work = await mkdtemp(join(tmpdir(), "hatchward-entrypoint-"));
  cleanups.push(() => rm(fake.root, { force: true, recursive: true }));
  cleanups.push(() => rm(work, { force: true, recursive: true }));
  const workspace = join(work, "workspace");
  const home = join(work, "home");
  const runDir = join(work, "run");
  await mkdir(workspace);
  await mkdir(home);
  await mkdir(runDir);
  if (options.git) await mkdir(join(workspace, ".git"));
  for (const f of options.files ?? []) await Bun.write(join(workspace, f), "");
  return { fake, work, workspace, home, runDir };
}

function baseEnv(
  f: { workspace: string; home: string; runDir: string },
  extra: Record<string, string> = {},
) {
  return {
    AGENT_WORKSPACE: f.workspace,
    AGENT_HOME: f.home,
    AGENT_RUN_DIR: f.runDir,
    ...extra,
  };
}

async function run(
  f: { fake: Awaited<ReturnType<typeof fixture>>["fake"] } & {
    workspace: string;
    home: string;
    runDir: string;
  },
  extra: Record<string, string> = {},
  options: { stdin?: string } = {},
) {
  return runScript(script, f.fake, baseEnv(f, extra), {
    args: ["final"],
    ...options,
  });
}

test("the firewall runs before anything else and the command is exec'd as agent with dropped privileges", async () => {
  const f = await fixture({ git: true });
  const r = await run(f);
  expect(r.code).toBe(0);
  const seq = await sequence(f.fake);
  expect(seq[0]?.name).toBe("init-firewall");
  const drops = await calls(f.fake, "setpriv");
  const last = drops.at(-1);
  expect(last?.argv.slice(0, 6)).toEqual([
    "--reuid=agent",
    "--regid=agent",
    "--init-groups",
    "--inh-caps=-all",
    "--bounding-set=-all",
    "--no-new-privs",
  ]);
  const envIndex = last?.argv.indexOf("env") ?? -1;
  expect(envIndex).toBeGreaterThan(0);
  expect(last?.argv.at(-1)).toBe("final");
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.HOME).toBe(f.home);
  expect(final?.env.PATH).toContain(`${f.home}/.local/bin`);
});

test("provisioning output goes to stderr and fd 1 is left to the command", async () => {
  const f = await fixture({ git: true });
  const r = await run(f);
  expect(r.stdout).toBe("stdin_bytes=0 stdin_is_devnull=1\n");
});

test("a provided workspace with .git and no AGENT_REPO is left untouched", async () => {
  const f = await fixture({ git: true });
  const r = await run(f);
  expect(r.code).toBe(0);
  const git = (await calls(f.fake, "git")).map((c) => c.argv.join(" "));
  expect(git.some((a) => /clone|fetch|reset|checkout|clean/.test(a))).toBe(
    false,
  );
});

test("an empty workspace with no AGENT_REPO warns but still runs the command", async () => {
  const f = await fixture();
  const r = await run(f);
  expect(r.code).toBe(0);
  expect(r.stderr).toContain(
    "agent-entrypoint: WARNING — /workspace is empty and AGENT_REPO is unset; nothing to provision",
  );
  expect(await calls(f.fake, "final")).toHaveLength(1);
});

test("self-clone mode clones an empty workspace over HTTPS with plain git, then syncs to the branch tip", async () => {
  const f = await fixture();
  const r = await run(f, {
    AGENT_REPO: "octocat/Hello-World",
    AGENT_BASE_BRANCH: "release",
    AGENT_CLONE_ARGS: "--filter=blob:none",
  });
  expect(r.code).toBe(0);
  const git = (await calls(f.fake, "git")).map((c) => c.argv);
  expect(git[0]).toEqual([
    "-C",
    f.workspace,
    "check-ref-format",
    "--branch",
    "release",
  ]);
  expect(git[1]).toEqual([
    "clone",
    "-q",
    "--filter=blob:none",
    "--branch",
    "release",
    "https://github.com/octocat/Hello-World.git",
    f.workspace,
  ]);
  const rest = git.slice(2).map((a) => a.join(" "));
  const inWorkspace = `-C ${f.workspace}`;
  expect(rest).toEqual([
    `${inWorkspace} remote set-head origin --auto`,
    `${inWorkspace} fetch -q origin +refs/heads/release:refs/remotes/origin/release`,
    `${inWorkspace} checkout -q -B release origin/release`,
    `${inWorkspace} reset -q --hard origin/release`,
    `${inWorkspace} clean -q -fd`,
    `${inWorkspace} worktree prune`,
    `${inWorkspace} submodule -q update --init --recursive`,
    `config --global --add safe.directory ${f.workspace}`,
    "config --global user.name hatchward-agent",
    "config --global user.email agent@hatchward.invalid",
  ]);
  // Every git call ran as agent, not root.
  const drops = await calls(f.fake, "setpriv");
  expect(drops.filter((d) => d.argv.includes("git"))).toHaveLength(git.length);
});

test("self-clone mode accepts a full https URL and defaults the branch to origin's HEAD", async () => {
  const f = await fixture({ git: true });
  const r = await run(f, {
    AGENT_REPO: "https://gitlab.example/group/repo.git",
    FAKE_GIT_DEFAULT_BRANCH: "develop",
  });
  expect(r.code).toBe(0);
  const git = (await calls(f.fake, "git")).map((c) => c.argv.join(" "));
  expect(git.some((a) => a.startsWith("clone"))).toBe(false);
  expect(git).toContain(
    `-C ${f.workspace} symbolic-ref --short refs/remotes/origin/HEAD`,
  );
  expect(git).toContain(
    `-C ${f.workspace} checkout -q -B develop origin/develop`,
  );
});

test("an AGENT_REPO that is not owner/name or an https URL is fatal before any network call", async () => {
  for (const bad of ["-evil", "a/b/c", "ssh://git@github.com/a/b", "a b/c"]) {
    const f = await fixture();
    const r = await run(f, { AGENT_REPO: bad });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(
      `agent-entrypoint: FATAL — AGENT_REPO '${bad}' must be owner/name or an https:// URL`,
    );
    expect(await calls(f.fake, "git")).toHaveLength(0);
  }
});

test("an AGENT_REPO URL carrying credentials is fatal", async () => {
  const f = await fixture();
  const r = await run(f, {
    AGENT_REPO: "https://x:ghp_sentinel@github.com/o/r",
  });
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_REPO must not carry credentials; use GH_TOKEN_FILE",
  );
  expect(r.stderr).not.toContain("ghp_sentinel");
  expect(await calls(f.fake, "git")).toHaveLength(0);
});

test("an AGENT_WORKDIR that escapes the workspace is fatal", async () => {
  for (const bad of ["../etc", "/etc", "apps/../../x", ".."]) {
    const f = await fixture({ git: true });
    const r = await run(f, { AGENT_WORKDIR: bad });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(
      `agent-entrypoint: FATAL — AGENT_WORKDIR '${bad}' must be a relative path inside /workspace`,
    );
    expect(await calls(f.fake, "final")).toHaveLength(0);
  }
});

test("a variable outside AGENT_STAGE_VARS is not staged and reaches the command untouched", async () => {
  const f = await fixture({ git: true });
  await run(f, { OPENAI_API_KEY: "not-a-secret-here" });
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.OPENAI_API_KEY).toBe("not-a-secret-here");
  await expect(
    stat(join(f.runDir, "secrets/openai_api_key")),
  ).rejects.toThrow();
});

test("an AGENT_BASE_BRANCH that git refuses is fatal", async () => {
  const f = await fixture();
  const r = await run(f, { AGENT_REPO: "o/r", AGENT_BASE_BRANCH: "-x" });
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_BASE_BRANCH '-x' is not a valid branch name",
  );
});

test("a workspace owned by another uid is chowned recursively; an agent-owned one is not touched", async () => {
  const foreign = await fixture({ git: true });
  await run(foreign, { FAKE_STAT_UID: "0" });
  expect((await calls(foreign.fake, "chown")).map((c) => c.argv)).toEqual([
    ["-R", "agent:agent", foreign.workspace],
  ]);
  const owned = await fixture({ git: true });
  await run(owned, { FAKE_STAT_UID: "1000" });
  expect(await calls(owned.fake, "chown")).toHaveLength(0);
  // The docker cp shape: the directory is agent-owned, its contents are root's.
  const copied = await fixture({ git: true });
  await run(copied, {
    FAKE_STAT_UIDS: `${copied.workspace}=1000;${join(copied.workspace, ".git")}=0`,
  });
  expect((await calls(copied.fake, "chown")).map((c) => c.argv)).toEqual([
    ["-R", "agent:agent", copied.workspace],
  ]);
});

test("a non-TTY stdin is captured to the manifest file and the command's stdin is /dev/null", async () => {
  const f = await fixture({ git: true });
  const manifest = '{"agent":{"prompt":"hi"}}';
  const r = await run(f, {}, { stdin: manifest });
  expect(r.code).toBe(0);
  expect(await Bun.file(join(f.runDir, "manifest.json")).text()).toBe(manifest);
  expect((await stat(join(f.runDir, "manifest.json"))).mode & 0o777).toBe(
    0o600,
  );
  expect((await calls(f.fake, "chown")).map((c) => c.argv)).toContainEqual([
    "agent:agent",
    join(f.runDir, "manifest.json"),
  ]);
  expect(r.stdout).toBe("stdin_bytes=0 stdin_is_devnull=1\n");
});

test("secret files are copied for the agent, the _FILE variables are re-pointed, and values never enter argv", async () => {
  const f = await fixture({ git: true });
  const key = join(f.work, "anthropic");
  const gh = join(f.work, "github");
  await Bun.write(key, "sk-sentinel-anthropic\n");
  await Bun.write(gh, "ghp_sentinel\n");
  const r = await run(f, {
    AGENT_STAGE_VARS: "GH_TOKEN ANTHROPIC_API_KEY",
    ANTHROPIC_API_KEY_FILE: key,
    GH_TOKEN_FILE: gh,
  });
  expect(r.code).toBe(0);
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.ANTHROPIC_API_KEY_FILE).toBe(
    join(f.runDir, "secrets/anthropic_api_key"),
  );
  expect(final?.env.GH_TOKEN_FILE).toBe(join(f.runDir, "secrets/gh_token"));
  expect(final?.env.GH_TOKEN).toBeUndefined();
  expect(final?.env.ANTHROPIC_API_KEY).toBeUndefined();
  expect(
    await Bun.file(join(f.runDir, "secrets/anthropic_api_key")).text(),
  ).toBe("sk-sentinel-anthropic\n");
  expect(
    (await stat(join(f.runDir, "secrets/anthropic_api_key"))).mode & 0o777,
  ).toBe(0o400);
  // The directory itself is handed to the agent, or the 0400 copies inside a
  // root-owned 0700 directory would be unreadable after the privilege drop.
  expect((await stat(join(f.runDir, "secrets"))).mode & 0o777).toBe(0o700);
  expect((await calls(f.fake, "chown")).map((c) => c.argv)).toContainEqual([
    "agent:agent",
    join(f.runDir, "secrets"),
  ]);
  // gh receives the token on stdin, once, and configures git.
  expect(await Bun.file(join(f.fake.log, "gh-login-stdin")).text()).toBe(
    "ghp_sentinel\n",
  );
  const ghCalls = (await calls(f.fake, "gh")).map((c) => c.argv.join(" "));
  expect(ghCalls).toEqual(["auth login --with-token", "auth setup-git"]);
  // No recorded argv anywhere carries a secret value.
  const everything = (await sequence(f.fake)).flatMap((s) => s.argv);
  expect(everything.join("\n")).not.toContain("sentinel");
  expect(r.stdout + r.stderr).not.toContain("sentinel");
});

test("a secret passed as a plain variable is staged to a file and removed from the environment", async () => {
  const f = await fixture({ git: true });
  const r = await run(f, { GH_TOKEN: "ghp_sentinel_plain" });
  expect(r.code).toBe(0);
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.GH_TOKEN).toBeUndefined();
  expect(final?.env.GH_TOKEN_FILE).toBe(join(f.runDir, "secrets/gh_token"));
  expect(await Bun.file(join(f.runDir, "secrets/gh_token")).text()).toBe(
    "ghp_sentinel_plain\n",
  );
  expect(await Bun.file(join(f.fake.log, "gh-login-stdin")).text()).toBe(
    "ghp_sentinel_plain\n",
  );
  const everything = (await sequence(f.fake)).flatMap((s) => s.argv);
  expect(everything.join("\n")).not.toContain("sentinel");
});

test("without a GitHub token, gh is never invoked", async () => {
  const f = await fixture({ git: true });
  await run(f);
  expect(await calls(f.fake, "gh")).toHaveLength(0);
});

test("AGENT_WORKDIR is where the command starts and CLAUDE_PROJECT_DIR follows it", async () => {
  const f = await fixture({ git: true });
  await mkdir(join(f.workspace, "apps/api"), { recursive: true });
  const final = await makeFakeBin(["final"], { final: "pwd" });
  cleanups.push(() => rm(final.root, { force: true, recursive: true }));
  const r = await runScript(
    script,
    f.fake,
    {
      ...baseEnv(f, { AGENT_WORKDIR: "apps/api" }),
      PATH: `${f.fake.dir}:${final.dir}:/usr/bin:/bin`,
    },
    { args: ["sh", "-c", "pwd; printf '%s\\n' \"$CLAUDE_PROJECT_DIR\""] },
  );
  expect(r.code).toBe(0);
  expect(r.stdout).toBe(
    `${join(f.workspace, "apps/api")}\n${join(f.workspace, "apps/api")}\n`,
  );
});

test("HATCHWARD_ASSIGNMENT_ACTION_SOCKET passes through to the command untouched", async () => {
  const f = await fixture({ git: true });
  await run(f, {
    HATCHWARD_ASSIGNMENT_ACTION_SOCKET: "/run/hatchward/actions.sock",
  });
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.HATCHWARD_ASSIGNMENT_ACTION_SOCKET).toBe(
    "/run/hatchward/actions.sock",
  );
});
