import { afterEach, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { calls, makeFakeBin, runScript, sequence } from "./lib/fakes";

const script = join(import.meta.dir, "../claude/agent-claude.sh");
const libDir = join(import.meta.dir, "../lib");
const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((c) => c()));
});

// The claude fake records argv/env like every fake and keeps what arrived on
// stdin, which is where the prompt must travel.
const CLAUDE_BODY = `cat > "$FAKE_LOG/claude-stdin"`;

async function fixture() {
  const fake = await makeFakeBin(["claude"], { claude: CLAUDE_BODY });
  const work = await mkdtemp(join(tmpdir(), "hatchward-agent-claude-"));
  cleanups.push(() => rm(fake.root, { force: true, recursive: true }));
  cleanups.push(() => rm(work, { force: true, recursive: true }));
  const workspace = join(work, "workspace");
  const home = join(work, "home");
  const runDir = join(work, "run");
  await mkdir(join(workspace, ".git"), { recursive: true });
  await mkdir(home);
  await mkdir(runDir);
  const key = join(work, "anthropic_api_key");
  await Bun.write(key, "sk-sentinel\n");
  return { fake, work, workspace, home, runDir, key };
}

function baseEnv(
  f: Awaited<ReturnType<typeof fixture>>,
  extra: Record<string, string> = {},
) {
  return {
    AGENT_LIB_DIR: libDir,
    AGENT_WORKSPACE: f.workspace,
    CLAUDE_PROJECT_DIR: f.workspace,
    HOME: f.home,
    AGENT_RUN_DIR: f.runDir,
    ANTHROPIC_API_KEY_FILE: f.key,
    AGENT_PROMPT: "Do the thing",
    ...extra,
  };
}

test("runs claude headless with the prompt on stdin, json output, and the credential only in its environment", async () => {
  const f = await fixture();
  const r = await runScript(script, f.fake, baseEnv(f));
  expect(r.code).toBe(0);
  const [call] = await calls(f.fake, "claude");
  expect(call?.argv).toEqual([
    "--dangerously-skip-permissions",
    "-p",
    "--output-format",
    "json",
    "--max-turns",
    "200",
  ]);
  expect(await Bun.file(join(f.fake.log, "claude-stdin")).text()).toBe(
    "Do the thing\n",
  );
  expect(call?.env.ANTHROPIC_API_KEY).toBe("sk-sentinel");
  const everything = (await sequence(f.fake)).flatMap((s) => s.argv);
  expect(everything.join("\n")).not.toContain("sentinel");
  expect(r.stdout + r.stderr).not.toContain("sentinel");
});

test("model, max-turns and output format pass through; stream-json adds --verbose", async () => {
  const f = await fixture();
  await runScript(
    script,
    f.fake,
    baseEnv(f, {
      AGENT_MODEL: "opus",
      AGENT_MAX_TURNS: "40",
      AGENT_OUTPUT_FORMAT: "stream-json",
    }),
  );
  const [call] = await calls(f.fake, "claude");
  expect(call?.argv).toEqual([
    "--dangerously-skip-permissions",
    "-p",
    "--output-format",
    "stream-json",
    "--verbose",
    "--max-turns",
    "40",
    "--model",
    "opus",
  ]);
});

test("an empty AGENT_MODEL adds no --model flag", async () => {
  const f = await fixture();
  await runScript(script, f.fake, baseEnv(f, { AGENT_MODEL: "" }));
  const [call] = await calls(f.fake, "claude");
  expect(call?.argv).not.toContain("--model");
});

test("the manifest's model is used when AGENT_MODEL is unset", async () => {
  const f = await fixture();
  await Bun.write(
    join(f.runDir, "manifest.json"),
    JSON.stringify({ agent: { prompt: "From manifest", model: "sonnet" } }),
  );
  await runScript(script, f.fake, { ...baseEnv(f), AGENT_PROMPT: "" });
  const [call] = await calls(f.fake, "claude");
  expect(call?.argv.slice(-2)).toEqual(["--model", "sonnet"]);
  expect(await Bun.file(join(f.fake.log, "claude-stdin")).text()).toBe(
    "From manifest\n",
  );
});

test("pre-trusts the project directory in ~/.claude.json with only the two trust keys", async () => {
  const f = await fixture();
  // A fresh image has no ~/.claude.json at all.
  const projectDir = join(f.workspace, "apps/api");
  await mkdir(projectDir, { recursive: true });
  const fresh = await runScript(
    script,
    f.fake,
    baseEnv(f, { CLAUDE_PROJECT_DIR: projectDir }),
  );
  expect(fresh.code).toBe(0);
  expect(
    JSON.parse(await Bun.file(join(f.home, ".claude.json")).text()),
  ).toEqual({
    projects: {
      [projectDir]: {
        hasTrustDialogAccepted: true,
        hasCompletedProjectOnboarding: true,
      },
    },
  });
  // An existing file keeps everything it had.
  await Bun.write(
    join(f.home, ".claude.json"),
    JSON.stringify({ existing: true }),
  );
  await runScript(script, f.fake, baseEnv(f));
  expect(
    JSON.parse(await Bun.file(join(f.home, ".claude.json")).text()),
  ).toEqual({
    existing: true,
    projects: {
      [f.workspace]: {
        hasTrustDialogAccepted: true,
        hasCompletedProjectOnboarding: true,
      },
    },
  });
});

test("a trust file that cannot be updated is a contract error, not a silent skip", async () => {
  const f = await fixture();
  await Bun.write(join(f.home, ".claude.json"), "not json");
  const r = await runScript(script, f.fake, baseEnv(f));
  expect(r.code).toBe(2);
  expect(r.stderr).toContain(
    "agent-claude: could not write the workspace trust entry to",
  );
  expect(await calls(f.fake, "claude")).toHaveLength(0);
});

test("falls back to CLAUDE_CODE_OAUTH_TOKEN when no API key is configured", async () => {
  const f = await fixture();
  const token = join(f.work, "oauth");
  await Bun.write(token, "oauth-sentinel\n");
  const r = await runScript(script, f.fake, {
    ...baseEnv(f),
    ANTHROPIC_API_KEY_FILE: "",
    CLAUDE_CODE_OAUTH_TOKEN_FILE: token,
  });
  expect(r.code).toBe(0);
  const [call] = await calls(f.fake, "claude");
  expect(call?.env.CLAUDE_CODE_OAUTH_TOKEN).toBe("oauth-sentinel");
  expect(call?.env.ANTHROPIC_API_KEY).toBeUndefined();
});

test("refuses to start without a model credential", async () => {
  const f = await fixture();
  const r = await runScript(script, f.fake, {
    ...baseEnv(f),
    ANTHROPIC_API_KEY_FILE: "",
  });
  expect(r.code).toBe(2);
  expect(r.stdout).toBe("");
  expect(r.stderr).toContain(
    "agent-claude: no model credential — set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN (or their _FILE forms)",
  );
  expect(await calls(f.fake, "claude")).toHaveLength(0);
});

test("refuses to start without a prompt", async () => {
  const f = await fixture();
  const r = await runScript(script, f.fake, {
    ...baseEnv(f),
    AGENT_PROMPT: "",
  });
  expect(r.code).toBe(2);
  expect(r.stderr).toContain(
    "agent: no prompt — set AGENT_PROMPT, AGENT_PROMPT_FILE, or pass a manifest on stdin",
  );
  expect(await calls(f.fake, "claude")).toHaveLength(0);
});

test("refuses to start on an empty workspace", async () => {
  const f = await fixture();
  await rm(join(f.workspace, ".git"), { recursive: true });
  const r = await runScript(script, f.fake, baseEnv(f));
  expect(r.code).toBe(2);
  expect(r.stderr).toContain(
    "agent-claude: /workspace is empty — pre-clone the workspace or set AGENT_REPO",
  );
  expect(await calls(f.fake, "claude")).toHaveLength(0);
});

test("refuses to run with the firewall disabled unless the unsafe override is set", async () => {
  const f = await fixture();
  await Bun.write(join(f.runDir, "firewall-disabled"), "");
  const refused = await runScript(script, f.fake, baseEnv(f));
  expect(refused.code).toBe(2);
  expect(refused.stderr).toContain(
    "agent: refusing to run with --dangerously-skip-permissions while the firewall is disabled",
  );
  expect(await calls(f.fake, "claude")).toHaveLength(0);
  const allowed = await runScript(
    script,
    f.fake,
    baseEnv(f, { AGENT_UNSAFE_NO_FIREWALL: "1" }),
  );
  expect(allowed.code).toBe(0);
  expect(await calls(f.fake, "claude")).toHaveLength(1);
});
