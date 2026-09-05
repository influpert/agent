import { afterEach, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeFakeBin, runScript } from "./lib/fakes";

// lib/prompt.sh is sourced by every CLI layer's CMD script. These tests drive
// its functions through a one-line bash wrapper so the assertions are on what
// the functions print and return, not on how a CMD script happens to use them.
const lib = join(import.meta.dir, "../lib/prompt.sh");
const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((c) => c()));
});

async function fixture() {
  const fake = await makeFakeBin([]);
  const work = await mkdtemp(join(tmpdir(), "hatchward-prompt-"));
  cleanups.push(() => rm(fake.root, { force: true, recursive: true }));
  cleanups.push(() => rm(work, { force: true, recursive: true }));
  const runDir = join(work, "run");
  await mkdir(runDir);
  const wrapper = join(work, "call.sh");
  await Bun.write(wrapper, `. "${lib}"\n"$@"\n`);
  await chmod(wrapper, 0o755);
  return { fake, work, runDir, wrapper };
}

const MANIFEST = JSON.stringify({
  agent: { prompt: "Deliver the task.", model: "claude-opus-4-1" },
  task: {
    externalTaskId: "50000000-0000-4000-8000-000000000001",
    fields: [
      { field: "title", value: "Ship the runner" },
      { field: "labels", value: ["runner", "v1"] },
    ],
  },
});

test("agent_resolve_prompt prefers AGENT_PROMPT over every other source", async () => {
  const f = await fixture();
  await Bun.write(join(f.runDir, "manifest.json"), MANIFEST);
  const r = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir, AGENT_PROMPT: "From env" },
    { args: ["agent_resolve_prompt"] },
  );
  expect(r.code).toBe(0);
  expect(r.stdout).toBe("From env\n");
});

test("agent_resolve_prompt reads AGENT_PROMPT_FILE when AGENT_PROMPT is unset", async () => {
  const f = await fixture();
  const file = join(f.work, "prompt.txt");
  await Bun.write(file, "From file\nsecond line\n");
  const r = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir, AGENT_PROMPT_FILE: file },
    { args: ["agent_resolve_prompt"] },
  );
  expect(r.code).toBe(0);
  expect(r.stdout).toBe("From file\nsecond line\n");
});

test("agent_resolve_prompt falls back to the manifest prompt with the task fields rendered", async () => {
  const f = await fixture();
  await Bun.write(join(f.runDir, "manifest.json"), MANIFEST);
  const r = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir },
    { args: ["agent_resolve_prompt"] },
  );
  expect(r.code).toBe(0);
  expect(r.stdout).toBe(
    [
      "Deliver the task.",
      "",
      "## Task",
      "",
      "- title: Ship the runner",
      '- labels: ["runner","v1"]',
      "",
    ].join("\n"),
  );
});

test("agent_resolve_prompt fails with a named line when no source has a prompt", async () => {
  const f = await fixture();
  const r = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir, AGENT_PROMPT: "" },
    { args: ["agent_resolve_prompt"] },
  );
  expect(r.code).toBe(2);
  expect(r.stdout).toBe("");
  expect(r.stderr).toContain(
    "agent: no prompt — set AGENT_PROMPT, AGENT_PROMPT_FILE, or pass a manifest on stdin",
  );
});

test("agent_resolve_model prefers AGENT_MODEL, then the manifest, then prints nothing", async () => {
  const f = await fixture();
  await Bun.write(join(f.runDir, "manifest.json"), MANIFEST);
  const env = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir, AGENT_MODEL: "sonnet" },
    { args: ["agent_resolve_model"] },
  );
  expect(env.stdout).toBe("sonnet\n");
  const manifest = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir },
    { args: ["agent_resolve_model"] },
  );
  expect(manifest.stdout).toBe("claude-opus-4-1\n");
  await rm(join(f.runDir, "manifest.json"));
  const none = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir },
    { args: ["agent_resolve_model"] },
  );
  expect(none.code).toBe(0);
  expect(none.stdout).toBe("");
});

test("agent_resolve_secret reads the variable, else its _FILE, and never echoes to stderr", async () => {
  const f = await fixture();
  const file = join(f.work, "key");
  await Bun.write(file, "sk-from-file\n");
  const fromEnv = await runScript(
    f.wrapper,
    f.fake,
    { ANTHROPIC_API_KEY: "sk-from-env", ANTHROPIC_API_KEY_FILE: file },
    { args: ["agent_resolve_secret", "ANTHROPIC_API_KEY"] },
  );
  expect(fromEnv.stdout).toBe("sk-from-env\n");
  const fromFile = await runScript(
    f.wrapper,
    f.fake,
    { ANTHROPIC_API_KEY_FILE: file },
    { args: ["agent_resolve_secret", "ANTHROPIC_API_KEY"] },
  );
  expect(fromFile.stdout).toBe("sk-from-file\n");
  expect(fromFile.stderr).toBe("");
  const missing = await runScript(
    f.wrapper,
    f.fake,
    {},
    { args: ["agent_resolve_secret", "ANTHROPIC_API_KEY"] },
  );
  expect(missing.code).toBe(1);
  expect(missing.stdout).toBe("");
  expect(missing.stderr).toBe("");
});

test("agent_require_firewall refuses to continue when the firewall was disabled without the unsafe override", async () => {
  const f = await fixture();
  const ok = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir },
    { args: ["agent_require_firewall"] },
  );
  expect(ok.code).toBe(0);
  await Bun.write(join(f.runDir, "firewall-disabled"), "");
  const refused = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir },
    { args: ["agent_require_firewall"] },
  );
  expect(refused.code).toBe(2);
  expect(refused.stderr).toContain(
    "agent: refusing to run with --dangerously-skip-permissions while the firewall is disabled (set AGENT_UNSAFE_NO_FIREWALL=1 to override)",
  );
  const overridden = await runScript(
    f.wrapper,
    f.fake,
    { AGENT_RUN_DIR: f.runDir, AGENT_UNSAFE_NO_FIREWALL: "1" },
    { args: ["agent_require_firewall"] },
  );
  expect(overridden.code).toBe(0);
  expect(overridden.stderr).toContain(
    "agent: WARNING — firewall disabled and AGENT_UNSAFE_NO_FIREWALL=1; the agent can reach host services",
  );
});
