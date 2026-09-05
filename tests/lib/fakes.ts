import { chmod, mkdir, mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Recording fakes for the external commands the agent-image scripts call.
 *
 * Every invocation of a fake writes one record to `$FAKE_LOG/<seq>.<name>`:
 * argv NUL-separated on the first line, then the fake's entire environment as
 * `KEY=value` lines — so "not present" in a parsed record means unset, and a
 * negative assertion cannot pass by omission. Behaviour is
 * steered by FAKE_* variables the bodies below read. Assertions read the
 * records back with `calls()`; nothing asserts on the fake's own behaviour.
 */
export interface FakeBin {
  dir: string;
  log: string;
  root: string;
}

export interface Call {
  argv: string[];
  env: Record<string, string>;
}

const RECORDER = `
_fake_record() {
  n=$(ls "$FAKE_LOG" 2>/dev/null | wc -l | tr -d ' ')
  f="$FAKE_LOG/$(printf '%04d' "$n").$FAKE_NAME"
  : > "$f"
  for a in "$@"; do printf '%s\\0' "$a" >> "$f"; done
  printf '\\n' >> "$f"
  env >> "$f"
}
`;

const BODIES: Record<string, string> = {
  // Succeeds when the URL matches the FAKE_CURL_OK extended regex (a `-6`
  // request instead matches FAKE_CURL6_OK); on api.github.com/meta it also
  // prints FAKE_CURL_META_JSON. Else exit 7.
  curl: `
url=""; v6=0
for a in "$@"; do case "$a" in http://*|https://*) url="$a";; -6) v6=1;; esac; done
ok="\${FAKE_CURL_OK-}"; [ "$v6" = 0 ] || ok="\${FAKE_CURL6_OK-}"
if [ -n "$ok" ] && printf '%s' "$url" | grep -Eq "$ok"; then
  case "$url" in *api.github.com/meta*) printf '%s' "\${FAKE_CURL_META_JSON-}";; esac
  exit 0
fi
exit 7
`,
  // getent ahostsv4 <host>; FAKE_GETENT_MAP="host=ip ip;host2=ip"
  getent: `
host="$2"
printf '%s\\n' "\${FAKE_GETENT_MAP-}" | tr ';' '\\n' | while IFS='=' read -r h ips; do
  if [ "$h" = "$host" ]; then
    for ip in $ips; do printf '%s STREAM %s\\n' "$ip" "$host"; done
  fi
done
exit 0
`,
  // ip -o link show → FAKE_IP_LINKS (';'-separated lines); ip -6 route show default → FAKE_IP6_ROUTE
  ip: `
case "$*" in
  *"-6 route show default"*) [ -z "\${FAKE_IP6_ROUTE-}" ] || printf '%s\\n' "$FAKE_IP6_ROUTE";;
  *"link show"*) printf '%s\\n' "\${FAKE_IP_LINKS-1: lo: <LOOPBACK,UP>}" | tr ';' '\\n';;
esac
exit 0
`,
  iptables: `[ "\${FAKE_IPTABLES_FAIL-0}" = "1" ] && exit 1; exit 0`,
  ip6tables: `[ "\${FAKE_IP6TABLES_FAIL-0}" = "1" ] && exit 1; exit 0`,
};

export async function makeFakeBin(
  names: string[],
  extra: Record<string, string> = {},
): Promise<FakeBin> {
  const root = await mkdtemp(join(tmpdir(), "hatchward-agent-fakes-"));
  const dir = join(root, "bin");
  const log = join(root, "log");
  await mkdir(dir);
  await mkdir(log);
  for (const name of names) {
    const body = extra[name] ?? BODIES[name] ?? "exit 0\n";
    await Bun.write(
      join(dir, name),
      `#!/bin/sh\nFAKE_NAME=${name}\n${RECORDER}\n_fake_record "$@"\n${body}\n`,
    );
    await chmod(join(dir, name), 0o755);
  }
  return { dir, log, root };
}

async function parseRecord(path: string): Promise<Call> {
  const text = await readFile(path, "utf8");
  const newline = text.indexOf("\n");
  const argvPart = text.slice(0, newline);
  const argv = argvPart.split("\0");
  argv.pop(); // trailing NUL terminator
  const env: Record<string, string> = {};
  for (const line of text.slice(newline + 1).split("\n")) {
    const eq = line.indexOf("=");
    // `env` prints one line per variable; a continuation line of a multi-line
    // value has no '=' at a sane position and is not a variable of interest.
    if (eq <= 0 || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(line.slice(0, eq)))
      continue;
    env[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return { argv, env };
}

/** Every recorded invocation of `name`, in call order. */
export async function calls(fake: FakeBin, name: string): Promise<Call[]> {
  const files = (await readdir(fake.log))
    .filter((f) => f.endsWith(`.${name}`))
    .sort();
  return Promise.all(files.map((f) => parseRecord(join(fake.log, f))));
}

/** Every recorded invocation of any fake, in global call order. */
export async function sequence(
  fake: FakeBin,
): Promise<{ name: string; argv: string[] }[]> {
  const files = (await readdir(fake.log)).sort();
  return Promise.all(
    files.map(async (f) => ({
      name: f.slice(f.indexOf(".") + 1),
      argv: (await parseRecord(join(fake.log, f))).argv,
    })),
  );
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Runs a script with the fake bin first on PATH and only the environment
 * given here (plus the recorder wiring). Nothing from the test process's
 * own environment leaks in, so a decoy set there cannot satisfy an assertion.
 */
export async function runScript(
  script: string,
  fake: FakeBin,
  env: Record<string, string>,
  options: { stdin?: string; args?: string[] } = {},
): Promise<RunResult> {
  const child = Bun.spawn(["bash", script, ...(options.args ?? [])], {
    env: {
      PATH: `${fake.dir}:/usr/bin:/bin`,
      FAKE_LOG: fake.log,
      ...env,
    },
    stdin: options.stdin === undefined ? "ignore" : new Blob([options.stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { code, stdout, stderr };
}
