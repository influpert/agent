import { afterEach, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { calls, makeFakeBin, runScript, sequence } from "./lib/fakes";

const script = join(import.meta.dir, "../init-firewall.sh");
const FAKES = ["ip", "iptables", "ip6tables", "getent", "curl"];
const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((c) => c()));
});

async function fixture(allowFiles: Record<string, string> = {}) {
  const fake = await makeFakeBin(FAKES);
  const work = await mkdtemp(join(tmpdir(), "hatchward-firewall-"));
  cleanups.push(() => rm(fake.root, { force: true, recursive: true }));
  cleanups.push(() => rm(work, { force: true, recursive: true }));
  const allowDir = join(work, "allow-domains.d");
  const rangesDir = join(work, "allow-ranges.d");
  const runDir = join(work, "run");
  await mkdir(allowDir);
  await mkdir(rangesDir);
  await mkdir(runDir);
  for (const [name, body] of Object.entries(allowFiles)) {
    await Bun.write(join(allowDir, name), body);
  }
  const resolvConf = join(work, "resolv.conf");
  await Bun.write(resolvConf, "search example\nnameserver 192.168.65.7\n");
  return { fake, allowDir, rangesDir, runDir, resolvConf };
}

// A bridge-attached container: one loopback and one veth.
const BRIDGED = "1: lo: <LOOPBACK,UP>;2: eth0: <BROADCAST,UP>";

function baseEnv(
  f: {
    allowDir: string;
    rangesDir: string;
    runDir: string;
    resolvConf: string;
  },
  extra: Record<string, string> = {},
) {
  return {
    AGENT_ALLOW_DIR: f.allowDir,
    AGENT_RANGES_DIR: f.rangesDir,
    AGENT_RUN_DIR: f.runDir,
    AGENT_RESOLV_CONF: f.resolvConf,
    FAKE_IP_LINKS: BRIDGED,
    // Positive canary reaches api.github.com; the negative canary to
    // example.com must fail for the firewall to be "in effect".
    FAKE_CURL_OK: "api\\.github\\.com",
    ...extra,
  };
}

function acceptRules(argvs: string[][]): string[] {
  return argvs
    .filter(
      (a) =>
        a[0] === "-A" &&
        a[1] === "OUTPUT" &&
        a.includes("-d") &&
        !a.includes("--dport") &&
        a.at(-1) === "ACCEPT",
    )
    .map((a) => a[a.indexOf("-d") + 1]);
}

test("AGENT_FIREWALL=0 skips every rule and leaves a marker for the CMD guard", async () => {
  const f = await fixture();
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, { AGENT_FIREWALL: "0" }),
  );
  expect(r.code).toBe(0);
  expect(r.stdout).toBe("");
  expect(r.stderr).toContain("init-firewall: DISABLED via AGENT_FIREWALL=0");
  expect(await calls(f.fake, "iptables")).toHaveLength(0);
  expect((await stat(join(f.runDir, "firewall-disabled"))).isFile()).toBe(true);
});

test("a container with no non-loopback interface needs no firewall and exits 0", async () => {
  const f = await fixture();
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, { FAKE_IP_LINKS: "1: lo: <LOOPBACK,UP>" }),
  );
  expect(r.code).toBe(0);
  expect(r.stderr).toContain(
    "init-firewall: no egress interface; firewall not required",
  );
  expect(await calls(f.fake, "iptables")).toHaveLength(0);
  await expect(stat(join(f.runDir, "firewall-disabled"))).rejects.toThrow();
});

test("an interface without usable iptables is fatal with the named line", async () => {
  const f = await fixture();
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, { FAKE_IPTABLES_FAIL: "1" }),
  );
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "init-firewall: FATAL — cannot use iptables (needs --cap-add=NET_ADMIN and a netfilter-capable kernel)",
  );
});

test("allowlist merges allow-domains.d files and AGENT_ALLOW_DOMAINS, deduplicating by address", async () => {
  const f = await fixture({
    base: "# comment line\ngithub.com\n\nregistry.npmjs.org # trailing comment\n",
    claude: "api.anthropic.com\n",
  });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, {
      AGENT_ALLOW_DOMAINS: "pypi.org, files.pythonhosted.org extra.example",
      FAKE_GETENT_MAP:
        "github.com=140.82.1.1 140.82.1.2;registry.npmjs.org=104.16.1.1;api.anthropic.com=160.79.1.1;pypi.org=151.101.1.1;files.pythonhosted.org=151.101.1.1;extra.example=198.41.0.4",
    }),
  );
  expect(r.code).toBe(0);
  const argvs = (await calls(f.fake, "iptables")).map((c) => c.argv);
  const accepted = acceptRules(argvs).sort();
  // Six hosts, seven addresses, one shared → six distinct ACCEPT targets.
  expect(accepted).toEqual(
    [
      "104.16.1.1",
      "140.82.1.1",
      "140.82.1.2",
      "151.101.1.1",
      "160.79.1.1",
      "198.41.0.4",
    ].sort(),
  );
  // Each host is resolved three times so round-robin answers are unioned.
  const resolved = (await calls(f.fake, "getent")).map((c) => c.argv[1]);
  expect(resolved).toHaveLength(18);
  expect([...new Set(resolved)].sort()).toEqual(
    [
      "api.anthropic.com",
      "extra.example",
      "files.pythonhosted.org",
      "github.com",
      "pypi.org",
      "registry.npmjs.org",
    ].sort(),
  );
});

test("addresses in private, loopback, link-local, CGNAT or multicast ranges are dropped with a warning", async () => {
  const f = await fixture({ base: "github.com\nevil.example\n" });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, {
      AGENT_ALLOW_DOMAINS: "host.docker.internal",
      FAKE_GETENT_MAP:
        "github.com=140.82.1.1;evil.example=10.1.2.3 172.16.5.5 192.168.1.1 127.0.0.2 169.254.1.1 100.64.0.1 224.0.0.5;host.docker.internal=192.168.65.254",
    }),
  );
  expect(r.code).toBe(0);
  const accepted = acceptRules(
    (await calls(f.fake, "iptables")).map((c) => c.argv),
  );
  expect(accepted).toEqual(["140.82.1.1"]);
  expect(r.stderr).toContain(
    "init-firewall: WARNING — dropping non-public address 192.168.65.254 for host.docker.internal",
  );
  expect(r.stderr).toContain(
    "init-firewall: WARNING — dropping non-public address 10.1.2.3 for evil.example",
  );
});

test("AGENT_ALLOW_DOMAINS entries that are not hostnames are refused", async () => {
  const f = await fixture({ base: "github.com\n" });
  for (const bad of ["10.0.0.0/8", "192.168.1.1", "bad/host"]) {
    const r = await runScript(
      script,
      f.fake,
      baseEnv(f, {
        AGENT_ALLOW_DOMAINS: bad,
        FAKE_GETENT_MAP: "github.com=140.82.1.1",
      }),
    );
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(
      `init-firewall: FATAL — AGENT_ALLOW_DOMAINS entry '${bad}' is not a hostname`,
    );
  }
});

test("GitHub meta CIDRs are permitted as well as resolved addresses", async () => {
  const f = await fixture({ base: "github.com\n" });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, {
      FAKE_GETENT_MAP: "github.com=140.82.1.1",
      FAKE_CURL_META_JSON: JSON.stringify({
        web: ["140.82.112.0/20"],
        api: ["192.30.252.0/22"],
        git: ["2606:50c0::/32"],
      }),
    }),
  );
  expect(r.code).toBe(0);
  const accepted = acceptRules(
    (await calls(f.fake, "iptables")).map((c) => c.argv),
  ).sort();
  expect(accepted).toEqual(
    ["140.82.1.1", "140.82.112.0/20", "192.30.252.0/22"].sort(),
  );
});

test("default policies flip to DROP only after every ACCEPT rule, then the canaries run", async () => {
  const f = await fixture({ base: "github.com\n" });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, { FAKE_GETENT_MAP: "github.com=140.82.1.1" }),
  );
  expect(r.code).toBe(0);
  const seq = await sequence(f.fake);
  const lastAccept =
    seq
      .map((s, i) => (s.name === "iptables" && s.argv[0] === "-A" ? i : -1))
      .filter((i) => i >= 0)
      .at(-1) ?? -1;
  const firstDrop = seq.findIndex(
    (s) =>
      s.name === "iptables" && s.argv[0] === "-P" && s.argv.at(-1) === "DROP",
  );
  const firstCanary = seq.findIndex(
    (s) => s.name === "curl" && s.argv.some((a) => a.includes("example.com")),
  );
  expect(lastAccept).toBeGreaterThan(-1);
  expect(firstDrop).toBeGreaterThan(lastAccept);
  expect(firstCanary).toBeGreaterThan(firstDrop);
  // The whole rule set, in order: nothing here is optional.
  const rules = seq
    .filter((s) => s.name === "iptables")
    .map((s) => s.argv.join(" "));
  expect(rules).toEqual([
    "-L -n",
    "-P INPUT ACCEPT",
    "-P OUTPUT ACCEPT",
    "-P FORWARD ACCEPT",
    "-F",
    "-A OUTPUT -o lo -j ACCEPT",
    "-A INPUT -i lo -j ACCEPT",
    "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    "-A OUTPUT -p udp --dport 53 -d 192.168.65.7 -j ACCEPT",
    "-A OUTPUT -p tcp --dport 53 -d 192.168.65.7 -j ACCEPT",
    "-A OUTPUT -d 140.82.1.1 -j ACCEPT",
    "-P OUTPUT DROP",
    "-P INPUT DROP",
    "-P FORWARD DROP",
  ]);
  // DNS to the configured resolver is permitted even though it is a LAN address.
  const dns = seq
    .filter((s) => s.name === "iptables" && s.argv.includes("--dport"))
    .map(
      (s) =>
        `${s.argv[s.argv.indexOf("-p") + 1]}:${s.argv[s.argv.indexOf("-d") + 1]}`,
    )
    .sort();
  expect(dns).toEqual(["tcp:192.168.65.7", "udp:192.168.65.7"]);
  expect(r.stdout).toBe("");
  expect(r.stderr).toContain("init-firewall: default-DROP active");
});

test("a reachable example.com after lockdown is fatal: the firewall failed open", async () => {
  const f = await fixture({ base: "github.com\n" });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, {
      FAKE_GETENT_MAP: "github.com=140.82.1.1",
      FAKE_CURL_OK: ".*",
    }),
  );
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "init-firewall: FATAL — example.com is reachable; default-DROP is NOT in effect",
  );
});

test("a v6 default route without usable ip6tables is fatal", async () => {
  const f = await fixture({ base: "github.com\n" });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, {
      FAKE_GETENT_MAP: "github.com=140.82.1.1",
      FAKE_IP6_ROUTE: "default via fe80::1 dev eth0",
      FAKE_IP6TABLES_FAIL: "1",
    }),
  );
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "init-firewall: FATAL — IPv6 default route present but ip6tables is unusable",
  );
});

test("usable ip6tables locks IPv6 down even without a v6 route, and the v6 canary runs only with one", async () => {
  const f = await fixture({ base: "github.com\n" });
  const expectedRules = [
    "-L -n",
    "-F",
    "-A OUTPUT -o lo -j ACCEPT",
    "-A INPUT -i lo -j ACCEPT",
    "-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
    "-P OUTPUT DROP",
    "-P INPUT DROP",
    "-P FORWARD DROP",
  ];
  const noRoute = await runScript(
    script,
    f.fake,
    baseEnv(f, { FAKE_GETENT_MAP: "github.com=140.82.1.1" }),
  );
  expect(noRoute.code).toBe(0);
  expect(
    (await calls(f.fake, "ip6tables")).map((c) => c.argv.join(" ")),
  ).toEqual(expectedRules);
  expect((await calls(f.fake, "curl")).some((c) => c.argv.includes("-6"))).toBe(
    false,
  );

  const g = await fixture({ base: "github.com\n" });
  const withRoute = await runScript(
    script,
    g.fake,
    baseEnv(g, {
      FAKE_GETENT_MAP: "github.com=140.82.1.1",
      FAKE_IP6_ROUTE: "default via fe80::1 dev eth0",
    }),
  );
  expect(withRoute.code).toBe(0);
  const seq = await sequence(g.fake);
  const lastDrop =
    seq
      .map((s, i) => (s.name === "ip6tables" && s.argv[0] === "-P" ? i : -1))
      .filter((i) => i >= 0)
      .at(-1) ?? -1;
  const canary = seq.findIndex(
    (s) =>
      s.name === "curl" &&
      s.argv.includes("-6") &&
      s.argv.some((a) => a.includes("example.com")),
  );
  expect(canary).toBeGreaterThan(lastDrop);
});

test("a reachable example.com over IPv6 after lockdown is fatal", async () => {
  const f = await fixture({ base: "github.com\n" });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, {
      FAKE_GETENT_MAP: "github.com=140.82.1.1",
      FAKE_IP6_ROUTE: "default via fe80::1 dev eth0",
      FAKE_CURL6_OK: ".*",
    }),
  );
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "init-firewall: FATAL — example.com is reachable over IPv6; default-DROP is NOT in effect",
  );
});

test("GitHub meta ranges pass through the same non-public filter", async () => {
  const f = await fixture({ base: "github.com\n" });
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, {
      FAKE_GETENT_MAP: "github.com=140.82.1.1",
      FAKE_CURL_META_JSON: JSON.stringify({
        web: ["10.0.0.0/8", "140.82.112.0/20"],
      }),
    }),
  );
  expect(r.code).toBe(0);
  const accepted = acceptRules(
    (await calls(f.fake, "iptables")).map((c) => c.argv),
  ).sort();
  expect(accepted).toEqual(["140.82.1.1", "140.82.112.0/20"].sort());
  expect(r.stderr).toContain(
    "dropping non-public range 10.0.0.0/8 from api.github.com/meta",
  );
});

test("shipped allow-ranges.d CIDRs are permitted, filtered, and survive a failed meta fetch", async () => {
  const f = await fixture({ base: "github.com\n" });
  await Bun.write(
    join(f.rangesDir, "github"),
    "# snapshot\n140.82.112.0/20\n\n10.0.0.0/8 # must be dropped\n185.199.108.0/22\n",
  );
  const r = await runScript(
    script,
    f.fake,
    baseEnv(f, { FAKE_GETENT_MAP: "github.com=140.82.1.1" }),
  );
  expect(r.code).toBe(0);
  const accepted = acceptRules(
    (await calls(f.fake, "iptables")).map((c) => c.argv),
  ).sort();
  expect(accepted).toEqual(
    ["140.82.1.1", "140.82.112.0/20", "185.199.108.0/22"].sort(),
  );
  expect(r.stderr).toContain(
    "init-firewall: WARNING — dropping non-public range 10.0.0.0/8 from github",
  );
  expect(r.stderr).toContain(
    "could not fetch api.github.com/meta; relying on the shipped range snapshot",
  );
});
