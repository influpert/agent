#!/usr/bin/env bash
# Smoke test for the agent images: runs the built containers the way the docs
# and the runner launch them and checks the contract from the outside.
#
#   ./smoke.sh <base image> <claude image>
#
# Needs a Docker daemon with bridge networking and NET_ADMIN available (any
# Linux host, GitHub's ubuntu runners, Docker Desktop), and python3 on the host
# for the throwaway HTTP listener in check 3. The fake-driven bun tests
# under tests/ cover the scripts' logic; this covers what fakes
# cannot: the real privilege drop, real iptables, a real clone through the
# firewall, and the runner's create/cp/start launch shape.
set -euo pipefail

base="${1:?base image}"
claude="${2:?claude image}"

# The launch flags the docs publish and the runner will pass (PR 3).
CAPS=(--cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add CHOWN
  --cap-add DAC_READ_SEARCH --cap-add SETUID --cap-add SETGID --cap-add SETPCAP
  --security-opt no-new-privileges --pids-limit 512)

pass() { echo "smoke: ok — $*"; }
fail() { echo "smoke: FAIL — $*" >&2; exit 1; }
contains() {
  # A newline inside a fixed-string pattern is a pattern *list* to grep, and the
  # empty member matches everything — refuse it rather than pass vacuously.
  case "$2" in *$'\n'*) fail "$3: pattern must be a single line";; esac
  printf '%s' "$1" | grep -qF -- "$2" || fail "$3: expected to find '$2'"
}

tmp="$(mktemp -d)"
listener_pid=""
cleanup() {
  if [ -n "$listener_pid" ]; then
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
  docker rm -f smoke-runner-shape >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Identity and privileges of the exec'd command.
out="$(docker run --rm "${CAPS[@]}" "$base" sh -c '
  printf "uid=%s user=%s\n" "$(id -u)" "$(id -un)"
  command -v sudo >/dev/null && echo HAS_SUDO || echo no-sudo
  grep -E "^(CapBnd|CapPrm|CapEff|CapAmb|NoNewPrivs):" /proc/self/status' 2>"$tmp/stderr1")"
contains "$out" "uid=1000 user=agent" "uid/user"
contains "$out" "no-sudo" "sudo absent"
for cap in CapBnd CapPrm CapEff CapAmb; do
  printf '%s' "$out" | grep -Eq "^$cap:\s+0+$" || fail "$cap is not empty: $(printf '%s' "$out" | grep "^$cap")"
done
contains "$out" "NoNewPrivs:	1" "no_new_privs"
contains "$(cat "$tmp/stderr1")" "init-firewall: default-DROP active" "firewall summary on stderr"
pass "runs as agent with no capabilities, no sudo, no_new_privs"

# 2. Self-clone of a public repository through the firewall.
out="$(docker run --rm "${CAPS[@]}" -e AGENT_REPO=octocat/Hello-World "$base" \
  sh -c 'printf "head=%s\n" "$(git -C /workspace rev-parse HEAD)"; printf "git_owner=%s\n" "$(stat -c %U /workspace/.git)"' 2>/dev/null)"
printf '%s' "$out" | grep -Eq '^head=[0-9a-f]{40}$' || fail "clone: no commit hash in: $out"
contains "$out" "git_owner=agent" "workspace owned by agent"
pass "self-clone works through the firewall"

# 3. Egress: host and public internet blocked, allowlisted host reachable.
python3 -m http.server 18080 --bind 0.0.0.0 >/dev/null 2>&1 &
listener_pid=$!
sleep 1
probe='
  curl -fsS --max-time 4 -o /dev/null http://host.docker.internal:18080/ && echo HOST_OPEN || echo host-blocked
  curl -fsS --max-time 4 -o /dev/null https://example.com && echo EXAMPLE_OPEN || echo example-blocked
  curl -fsS --max-time 8 -o /dev/null https://api.github.com/zen && echo github-ok || echo GITHUB_BLOCKED'
out="$(docker run --rm "${CAPS[@]}" --add-host host.docker.internal:host-gateway \
  -e AGENT_ALLOW_DOMAINS=host.docker.internal "$base" sh -c "$probe" 2>"$tmp/stderr3")"
contains "$out" "host-blocked" "host unreachable even when allowlisted by name"
contains "$out" "example-blocked" "example.com blocked"
contains "$out" "github-ok" "api.github.com reachable"
contains "$(cat "$tmp/stderr3")" "dropping non-public address" "private address warning"
out="$(docker run --rm "${CAPS[@]}" --add-host host.docker.internal:host-gateway \
  -e AGENT_FIREWALL=0 -e AGENT_UNSAFE_NO_FIREWALL=1 "$base" sh -c "$probe" 2>/dev/null)"
contains "$out" "HOST_OPEN" "host reachable with the firewall disabled (proves the listener works)"
pass "egress policy: host and internet blocked, allowlist reachable"

# 4. Without NET_ADMIN the container refuses to start.
code=0
docker run --rm "$base" true >"$tmp/out4" 2>"$tmp/err4" || code=$?
[ "$code" -ne 0 ] || fail "container started without NET_ADMIN"
contains "$(cat "$tmp/err4")" "init-firewall: FATAL — cannot use iptables" "fail-closed without caps"
pass "fails closed without NET_ADMIN"

# 5. Default Claude CMD with no credential: contract error, nothing on stdout.
code=0
docker run --rm "${CAPS[@]}" -e AGENT_REPO=octocat/Hello-World -e AGENT_PROMPT=hello "$claude" \
  >"$tmp/out5" 2>"$tmp/err5" || code=$?
[ "$code" -eq 2 ] || fail "expected exit 2 without a credential, got $code: $(cat "$tmp/err5")"
[ ! -s "$tmp/out5" ] || fail "stdout was not empty: $(cat "$tmp/out5")"
contains "$(cat "$tmp/err5")" "agent-claude: no model credential" "credential guard"
out="$(docker run --rm "${CAPS[@]}" "$claude" claude --version 2>/dev/null)"
[ -n "$out" ] || fail "claude --version printed nothing"
pass "claude layer: credential guard and CLI present ($out)"

# 6. A toolchain install through the firewall (what "agent installs what it needs" relies on).
out="$(docker run --rm "${CAPS[@]}" "$base" sh -c 'mise use -g node@lts >/dev/null && node --version' 2>/dev/null)"
printf '%s' "$out" | grep -Eq '^v[0-9]+' || fail "mise node install: $out"
pass "mise installs node through the firewall ($out)"

# 7. The runner's launch shape: create, cp a root-owned tree, start with the
# manifest on stdin, and a command that never sees that stdin. `create -i` is
# load-bearing: without OpenStdin at create time, `start -a -i` attaches no
# stdin at all and the manifest silently never arrives.
mkdir -p "$tmp/ws/.git"
echo "x" > "$tmp/ws/file"
printf '{"agent":{"prompt":"From manifest","model":"m"},"task":{"fields":[{"field":"title","value":"T"}]}}' > "$tmp/manifest.json"
docker create -i --name smoke-runner-shape "${CAPS[@]}" --workdir /workspace "$base" \
  sh -c 'printf "manifest=%s\n" "$(stat -c "%a %U" /run/hatchward/manifest.json)"; printf "prompt=%s\n" "$(jq -r .agent.prompt /run/hatchward/manifest.json)"; printf "file_owner=%s\n" "$(stat -c %U /workspace/file)"; printf "stdin_bytes=%s\n" "$(cat | wc -c | tr -d " ")"' >/dev/null
docker cp "$tmp/ws/." smoke-runner-shape:/workspace
out="$(docker start -a -i smoke-runner-shape < "$tmp/manifest.json" 2>/dev/null)"
docker rm -f smoke-runner-shape >/dev/null
contains "$out" "manifest=600 agent" "manifest mode/owner"
contains "$out" "prompt=From manifest" "manifest prompt readable"
contains "$out" "file_owner=agent" "docker cp'd tree re-owned by agent"
contains "$out" "stdin_bytes=0" "command stdin detached"
pass "runner launch shape: manifest captured, tree re-owned, stdin detached"

# 8. A secret file owned by a foreign uid, mounted read-only, is readable by the agent.
echo "sk-smoke-sentinel" > "$tmp/secret"
chmod 600 "$tmp/secret"
if chown 4242 "$tmp/secret" 2>/dev/null || sudo -n chown 4242 "$tmp/secret" 2>/dev/null; then
  out="$(docker run --rm "${CAPS[@]}" --mount "type=bind,src=$tmp/secret,dst=/run/secrets/anthropic_api_key,readonly" \
    -e ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_api_key \
    -e AGENT_STAGE_VARS=ANTHROPIC_API_KEY "$base" \
    sh -c 'printf "staged=%s\n" "$(cat "$ANTHROPIC_API_KEY_FILE")"; printf "raw_in_env=%s\n" "$(env | grep -c "^ANTHROPIC_API_KEY=" || true)"' 2>/dev/null)"
  contains "$out" "staged=sk-smoke-sentinel" "foreign-uid secret readable via the staged copy"
  contains "$out" "raw_in_env=0" "raw value absent from the environment"
  pass "secret staging works for a foreign-uid host file"
else
  echo "smoke: skipped — cannot chown to a foreign uid on this host (needs root)"
fi

echo "smoke: all checks passed"
