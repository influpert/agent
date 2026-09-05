#!/usr/bin/env bash
# Egress firewall for the agent sandbox: default-DROP plus a hostname allowlist.
#
# Runs as root from agent-entrypoint before any agent code executes. The
# allowlist is assembled from /etc/hatchward/allow-domains.d/* (one file per
# image layer) plus AGENT_ALLOW_DOMAINS at runtime.
#
# WHAT IT GUARANTEES: no path from the container to the host, the LAN, sibling
# containers, or the public internet except (a) port 53 to the configured
# resolver and (b) the allowlisted hosts. Resolved addresses inside private,
# loopback, link-local, CGNAT or multicast ranges are dropped whatever their
# source, so an allowlist entry cannot re-open the host path.
#
# WHAT IT DOES NOT GUARANTEE: exfiltration control. The agent holds whatever
# credentials it was given and can reach every allowlisted host; several of
# those sit on shared CDN addresses. The spec records this as a residual.
#
# FAIL-CLOSED: if there is an egress interface and the rules cannot be applied,
# or the negative canary shows egress is not restricted, exit 1 so the
# entrypoint refuses to run an unprotected agent. AGENT_FIREWALL=0 skips the
# firewall (debugging only) and leaves a marker the CLI-layer CMD checks.
#
# Runtime paths are overridable so the script can run under tests.
set -euo pipefail

AGENT_ALLOW_DIR="${AGENT_ALLOW_DIR:-/etc/hatchward/allow-domains.d}"
AGENT_RANGES_DIR="${AGENT_RANGES_DIR:-/etc/hatchward/allow-ranges.d}"
AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/hatchward}"
AGENT_RESOLV_CONF="${AGENT_RESOLV_CONF:-/etc/resolv.conf}"

log() { echo "init-firewall: $*" >&2; }
fatal() { log "FATAL — $*"; exit 1; }
verbose() { if [ "${AGENT_VERBOSE:-0}" = "1" ]; then log "$@"; fi; }

mkdir -p "$AGENT_RUN_DIR"

if [ "${AGENT_FIREWALL:-1}" = "0" ]; then
  log "DISABLED via AGENT_FIREWALL=0 — agent can reach host services"
  : > "$AGENT_RUN_DIR/firewall-disabled"
  exit 0
fi

# --- Is there anything to firewall? -----------------------------------------
# --network none leaves only loopback; that is stricter than these rules, so
# there is nothing to apply and nothing to refuse.
if ! ip -o link show | grep -v ': lo:' | grep -q .; then
  log "no egress interface; firewall not required"
  exit 0
fi

# --- iptables backend --------------------------------------------------------
# Pick the binary directly rather than rewriting /etc/alternatives at runtime.
IPT=""
for candidate in iptables-nft iptables-legacy iptables; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -L -n >/dev/null 2>&1; then
    IPT="$candidate"
    break
  fi
done
[ -n "$IPT" ] || fatal "cannot use iptables (needs --cap-add=NET_ADMIN and a netfilter-capable kernel)"

IP6T=""
for candidate in ip6tables-nft ip6tables-legacy ip6tables; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -L -n >/dev/null 2>&1; then
    IP6T="$candidate"
    break
  fi
done

# --- Allowlist ---------------------------------------------------------------
# One hostname per line in allow-domains.d files; '#' starts a comment.
# AGENT_ALLOW_DOMAINS adds more, separated by spaces or commas.
hostname_ok() {
  # A dotted name whose labels are not all numeric: an IP literal or a CIDR is
  # refused so the env cannot inject raw ranges.
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$' \
    && ! printf '%s' "$1" | grep -Eq '^[0-9.]+$'
}

domains_file="$(mktemp)"
addr_file="$(mktemp)"
trap 'rm -f "$domains_file" "$addr_file"' EXIT

if [ -d "$AGENT_ALLOW_DIR" ]; then
  for f in "$AGENT_ALLOW_DIR"/*; do
    [ -f "$f" ] || continue
    sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f" | grep -v '^$' >> "$domains_file" || true
  done
fi
for d in $(printf '%s' "${AGENT_ALLOW_DOMAINS:-}" | tr ',' ' '); do
  hostname_ok "$d" || fatal "AGENT_ALLOW_DOMAINS entry '$d' is not a hostname"
  echo "$d" >> "$domains_file"
done
sort -u -o "$domains_file" "$domains_file"

# --- Gather phase (egress still open): resolve to addresses -------------------
resolve_v4() {
  getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u || true
}

# Non-public IPv4 ranges: loopback, RFC1918, link-local, CGNAT, multicast,
# reserved (class E), benchmark, documentation, "this network", broadcast.
# Matches a bare address or a CIDR (the GitHub meta list is CIDRs).
non_public_v4() {
  case "$1" in
    0.*|10.*|127.*|169.254.*|192.168.*|255.255.255.255) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*) return 0 ;;
    198.1[89].*|192.0.0.*|192.0.2.*|198.51.100.*|203.0.113.*) return 0 ;;
  esac
  return 1
}

# Resolve every hostname several times: round-robin records (github.com hands
# out one of several addresses per query) would otherwise leave the address a
# later client gets outside the rule set.
resolve_v4_union() {
  { resolve_v4 "$1"; resolve_v4 "$1"; resolve_v4 "$1"; } | sort -u
}

while IFS= read -r d; do
  [ -n "$d" ] || continue
  found=0
  for ip in $(resolve_v4_union "$d"); do
    if non_public_v4 "$ip"; then
      log "WARNING — dropping non-public address $ip for $d"
      continue
    fi
    echo "$ip" >> "$addr_file"
    found=1
  done
  [ "$found" = 1 ] || log "WARNING — '$d' resolved to no public IPv4 address; it will be unreachable"
done < "$domains_file"

# Static ranges shipped in the image (allow-ranges.d/*: one CIDR per line, '#'
# comments). GitHub's published ranges live here as a snapshot, because the
# live api.github.com/meta fetch below is rate-limited for unauthenticated
# callers and CI runners hit that limit routinely. Filtered like everything
# else, so a file cannot smuggle in a private range.
if [ -d "$AGENT_RANGES_DIR" ]; then
  for f in "$AGENT_RANGES_DIR"/*; do
    [ -f "$f" ] || continue
    while IFS= read -r cidr; do
      [ -n "$cidr" ] || continue
      if non_public_v4 "$cidr"; then
        log "WARNING — dropping non-public range $cidr from $(basename "$f")"
        continue
      fi
      echo "$cidr" >> "$addr_file"
    done < <(sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f" | grep -v '^$' || true)
  done
fi

# GitHub's live published ranges, when reachable: its endpoints rotate across
# addresses a single boot-time resolution would miss. Best effort — a failure
# leaves the snapshot and the resolved addresses in place.
if meta="$(curl -fsS --connect-timeout 5 --max-time 10 https://api.github.com/meta 2>/dev/null)" && [ -n "$meta" ]; then
  while IFS= read -r cidr; do
    [ -n "$cidr" ] || continue
    if non_public_v4 "$cidr"; then
      log "WARNING — dropping non-public range $cidr from api.github.com/meta"
      continue
    fi
    echo "$cidr" >> "$addr_file"
  done < <(printf '%s' "$meta" | jq -r '(.web // []) + (.api // []) + (.git // []) | .[]' 2>/dev/null | grep -F '.' || true)
else
  log "WARNING — could not fetch api.github.com/meta; relying on the shipped range snapshot and resolved addresses"
fi
sort -u -o "$addr_file" "$addr_file"

# --- Apply phase: lock down, then permit the gathered set --------------------
for chain in INPUT OUTPUT FORWARD; do "$IPT" -P "$chain" ACCEPT; done
"$IPT" -F

"$IPT" -A OUTPUT -o lo -j ACCEPT
"$IPT" -A INPUT -i lo -j ACCEPT
"$IPT" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
"$IPT" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS to whatever resolver the runtime configured.
if [ -r "$AGENT_RESOLV_CONF" ]; then
  while read -r ns; do
    [ -n "$ns" ] || continue
    "$IPT" -A OUTPUT -p udp --dport 53 -d "$ns" -j ACCEPT
    "$IPT" -A OUTPUT -p tcp --dport 53 -d "$ns" -j ACCEPT
  done < <(awk '/^nameserver/ {print $2}' "$AGENT_RESOLV_CONF" | grep -F '.' || true)
fi

count=0
while IFS= read -r ip; do
  [ -n "$ip" ] || continue
  "$IPT" -A OUTPUT -d "$ip" -j ACCEPT
  count=$((count + 1))
done < "$addr_file"

"$IPT" -P OUTPUT DROP
"$IPT" -P INPUT DROP
"$IPT" -P FORWARD DROP

# IPv6: no allowlisted endpoint needs it and an open v6 path is a silent bypass
# (link-local reaches the host bridge even with no default route), so lock it
# down whenever ip6tables works. Missing ip6tables is fatal only when a v6
# default route makes the bypass real.
has_v6_route=0
if ip -6 route show default 2>/dev/null | grep -q .; then has_v6_route=1; fi
if [ -n "$IP6T" ]; then
  "$IP6T" -F
  "$IP6T" -A OUTPUT -o lo -j ACCEPT
  "$IP6T" -A INPUT -i lo -j ACCEPT
  "$IP6T" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  "$IP6T" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  "$IP6T" -P OUTPUT DROP
  "$IP6T" -P INPUT DROP
  "$IP6T" -P FORWARD DROP
  if [ "$has_v6_route" = 1 ] && curl -6 -fsS --connect-timeout 4 --max-time 5 -o /dev/null https://example.com 2>/dev/null; then
    fatal "example.com is reachable over IPv6; default-DROP is NOT in effect"
  fi
elif [ "$has_v6_route" = 1 ]; then
  fatal "IPv6 default route present but ip6tables is unusable"
else
  log "no IPv6 route; skipping ip6tables"
fi

# --- Canaries ----------------------------------------------------------------
# Negative: a non-allowlisted host must be unreachable, else refuse to run.
if curl -fsS --connect-timeout 4 --max-time 5 -o /dev/null https://example.com 2>/dev/null; then
  fatal "example.com is reachable; default-DROP is NOT in effect"
fi

# Positive: an allowlisted host should be reachable; warn rather than abort on
# a transient blip (a real failure surfaces in the agent's own run). No -f: an
# HTTP error such as a rate-limit 403 still proves the connection went through.
ok=0
for _ in 1 2 3; do
  if curl -sS --connect-timeout 4 --max-time 8 -o /dev/null https://api.github.com/ 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || log "WARNING — api.github.com unreachable after 3 tries; allowlist may be too tight or resolved addresses rotated"

verbose "allowlist: $(tr '\n' ' ' < "$domains_file")"
log "default-DROP active — $count v4 targets + loopback/DNS/established permitted; example.com blocked"
