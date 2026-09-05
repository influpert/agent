#!/usr/bin/env bash
# Entrypoint for the hatchward agent image.
#
# Runs as root only long enough to apply the egress firewall, fix workspace
# ownership, capture stdin, stage secrets and provision the repository; then it
# drops to the unprivileged "agent" user with an empty capability bounding set
# and execs the command (the CLI layer's CMD, or whatever the caller passed).
#
# Two provisioning modes:
#   self-clone          AGENT_REPO is set: clone an empty /workspace over HTTPS,
#                       then force-sync to the tip of AGENT_BASE_BRANCH (or the
#                       remote's default branch) on every boot.
#   provided workspace  AGENT_REPO is unset: /workspace is whatever the caller
#                       mounted or copied in (the hatchward runner does
#                       `docker cp`); it is not touched.
#
# Everything this script prints goes to stderr. fd 1 belongs to the command,
# whose stdout the runner captures. Runtime paths are overridable so the script
# runs under tests outside the image.
set -euo pipefail
# Never trace (a SHELLOPTS=xtrace in the environment would print secret values)
# and create every file closed until its mode is set explicitly.
set +x
umask 077

AGENT_WORKSPACE="${AGENT_WORKSPACE:-/workspace}"
AGENT_HOME="${AGENT_HOME:-/home/agent}"
AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/hatchward}"
AGENT_USER="${AGENT_USER:-agent}"
AGENT_PATH="$AGENT_HOME/.local/share/mise/shims:$AGENT_HOME/.local/bin:$PATH"
# Secret variables staged for the agent: a value in $NAME or a path in
# $NAME_FILE. CLI layers extend the list with their own credential names.
AGENT_STAGE_VARS="${AGENT_STAGE_VARS:-GH_TOKEN}"

log() { echo "agent-entrypoint: $*" >&2; }
fatal() { log "FATAL — $*"; exit 1; }

# The privilege drop: the agent user with every capability removed from the
# bounding and inheritable sets and no way to regain one. One definition, used
# by as_agent for the provisioning steps and by the final exec.
DROP=(setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --init-groups
  --inh-caps=-all --bounding-set=-all --no-new-privs
  env HOME="$AGENT_HOME" PATH="$AGENT_PATH")
as_agent() { "${DROP[@]}" "$@"; }

# 1. Firewall first: nothing below may run with unrestricted egress.
init-firewall

# The run dir must stay traversable by the agent (umask 077 above would make a
# fresh one root-only): its files are agent-owned, the directory is root's.
mkdir -p "$AGENT_RUN_DIR" "$AGENT_WORKSPACE"
chmod 755 "$AGENT_RUN_DIR"
agent_uid="$(id -u "$AGENT_USER")"

# 2. Ownership. A named volume or a `docker cp`'d tree arrives root-owned; the
# recursive chown is paid only when something is actually foreign.
owner_of() { stat -c %u "$1"; }
needs_chown=0
[ "$(owner_of "$AGENT_WORKSPACE")" = "$agent_uid" ] || needs_chown=1
if [ "$needs_chown" = 0 ]; then
  first_entry="$(find "$AGENT_WORKSPACE" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"
  if [ -n "$first_entry" ] && [ "$(owner_of "$first_entry")" != "$agent_uid" ]; then
    needs_chown=1
  fi
fi
[ "$needs_chown" = 0 ] || chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_WORKSPACE"

# 3. Stdin. The hatchward runner writes the execution manifest to stdin. Save
# it for the CLI layer and make sure no later process can read stdin as input.
manifest="$AGENT_RUN_DIR/manifest.json"
if [ ! -t 0 ]; then
  log "reading the manifest from stdin (the caller must close it)"
  cat > "$manifest"
  if [ -s "$manifest" ]; then
    chmod 600 "$manifest"
    chown "$AGENT_USER:$AGENT_USER" "$manifest"
  else
    rm -f "$manifest"
  fi
  exec </dev/null
fi

# 4. Secrets. A value may arrive as $NAME or as a file named by $NAME_FILE.
# Either way it ends up as an agent-owned 0400 copy under the run dir, the
# $NAME_FILE variable points at the copy, and the raw $NAME is removed from
# the environment so no descendant of the agent inherits a value.
secrets_dir="$AGENT_RUN_DIR/secrets"
# Agent-owned 0700: root writes the copies, only the agent can read them.
ensure_secrets_dir() {
  [ -d "$secrets_dir" ] && return 0
  mkdir -p "$secrets_dir"
  chmod 700 "$secrets_dir"
  chown "$AGENT_USER:$AGENT_USER" "$secrets_dir"
}
stage_secret() {
  local name="$1" file_var="${1}_FILE" value src dest
  dest="$secrets_dir/$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  value="${!name:-}"
  src="${!file_var:-}"
  if [ -n "$value" ]; then
    ensure_secrets_dir
    printf '%s\n' "$value" > "$dest"
  elif [ -n "$src" ]; then
    [ -r "$src" ] || fatal "$file_var='$src' is not readable"
    ensure_secrets_dir
    cp "$src" "$dest"
  else
    return 0
  fi
  chmod 400 "$dest"
  chown "$AGENT_USER:$AGENT_USER" "$dest"
  unset "$name"
  export "$file_var=$dest"
}
[ ! -d "$secrets_dir" ] || rm -rf "$secrets_dir"
for name in $AGENT_STAGE_VARS; do
  stage_secret "$name"
done

# GitHub auth: the token goes to gh on stdin and is stored in the agent's own
# gh hosts file, so git's credential helper works without a token in env.
if [ -n "${GH_TOKEN_FILE:-}" ]; then
  as_agent gh auth login --with-token < "$GH_TOKEN_FILE"
  as_agent gh auth setup-git
fi

# 5. Provision.
repo_url=""
if [ -n "${AGENT_REPO:-}" ]; then
  case "$AGENT_REPO" in
    https://*@*) fatal "AGENT_REPO must not carry credentials; use GH_TOKEN_FILE" ;;
    https://*) repo_url="$AGENT_REPO" ;;
    *)
      if printf '%s' "$AGENT_REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
        repo_url="https://github.com/$AGENT_REPO.git"
      else
        fatal "AGENT_REPO '$AGENT_REPO' must be owner/name or an https:// URL"
      fi
      ;;
  esac
fi

branch="${AGENT_BASE_BRANCH:-}"
if [ -n "$repo_url" ]; then
  clone_args=""
  if [ -n "$branch" ]; then
    as_agent git -C "$AGENT_WORKSPACE" check-ref-format --branch "$branch" >/dev/null 2>&1 \
      || fatal "AGENT_BASE_BRANCH '$branch' is not a valid branch name"
    clone_args="--branch $branch"
  fi
  if [ ! -d "$AGENT_WORKSPACE/.git" ]; then
    # shellcheck disable=SC2086 # AGENT_CLONE_ARGS and clone_args are word lists by contract
    as_agent git clone -q ${AGENT_CLONE_ARGS:-} $clone_args "$repo_url" "$AGENT_WORKSPACE"
  fi
  as_agent git -C "$AGENT_WORKSPACE" remote set-head origin --auto >/dev/null
  if [ -z "$branch" ]; then
    branch="$(as_agent git -C "$AGENT_WORKSPACE" symbolic-ref --short refs/remotes/origin/HEAD | sed 's|^origin/||')"
    [ -n "$branch" ] || fatal "could not determine the default branch of $repo_url; set AGENT_BASE_BRANCH"
  fi
  # A dirty or stale tree is impossible after this: the branch is exactly the
  # remote tip. clean -fd keeps ignored paths (a warm volume's dependency caches).
  as_agent git -C "$AGENT_WORKSPACE" fetch -q origin "+refs/heads/$branch:refs/remotes/origin/$branch"
  as_agent git -C "$AGENT_WORKSPACE" checkout -q -B "$branch" "origin/$branch"
  as_agent git -C "$AGENT_WORKSPACE" reset -q --hard "origin/$branch"
  as_agent git -C "$AGENT_WORKSPACE" clean -q -fd
  as_agent git -C "$AGENT_WORKSPACE" worktree prune
  as_agent git -C "$AGENT_WORKSPACE" submodule -q update --init --recursive
elif [ -z "$(find "$AGENT_WORKSPACE" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  log "WARNING — /workspace is empty and AGENT_REPO is unset; nothing to provision"
fi

# The agent, not root, gets the safe.directory entry: root never runs git here.
as_agent git config --global --add safe.directory "$AGENT_WORKSPACE"
as_agent git config --global user.name "${AGENT_GIT_NAME:-hatchward-agent}"
as_agent git config --global user.email "${AGENT_GIT_EMAIL:-agent@hatchward.invalid}"

# 6. Drop privileges and hand over.
project_dir="$AGENT_WORKSPACE"
if [ -n "${AGENT_WORKDIR:-}" ]; then
  case "/$AGENT_WORKDIR/" in
    //*|*/../*) fatal "AGENT_WORKDIR '$AGENT_WORKDIR' must be a relative path inside /workspace" ;;
  esac
  project_dir="$AGENT_WORKSPACE/$AGENT_WORKDIR"
  [ -d "$project_dir" ] || fatal "AGENT_WORKDIR '$AGENT_WORKDIR' does not exist under /workspace"
fi
cd "$project_dir"
export CLAUDE_PROJECT_DIR="$project_dir"
exec "${DROP[@]}" "$@"
