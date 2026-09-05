#!/usr/bin/env bash
# Shared helpers for the CLI-layer CMD scripts (agent-claude, later agent-codex).
# Sourced, not executed. Every function prints its answer on stdout and reports
# on stderr; secrets are printed only by agent_resolve_secret, to stdout, for a
# caller that captures them into the exec'd process's environment.
#
# Sources, in order of precedence:
#   prompt  AGENT_PROMPT → AGENT_PROMPT_FILE → manifest .agent.prompt (+ task)
#   model   AGENT_MODEL  → manifest .agent.model → none
#   secret  $NAME        → $NAME_FILE → none
# The manifest is what agent-entrypoint saved from a non-TTY stdin — the
# hatchward runner's execution manifest — at $AGENT_RUN_DIR/manifest.json.

AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/hatchward}"

agent_manifest_file() {
  printf '%s/manifest.json' "$AGENT_RUN_DIR"
}

agent_resolve_prompt() {
  if [ -n "${AGENT_PROMPT:-}" ]; then
    printf '%s\n' "$AGENT_PROMPT"
    return 0
  fi
  if [ -n "${AGENT_PROMPT_FILE:-}" ] && [ -r "$AGENT_PROMPT_FILE" ]; then
    cat "$AGENT_PROMPT_FILE"
    return 0
  fi
  local manifest
  manifest="$(agent_manifest_file)"
  if [ -s "$manifest" ] && jq -e '.agent.prompt | strings | length > 0' "$manifest" >/dev/null 2>&1; then
    jq -r '.agent.prompt' "$manifest"
    # The control plane does not render task fields into the prompt template,
    # so the agent would otherwise never see the task it was assigned.
    if jq -e '(.task.fields // []) | length > 0' "$manifest" >/dev/null 2>&1; then
      printf '\n## Task\n\n'
      jq -r '.task.fields[] | "- \(.field): \(if (.value | type) == "string" then .value else (.value | tojson) end)"' "$manifest"
    fi
    return 0
  fi
  echo "agent: no prompt — set AGENT_PROMPT, AGENT_PROMPT_FILE, or pass a manifest on stdin" >&2
  return 2
}

agent_resolve_model() {
  if [ -n "${AGENT_MODEL:-}" ]; then
    printf '%s\n' "$AGENT_MODEL"
    return 0
  fi
  local manifest
  manifest="$(agent_manifest_file)"
  if [ -s "$manifest" ]; then
    jq -r '.agent.model // empty' "$manifest" 2>/dev/null || true
  fi
  return 0
}

# agent_resolve_secret NAME — the value of $NAME, else the contents of the file
# named by $NAME_FILE (trailing newlines stripped). Silent on stderr so a
# caller's `2>&1` capture can never include a value by accident.
agent_resolve_secret() {
  local name="$1" file_var value file
  value="${!name:-}"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
    return 0
  fi
  file_var="${name}_FILE"
  file="${!file_var:-}"
  if [ -n "$file" ] && [ -r "$file" ]; then
    value="$(cat "$file")"
    if [ -n "$value" ]; then
      printf '%s\n' "$value"
      return 0
    fi
  fi
  return 1
}

# The firewall left a marker when it was disabled; a CMD that runs the agent
# with --dangerously-skip-permissions must not proceed on that alone.
agent_require_firewall() {
  local marker="$AGENT_RUN_DIR/firewall-disabled"
  [ -e "$marker" ] || return 0
  if [ "${AGENT_UNSAFE_NO_FIREWALL:-0}" = "1" ]; then
    echo "agent: WARNING — firewall disabled and AGENT_UNSAFE_NO_FIREWALL=1; the agent can reach host services" >&2
    return 0
  fi
  echo "agent: refusing to run with --dangerously-skip-permissions while the firewall is disabled (set AGENT_UNSAFE_NO_FIREWALL=1 to override)" >&2
  return 2
}
