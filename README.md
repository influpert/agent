# influpert/agent

The sandbox a coding agent runs in: one container per run, for any code base. Built for
the [hatchward](https://github.com/influpert/hatchward) runner and usable by hand.

What the sandbox guarantees: the agent runs as an unprivileged user with an empty
capability set and no way back to root; egress is default-DROP with a hostname
allowlist and no path to the host or LAN; credentials arrive as files staged for the
agent and never appear in argv or the environment; the prompt travels on stdin; the
workspace is either cloned fresh or used exactly as provided.

| Image | Source | Adds |
|---|---|---|
| `ghcr.io/influpert/agent:base` | `Dockerfile` | Debian trixie, git + git-lfs, gh, jq, tini, the egress firewall, a uid-1000 `agent` user, mise |
| `ghcr.io/influpert/agent:claude` | `claude/Dockerfile` | Claude Code CLI (pinned) and the `agent-claude` CMD |

Versions will be release tags: `:base-vX.Y.Z` and `:claude-vX.Y.Z` immutable, `:base`
and `:claude` moving; project configuration must pin a versioned tag. **Nothing publishes
these images until the first release tag.** `ci.yml` builds and smoke-tests every push; a
`v*` tag publishes both images with the workflow's own `GITHUB_TOKEN`. To build locally
(the Claude layer's `BASE_IMAGE` defaults to the tag this recipe produces):

```bash
docker build -t agent:base .
docker build -f claude/Dockerfile -t agent:claude .
./smoke.sh agent:base agent:claude
```

`smoke.sh` needs a Docker daemon and `python3` on the host (for a throwaway listener).

## What a run looks like

`tini` → `agent-entrypoint` (root) → `setpriv` drops to `agent` with an empty capability
bounding set → the command (`agent-claude` by default, or whatever you pass).

The root phase, in order: apply the firewall; re-own `/workspace` if a `docker cp` or a
foreign volume left it root-owned; save a non-TTY stdin as
`/run/hatchward/manifest.json` and detach stdin; stage secrets as agent-owned `0400`
files; authenticate `gh` over stdin; provision the repository; drop privileges.
Everything the entrypoint prints goes to stderr. fd 1 belongs to the command.

## Launching it by hand

Secrets and the prompt travel in an env file, never on the command line. `/run/secrets/`
below is only where this example mounts the host file; the image copies whatever the
`_FILE` variable points at to `/run/hatchward/secrets/` regardless.

```bash
envf="$(mktemp)"; chmod 600 "$envf"
cat > "$envf" <<EOF
ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_api_key
AGENT_PROMPT=Fix the failing test in apps/api and open a PR.
EOF
docker run --rm \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add CHOWN \
  --cap-add DAC_READ_SEARCH --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges --pids-limit 512 --cpus 2 --memory 3g \
  --mount type=bind,src="$HOME/.hatchward/secrets/_default/anthropic_api_key",dst=/run/secrets/anthropic_api_key,readonly \
  -v agent-ws-01:/workspace --env-file "$envf" -e AGENT_REPO=owner/repo \
  agent:claude
rm -f "$envf"
```

`NET_ADMIN` and `NET_RAW` are for the firewall, `CHOWN` for the workspace and secret
copies, `DAC_READ_SEARCH` so root can read a secret file owned by another uid, and
`SETUID`/`SETGID`/`SETPCAP` for the privilege drop. Nothing is granted to the agent
process itself. `--init` is unnecessary; `tini` is the image's entrypoint.

## Contract

| Variable | Layer | Meaning |
|---|---|---|
| `AGENT_REPO` | base | `owner/name` (GitHub) or an `https://` URL. Set: **self-clone mode** — an empty `/workspace` is cloned, then force-synced to the branch tip on every boot. Unset: **provided-workspace mode** — `/workspace` is used as found and never touched. |
| `AGENT_BASE_BRANCH` | base | Branch to sync in self-clone mode; default is the remote's default branch. |
| `AGENT_CLONE_ARGS` | base | Extra `git clone` arguments, e.g. `--filter=blob:none`. |
| `AGENT_WORKDIR` | base | Relative path under `/workspace` to start in; also becomes `CLAUDE_PROJECT_DIR`. |
| `GH_TOKEN` / `GH_TOKEN_FILE` | base | GitHub token for private clones and pushes. Use a fine-grained token scoped to one repository, per project (a classic PAT needs `repo` and `read:org`; a GitHub App installation token is not accepted by `gh auth login` yet). It is staged to a file and given to `gh auth login` on stdin; the raw value is removed from the environment. |
| `AGENT_STAGE_VARS` | base (set by each CLI layer's Dockerfile) | Space-separated variable names the entrypoint stages as secrets. Base: `GH_TOKEN`; Claude adds `ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN`. |
| `AGENT_SANDBOXED` | base | Always `1`. A repository's hooks can key on it to know they run inside this sandbox. |
| `AGENT_GIT_NAME`, `AGENT_GIT_EMAIL` | base | Commit identity. Defaults `hatchward-agent` / `agent@hatchward.invalid`. |
| `AGENT_ALLOW_DOMAINS` | base | Extra egress hostnames, space or comma separated. Hostnames only; anything resolving to a private address is dropped anyway. |
| `AGENT_FIREWALL` | base | `0` disables the firewall (debugging only). The CLI-layer CMD then refuses to run unless `AGENT_UNSAFE_NO_FIREWALL=1`. |
| `AGENT_VERBOSE` | base | `1` logs the effective egress allowlist on stderr. |
| `HATCHWARD_ASSIGNMENT_ACTION_SOCKET` | base | Set by the runner; passed through untouched. Unix-socket bind mounts work on Linux hosts only. |
| stdin | base | A non-TTY stdin is saved as `/run/hatchward/manifest.json` (the runner's execution manifest) and detached. The caller must close stdin; a pipe held open blocks the boot. |
| `AGENT_PROMPT` / `AGENT_PROMPT_FILE` | CLI layer | The prompt, in that order of precedence; else the manifest's `agent.prompt` with its `task.fields` rendered as a `## Task` section. |
| `AGENT_MODEL` | CLI layer | The model; else the manifest's `agent.model`; else the CLI default. Claude passes it as `--model`. |
| `AGENT_MAX_TURNS` | claude | `--max-turns`, default 200. |
| `AGENT_OUTPUT_FORMAT` | claude | `json` (default, final result only), `stream-json` (adds `--verbose`), or `text`. The runner caps combined output at 1 MiB. |
| `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` (+ `_FILE`) | claude | Model credential; the file form is preferred. Exported only into the exec'd `claude` process. |

Exit codes: `2` is a contract error — no prompt, no credential, an empty workspace, or the
firewall disabled without the override — always with a named line on stderr. `1` with a
`FATAL —` line is the firewall or a validation failure in the entrypoint. Any other
non-zero status is the failing tool's own: `git` or `gh` during provisioning (their
message, no `FATAL` line), or, once the CMD has started, the agent CLI's.

Secrets in the container: `/run/hatchward/secrets/<name>` (`0400`, agent-owned) — copies
made in the root phase from `$NAME` or `$NAME_FILE`. The `_FILE` variables are re-pointed
at the copies; the raw variables are unset before the drop.

## Firewall

Default-DROP on input, output and forward, then: loopback, established traffic, port 53
to the configured resolver, and the allowlist. The allowlist is the union of every file
in `/etc/hatchward/allow-domains.d/` (the base list plus one file per CLI layer) and
`AGENT_ALLOW_DOMAINS`. Hostnames are resolved once at boot; addresses in loopback, RFC
1918, link-local, CGNAT or multicast ranges are dropped with a warning whatever their
source. GitHub's published ranges are added so its CDN endpoints resolve. A container
with no non-loopback interface (`--network none`) skips the firewall; one with an
interface but no `NET_ADMIN` refuses to start.

**What this is and is not.** It blocks the host, the LAN, sibling containers and casual
egress. It is not exfiltration control: the agent holds the credentials it was given and
can reach every allowlisted host, several of which share CDN addresses with the rest of
the internet, and DNS is an open channel. A hostname-aware egress proxy is the follow-up
that would close that.

## Extending: what a CLI layer supplies

A layer image (`<cli>/`) builds `FROM` the base and adds exactly four
things: `allow-domains.d/<cli>` with the hosts its CLI needs, an `ENV AGENT_STAGE_VARS`
line naming its credential variables (keep `GH_TOKEN`), `agent-<cli>.sh` as the CMD, built
on `/usr/local/lib/hatchward/prompt.sh` (`agent_require_firewall`, `agent_resolve_prompt`,
`agent_resolve_model`, `agent_resolve_secret`), and whatever trust or config file its CLI
needs to run headless. The prompt goes to the CLI on stdin,
the credential is exported only into the exec'd process, and the CLI is `exec`'d so
`docker stop` reaches it.

## Running under the hatchward runner

**Today's hatchward runner does not launch this image usefully.** Its `worker.go`
(`src/cli/internal/hostedrunner/` in influpert/hatchward) creates
the container with `--network none`, no capabilities, no `-i` and no secret mounts, so
the firewall is skipped, no credential arrives and the manifest never reaches the
container. The runner change is a separate hatchward pull request written against this
contract:
provided-workspace mode, `docker create -i` with the flags above (`-i` is what lets
`start -a -i` attach stdin at all), `docker cp` of the operator's checkout into
`/workspace`, `docker start -a -i` with the execution manifest on stdin, secret files
staged from `~/.hatchward/secrets/`. The image then reads the prompt and model from the
manifest. An empty operator directory is a contract error: pre-clone the repository into
the workspace root. Combined stdout and stderr are capped at 1 MiB by the runner, which
is why the image is quiet by default and `json` is the default output format.
