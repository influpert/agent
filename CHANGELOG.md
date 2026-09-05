# Changelog

All notable changes to the agent images are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/). Each entry is condensed from that version's
`.github/releases/<tag>.md`, which the publish job turns into the GitHub release.

## [0.1.0] - unreleased

### Added
- `ghcr.io/influpert/agent:base`: Debian trixie (digest-pinned), git + git-lfs, gh, jq,
  tini, mise, a uid-1000 `agent` user, the default-DROP egress firewall with a composable
  hostname allowlist and shipped GitHub ranges, secret staging as agent-owned files, two
  workspace provisioning modes, and a `setpriv` privilege drop to an empty capability set.
- `ghcr.io/influpert/agent:claude`: Claude Code 2.1.236 and the `agent-claude` CMD that runs
  one headless session with the prompt on stdin and the credential only in its process.
- `smoke.sh`, the fake-driven test suite, `ci.yml` (check, build + smoke, publish on `v*`
  tags) and `bin/release`.
