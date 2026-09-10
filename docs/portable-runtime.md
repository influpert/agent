# Portable runtime (contract 3)

Contract-3 images expose an explicit `/usr/local/bin/hatchward-bootstrap`
entrypoint for the hosted runner. The standard image entrypoint still supports
its existing Linux firewall/provisioning mode. The portable mode requires a
Linux Docker engine (including the Linux VM provided by Docker Desktop on macOS)
with `/dev/fuse` and the default Docker security profile permitting FUSE mounts.
The native macOS runner talks to that engine through Docker exec streams.

The runner launches a read-only root, no network, no IPC shared-memory filesystem,
and a private Docker volume at `/hatchward-backing`. Startup requires only
SYS_ADMIN, CHOWN, SETUID, SETGID and SETPCAP. No host directory, Docker socket,
privileged mode, or unconfined profile is part of this contract.

`HATCHWARD_DISK_MIB` is the total size of an ext4 filesystem image, including
filesystem metadata. Workspace, home (including copied CLI installations), `/tmp`
and `/run` share this fixed capacity. Available payload space is smaller. The real Claude installation alone exceeds
256 MiB; provision at least 1 GiB for runtime validation and budget additional
space for the repository and toolchains. A full
filesystem fails writes; there is no unbounded or RAM-backed fallback. The
immutable root remains read-only and the backing image is root-only. FUSE mounts
use default_permissions,nosuid,nodev so kernel permission checks also protect
Unix socket path traversal. FUSE daemon, gateway, workload and final supervisor have empty
capability sets and no-new-privileges. The trusted bootstrap executes the dropped
supervisor before publishing readiness; neither image CMD nor imported code runs
during privileged setup. Every privileged helper pins a read-only system PATH,
uses absolute privilege-drop/interpreter paths, and ignores Python environment
configuration; agent-installed executables cannot shadow bootstrap tools during
channel replenishment.

The gateway runs as uid 10002, separately from workload uid 1000. It accepts only
loopback proxy and assignment action traffic. Host channel attachment requires
access to `/run/hatchward/bridge/control.sock` inside a private 0700 directory;
the workload cannot attach to it. Sixteen single-use Docker exec channels carry
bytes to fixed host endpoints. The channel starts with a P/A dispatch byte, then
uses bounded D data frames and F half-close frames (one-byte kind, four-byte
big-endian length). Explicit half-close avoids Docker exec stdout waiting for
process exit before the peer can send its response. `/run/hatchward/actions.sock` points at the
public gateway socket; neither that socket nor the proxy supplies unrestricted
host networking.

After `/run/hatchward/ready` appears, `hatchward-configure` accepts stdin JSON
`{"ca":"public PEM CA","proxyUrl":"http://hatchward:token@127.0.0.1:3128","env":{}}`.
Empty CA and proxy enable networkless execution. Environment keys are restricted
to GitHub/Anthropic credential names and values must be the literal
`hatchward-proxy-managed`; real provider credentials remain on the host. It
creates a bounded CA bundle and protected runtime configuration. `hatchward-import`
extracts a stdin tar as the agent, without adopting archive owners or privileged
modes. `hatchward-run COMMAND...` accepts a JSON execution manifest on stdin,
prepares agent-owned Git configuration, and executes the inspected image CMD as
uid 1000 with empty capabilities. The runner removes the assignment container and
private volume on completion or cancellation. A gateway or FUSE child exit terminates
the supervisor so daemon failure cannot silently leave a usable sandbox; ordinary
adopted workload children are reaped without terminating the assignment.

Validation commands (local, no publishing):

```sh
docker build -t agent:macos-base .
docker build -f claude/Dockerfile --build-arg BASE_IMAGE=agent:macos-base -t agent:macos-claude .
python3 -m unittest discover -s runtime/tests -p 'test_*.py'
python3 runtime/tests/docker_runtime.py agent:macos-base
```

`docker_runtime.py` checks actual import/run behavior, all persistent process
capability sets, protected paths, adversarial PATH shadowing, and shared filesystem
exhaustion, orphan reaping, and shutdown on gateway failure. Pass a second size argument (for example `1024`) to test the Claude
image, which also executes `claude --version`. Native Linux
validation and full hosted assignment evidence are tracked separately by the
runner integration; passing this test alone is not proof of the complete product.
