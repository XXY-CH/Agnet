# Docker compatibility smoke

`docker_smoke_test.go` is deliberately excluded from ordinary test runs with the `docker_smoke` build tag. It is a compatibility harness for the production `DockerCLIAdapter`; it never selects, starts, or falls back to Apple Container.

Run the focused harness only when Docker is already running, the approved local binary and Unix socket are available, and this exact image is already present locally:

```sh
go test -tags=docker_smoke ./cmd/go-fed-discovery -run '^TestDockerCompatibilitySmoke$'
AGNET_DOCKER_SMOKE=1 go test -tags=docker_smoke ./cmd/go-fed-discovery -run '^TestDockerCompatibilitySmoke'
```

The first command skips because the explicit opt-in is absent. The second command performs no pull or build. If `/usr/local/bin/docker`, `/var/run/docker.sock`, the daemon, or the exact digest-pinned image is unavailable, it fails with a `BLOCKED: Docker prerequisite failure` message instead of substituting another runtime.

When prerequisites are available, the harness exercises `DockerCLIAdapter` with deterministic scratch input, a read-only root filesystem, writable `/work`, no default network, CPU/memory/nofile constraints, bounded stdout/stderr/result capture, postflight identity checks, overflow rejection without a promotable result, and force removal.
