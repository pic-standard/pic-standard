# Deploying the PIC HTTP bridge with Docker

This document describes the hardened `docker-compose.yml` shipped in
this repository for running the reference PIC HTTP bridge locally.

## Purpose and audience

The compose file at the repository root brings up a single service,
`pic-server`, that serves the PIC HTTP bridge on the host loopback
interface. It is intended for:

- Local verification of PIC proposals against a fixed policy and key
  set.
- Alpha-stage integration testing from non-Python clients.
- A reference profile that other deployment tooling can copy from.

It is **not** intended as a production deployment recipe. The section
"What this hardening does not cover" below spells out what it leaves
to operator responsibility.

## Quickstart

```bash
docker compose up -d --build

# Liveness
curl -sS http://127.0.0.1:7580/health

# Version and machine-readable metadata
curl -sS http://127.0.0.1:7580/v1/version | python -m json.tool
```

Stop and remove:

```bash
docker compose down
```

The full request/response contract for `POST /verify`, `GET /health`,
and `GET /v1/version` is in
[`openapi/pic-bridge.v1.yaml`](../openapi/pic-bridge.v1.yaml). The PIC
error taxonomy for `error.code` values is in
[`docs/ERRORS.md`](ERRORS.md).

## Security hardening

Each control below is set on the `pic-server` service in
`docker-compose.yml`. The controls are cumulative; removing any one of
them weakens the profile.

### Loopback-only port binding

```yaml
ports:
  - "127.0.0.1:7580:7580"
```

The published host port is reachable from processes on the same host,
but not from other hosts through the host network interface. Other
services intentionally attached to the `pic-internal` Compose network
may still reach the bridge by service name.

### Read-only rootfs and bounded tmpfs

```yaml
read_only: true
tmpfs:
  - /tmp:size=64m,noexec,nosuid,nodev
```

The container filesystem is mounted read-only. Only `/tmp` is
writable, backed by a 64 MB tmpfs mounted `noexec,nosuid,nodev`. The
bridge does not persist any state on disk at runtime (audit records
go to stdout, HTTPServer is stateless, and the Dockerfile sets
`PYTHONDONTWRITEBYTECODE=1` so `.pyc` files are never emitted).

### Dropped Linux capabilities

```yaml
cap_drop:
  - ALL
```

The container starts with no Linux capabilities. The bridge is a
plain Python process and needs none. This blocks `CAP_NET_RAW`,
`CAP_SYS_ADMIN`, and every other capability the base image would
otherwise inherit.

### No new privileges

```yaml
security_opt:
  - no-new-privileges:true
```

Prevents any process the container starts from gaining new privileges
via `setuid` / `setgid` binaries or file capabilities. This is
belt-and-suspenders alongside the non-root user pin below.

### Non-root user pin

```yaml
user: "10001:10001"
```

The Dockerfile creates and runs as user `pic` (uid `10001`, gid
`10001`). The compose file pins the same uid/gid so a future
Dockerfile edit cannot silently regress the container to root.

### Init process

```yaml
init: true
```

Uses Docker's minimal init (`tini`) as PID 1 for correct signal
propagation and zombie reaping. Purely operational hygiene; not a
security control on its own.

### Runtime resource limits

```yaml
mem_limit: 512m
cpus: "0.5"
pids_limit: 128
deploy:
  resources:
    limits:
      memory: 512M
      cpus: "0.5"
```

Both the direct runtime fields (`mem_limit`, `cpus`, `pids_limit`)
and the Compose-spec canonical form (`deploy.resources.limits`) are
set. The runtime fields make `docker inspect` unambiguous outside
Swarm-style `deploy` semantics. Values are sized generously for an
alpha bridge; production deployments should re-benchmark and adjust.

### Explicit internal bridge network

```yaml
networks:
  pic-internal:
    driver: bridge
```

The service is attached to a named user-defined bridge network rather
than the default. This makes the network topology explicit and lets
future services in this compose file communicate with the bridge
without also being on the default bridge with everything else on the
host.

## File permissions

Because the compose file pins `user: "10001:10001"`, the host-mounted
config files must be **readable by uid/gid 10001:10001** inside the
container. Docker Desktop on Windows and macOS usually handles this
transparently through the file-sharing driver, but on Linux the host
inode permissions apply directly.

On Linux:

```bash
chmod 0444 pic_policy.json pic_keys.example.json
```

If your files were created by a different user and are still not
readable, adjust ownership to match the container user:

```bash
sudo chown 10001:10001 pic_policy.json pic_keys.example.json
```

Only add write permission if you explicitly intend to allow the
container to modify the file (this deployment profile does not).

## Why `/workspace` is not mounted

The image already contains the installed Python package. The compose
file mounts only policy and key files. Source-code mounts are
intentionally omitted from the hardened runtime profile so that a
container running against production configuration never depends on
whatever Python source happens to sit next to the compose file on the
host.

The Dockerfile ships a `CMD ["--host", "0.0.0.0", "--port", "7580",
"--repo-root", "/workspace"]` default that assumes such a mount. The
compose file overrides the command to drop `--repo-root` so the CLI
falls back to its default (`Path(".").resolve()` = `/app` inside the
container). `PIC_POLICY_PATH` and `PIC_KEYS_PATH` are set in the
environment block so no policy or key discovery ever needs to walk
the (non-existent) `/workspace` tree.

## Verifying the hardening

After `docker compose up -d`, inspect the running container to
confirm every control is applied. Each command below should print the
expected value; deviations mean the compose file was not honored (an
old container is still running, an override file relaxed something,
or the compose engine is too old).

```bash
docker inspect pic-cli-serve --format '{{json .HostConfig.ReadonlyRootfs}}'
# expected: true

docker inspect pic-cli-serve --format '{{json .HostConfig.CapDrop}}'
# expected: ["ALL"]

docker inspect pic-cli-serve --format '{{json .HostConfig.SecurityOpt}}'
# expected: includes "no-new-privileges:true"

docker inspect pic-cli-serve --format '{{json .HostConfig.Tmpfs}}'
# expected: includes /tmp with size=64m,noexec,nosuid,nodev

docker inspect pic-cli-serve --format '{{json .HostConfig.Memory}}'
# expected: 536870912   (512 MiB in bytes)

docker inspect pic-cli-serve --format '{{json .HostConfig.NanoCpus}}'
# expected: 500000000   (0.5 CPU in nanocpus)

docker inspect pic-cli-serve --format '{{json .HostConfig.PidsLimit}}'
# expected: 128

docker inspect pic-cli-serve --format '{{json .Config.User}}'
# expected: "10001:10001"

docker inspect pic-cli-serve --format '{{json .NetworkSettings.Ports}}'
# expected: 7580/tcp mapped to 127.0.0.1:7580 only
```

## Overriding for local development

Local overrides go in a separate `docker-compose.override.yml` file
sitting next to the base compose file; Docker Compose merges them
automatically. Keep overrides narrow. Blanket relaxations (undoing
`read_only`, dropping `cap_drop`, rebinding to `0.0.0.0`) are a
recipe for accidentally deploying a weakened profile.

Two safe examples:

Publish on a different host port because 7580 is in use:

```yaml
# docker-compose.override.yml
services:
  pic-server:
    ports:
      - "127.0.0.1:17580:7580"
```

Mount a temporary read-only evidence directory for a specific
verification session:

```yaml
# docker-compose.override.yml
services:
  pic-server:
    volumes:
      - ./tmp-evidence:/evidence:ro
```

Do not commit the override file to version control.

## What this hardening does not cover

The compose profile addresses container-level hardening. It does not
substitute for:

- **TLS and public internet exposure.** The bridge speaks plain HTTP
  on loopback only. Terminate TLS in an authenticating reverse proxy
  before exposing beyond the host.
- **Authentication and authorization in front of the bridge.** There
  is no built-in caller identity check; every process that can reach
  the loopback port can call `/verify`.
- **Malicious or over-broad PIC policies.** The policy file the
  bridge loads is trusted input; over-permissive policies grant
  over-permissive behavior.
- **Malicious key material.** Signature evidence is only as good as
  the trusted-signer keyring supplied.
- **Application-level rate limiting.** The bridge enforces
  per-request time budgets, but does not provide global caller
  throttling or application-level rate limiting.
- **Full container sandboxing against kernel or container-runtime
  vulnerabilities.** `cap_drop: ALL` + `no-new-privileges` + non-root
  reduces blast radius; they do not turn the container into a
  hypervisor-grade sandbox.
- **Production secrets management.** Files mounted from the host are
  visible in plain text inside the container. Use a secrets manager
  for anything more sensitive than a repository-tracked example key.

## Docker availability gate

This document and the compose file can be reviewed and structurally
validated without Docker installed. Full runtime verification of the
hardened profile requires Docker Engine (or Docker Desktop) on the
host. When Docker is available, run:

```bash
docker compose config          # parses and renders the merged spec
docker compose up -d --build   # builds the image and starts the container
docker inspect pic-cli-serve   # confirms every hardening control
```

Contributors changing `docker-compose.yml` in a PR should run these
locally and paste the relevant `docker inspect` output into the PR
description; CI does not yet gate on a live Docker run.
