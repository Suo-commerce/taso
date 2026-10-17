# Taso images (plan: claude/Taso_plan_k8s_docker_2026-10-17.md, step D1).
# Build from the repository root, which is the context:
#
#   docker build -f deploy/docker/Dockerfile --target wardend -t taso-wardend .
#   docker build -f deploy/docker/Dockerfile --target coordd  -t taso-coordd  .
#
# Targets
#
#   wardend   taso-wardend + taso-logcheck, runc and the ZFS userland.  Runs
#             privileged with the host's /dev/zfs and pool (see compose.yaml
#             and the Kubernetes manifests).  The ZFS userland must match the
#             host's kernel module: the base is Ubuntu 26.04, whose archive
#             carries 2.4.1 (as on the test server).  A host with another
#             module version needs another base; checked in step D2, not here.
#             taso-landlock is at /usr/lib/taso/landlock, to copy into agent
#             rootfs images (it runs inside the agent's container, not here).
#             The entrypoint is /usr/lib/taso/cgroup-init, which prepares
#             the container's cgroup for the agents' cgroups (cgroup v2)
#             and then runs taso-wardend; a command run in this image that
#             starts runc must go through it too.
#   coordd    taso-coordd alone.  It serves a Unix socket; mount the
#             directory holding it where the Wardens can reach it.  Over a
#             network it needs authentication first (fencing review, F3).
#
# The build stage uses the same base as the runtime stages, so the binaries
# link the same glibc they run with (they need only libc and libgcc_s).

ARG BASE=ubuntu:26.04
ARG RUST_VERSION=1.97.0

# ── build ─────────────────────────────────────────────────────────────

FROM ${BASE} AS builder
ARG RUST_VERSION
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}"
WORKDIR /src
COPY . .
# The target directory is a cache mount (kept between builds, not in the
# image), so the binaries are copied out in the same step.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p taso-warden -p taso-landlock --bins \
 && mkdir -p /out \
 && cp target/release/taso-wardend target/release/taso-coordd \
       target/release/taso-logcheck target/release/taso-landlock /out/

# ── taso-wardend ──────────────────────────────────────────────────────

FROM ${BASE} AS wardend
LABEL org.opencontainers.image.title="taso-wardend" \
      org.opencontainers.image.source="https://github.com/Suo-commerce/taso" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
 && apt-get install -y --no-install-recommends zfsutils-linux runc ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/taso-wardend /out/taso-logcheck /usr/local/bin/
COPY --from=builder /out/taso-landlock /usr/lib/taso/landlock
# Makes the container's cgroup able to hold the agents' cgroups (cgroup v2
# nesting, measured in D2), then execs the command.
COPY deploy/docker/cgroup-init.sh /usr/lib/taso/cgroup-init
# The Warden's state (local coordinator, Chronicle state); mount a volume
# here or point the config elsewhere.
RUN mkdir -p /var/lib/taso /run/taso
# The config names the coordinator, the pool, the store, run_dir and the
# Vessels; mount it here.
ENTRYPOINT ["/usr/lib/taso/cgroup-init", "/usr/local/bin/taso-wardend"]
CMD ["/etc/taso/wardend.json"]

# ── taso-coordd ───────────────────────────────────────────────────────

FROM ${BASE} AS coordd
LABEL org.opencontainers.image.title="taso-coordd" \
      org.opencontainers.image.source="https://github.com/Suo-commerce/taso" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/taso-coordd /usr/local/bin/
# /var/lib/taso holds coord.redb (a volume; it is the coordinator's only
# state and is fsynced on every write); /run/taso holds the socket.
VOLUME ["/var/lib/taso", "/run/taso"]
ENTRYPOINT ["/usr/local/bin/taso-coordd"]
CMD ["/var/lib/taso/coord.redb", "/run/taso/coord.sock"]
