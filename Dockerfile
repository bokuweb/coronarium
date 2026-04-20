# syntax=docker/dockerfile:1.6
#
# coronarium-proxy — runnable as a standalone container.
#
#   docker run --rm -p 8910:8910 ghcr.io/bokuweb/coronarium-proxy:v0 \
#       --listen 0.0.0.0:8910 --min-age 7d
#
# The image only ships the `coronarium` binary (scratch-ish
# distroless). The CA bundle is generated on first run inside the
# mounted config volume — bind-mount `/etc/coronarium` to persist it
# across container restarts:
#
#   docker run --rm -p 8910:8910 -v coronarium-conf:/etc/coronarium \
#       ghcr.io/bokuweb/coronarium-proxy:v0 \
#       --listen 0.0.0.0:8910 --min-age 7d
#
# For GitHub Actions adoption use `bokuweb/coronarium/proxy@v0` —
# it's a composite action that downloads the same binary and wires
# HTTPS_PROXY into $GITHUB_ENV for subsequent steps. The container
# image is for users who want to run the proxy in their own infra
# (Kubernetes, docker-compose, bare ECS, …).

# ---------- build stage ----------
FROM rust:1-bookworm AS build

WORKDIR /src
COPY . .

# Only build the proxy binary. Workspace excludes coronarium-ebpf from
# the default members, so this won't try to compile kernel programs.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p coronarium && \
    cp /src/target/release/coronarium /usr/local/bin/coronarium && \
    strip /usr/local/bin/coronarium || true

# ---------- runtime stage ----------
FROM debian:bookworm-slim

# ca-certificates: the proxy fetches publish dates from the real
# registries via TLS and needs the system root CAs to verify them.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/coronarium /usr/local/bin/coronarium

# Persist the generated CA + config here. Users should mount a
# volume so the CA is stable across restarts; without a mount, the
# CA is regenerated on every run (still works, but client trust
# would have to be re-installed each time).
ENV XDG_CONFIG_HOME=/etc/coronarium-xdg
RUN mkdir -p /etc/coronarium-xdg/coronarium

EXPOSE 8910

# tini so Ctrl-C / SIGTERM from `docker stop` reaches the proxy
# quickly and children don't zombie.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/coronarium", "proxy", "start"]
CMD ["--listen", "0.0.0.0:8910", "--min-age", "7d"]
