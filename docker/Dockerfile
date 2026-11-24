# syntax=docker/dockerfile:1.20@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d
# Node binary is taken from an immutable Docker Official Image; no distro package Node.
FROM node:24.22.3-trixie-slim@sha256:6709bf854652e2d21610e952df82ff9c0b98cc7315acdce75236bbb66bd8aa06 AS node-runtime
FROM ubuntu:24.04@sha256:9a04f13b3f80ef056361e30868593b1cfd2279fe19e4081cb93a90bf56819d6a AS base
ARG USER_UID=10001
ARG USER_GID=10001
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
# Native Ubuntu snapshot mode retains APT signature checks. Never use trusted=yes,
# AllowInsecureRepositories, Check-Valid-Until=false, or mixed Debian/Ubuntu .deb files.
RUN apt-get update --snapshot 20261124T000000Z \
  && apt-get upgrade -y --no-install-recommends --snapshot 20261124T000000Z \
  && apt-get install -y --no-install-recommends --snapshot 20261124T000000Z \
     ca-certificates gosu curl gh git wget ripgrep python3 tini libstdc++6 jq \
     openssh-client=1:9.6p1-3ubuntu13.20 \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid "$USER_GID" node \
  && useradd --uid "$USER_UID" --gid "$USER_GID" --home-dir /paperclip --no-create-home --shell /bin/sh node
ADD --checksum=sha256:9bee59c7313a216722c079c1e22160dea7f88df4e0c3450b1d7b01b882336c6a https://registry.npmjs.org/pnpm/-/pnpm-9.15.4.tgz /tmp/pnpm.tgz
RUN echo '9bee59c7313a216722c079c1e22160dea7f88df4e0c3450b1d7b01b882336c6a  /tmp/pnpm.tgz' | sha256sum -c - \
  && mkdir -p /opt/pnpm \
  && tar -xzf /tmp/pnpm.tgz -C /opt/pnpm --strip-components=1 \
  && ln -s /opt/pnpm/bin/pnpm.cjs /usr/local/bin/pnpm \
  && rm /tmp/pnpm.tgz \
  && test "$(node --version)" = v24.22.3 \
  && test "$(pnpm --version)" = 9.15.4

FROM base AS deps
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./
COPY cli/package.json cli/
COPY server/package.json server/
COPY ui/package.json ui/
COPY packages/shared/package.json packages/shared/
COPY packages/db/package.json packages/db/
COPY packages/adapter-utils/package.json packages/adapter-utils/
COPY packages/google-sheets-mcp-server/package.json packages/google-sheets-mcp-server/
COPY packages/kv-demo-mcp-server/package.json packages/kv-demo-mcp-server/
COPY packages/mcp-server/package.json packages/mcp-server/
COPY packages/paperclip-eval-kernel/package.json packages/paperclip-eval-kernel/
COPY packages/paperclip-runner/package.json packages/paperclip-runner/
COPY packages/skills-catalog/package.json packages/skills-catalog/
COPY packages/tailscale-https-broker/package.json packages/tailscale-https-broker/
COPY packages/teams-catalog/package.json packages/teams-catalog/
COPY packages/adapters/claude-local/package.json packages/adapters/claude-local/
COPY packages/adapters/codex-local/package.json packages/adapters/codex-local/
COPY packages/adapters/cursor-cloud/package.json packages/adapters/cursor-cloud/
COPY packages/adapters/cursor-local/package.json packages/adapters/cursor-local/
COPY packages/adapters/gemini-local/package.json packages/adapters/gemini-local/
COPY packages/adapters/grok-local/package.json packages/adapters/grok-local/
COPY packages/adapters/kimi-local/package.json packages/adapters/kimi-local/
COPY packages/adapters/hermes/package.json packages/adapters/hermes/
COPY packages/adapters/hermes-gateway/package.json packages/adapters/hermes-gateway/
COPY packages/adapters/openclaw-gateway/package.json packages/adapters/openclaw-gateway/
COPY packages/adapters/opencode-local/package.json packages/adapters/opencode-local/
COPY packages/adapters/pi-local/package.json packages/adapters/pi-local/
COPY packages/plugins/sdk/package.json packages/plugins/sdk/
COPY --parents packages/plugins/sandbox-providers/./*/package.json packages/plugins/sandbox-providers/
COPY packages/plugins/paperclip-plugin-fake-sandbox/package.json packages/plugins/paperclip-plugin-fake-sandbox/
COPY packages/plugins/plugin-llm-wiki/package.json packages/plugins/plugin-llm-wiki/
COPY packages/plugins/plugin-workspace-diff/package.json packages/plugins/plugin-workspace-diff/
COPY patches/ patches/
COPY scripts/link-plugin-dev-sdk.mjs scripts/
COPY packages/paperclip-runner/scripts/install-copilot-assets.mjs packages/paperclip-runner/scripts/materialize-copilot-binary.mjs packages/paperclip-runner/scripts/copilot-inner-distribution.mjs packages/paperclip-runner/scripts/
COPY packages/paperclip-runner/src/drivers/acpx/copilot-installation.ts packages/paperclip-runner/src/drivers/acpx/
COPY server/scripts/install-copilot-assets.mjs server/scripts/
COPY server/src/services/copilot-connection-probe.ts server/src/services/

# The reviewed candidate lock is an immutable build input. Never resolve in the build.
RUN pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile

FROM base AS rust-toolchain
ENV CARGO_BUILD_JOBS=2
WORKDIR /app
# Debian's packaged rust lags the ecosystem (trixie ships 1.85) and the
# runner's dependency tree now requires a newer rustc. Install rustup from a
# version-pinned, checksum-verified installer and let the runner's own
# rust-toolchain.toml choose the compiler — one pin, owned by the runner
# package, shared by CI and image builds alike.
#
# The C toolchain is explicit: apt's cargo used to pull gcc in as a
# dependency, and rustup does not — without it every build script dies on
# "linker `cc` not found".
RUN apt-get update --snapshot 20261124T000000Z \
  && apt-get install -y --no-install-recommends --snapshot 20261124T000000Z gcc libc6-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
ARG RUSTUP_VERSION=1.29.0
ARG RUSTUP_SHA256_AMD64=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
ARG RUSTUP_SHA256_ARM64=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) rustTarget="x86_64-unknown-linux-gnu"; sha256="$RUSTUP_SHA256_AMD64" ;; \
      arm64) rustTarget="aarch64-unknown-linux-gnu"; sha256="$RUSTUP_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rustTarget}/rustup-init"; \
    echo "${sha256}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none; \
    rm /tmp/rustup-init
# Install the package-owned compiler before any application source enters the
# stage. rustup-init above installs rustup itself, not the selected compiler.
COPY packages/paperclip-runner/rust-toolchain.toml /tmp/runner-toolchain/rust-toolchain.toml
RUN cd /tmp/runner-toolchain && rustup show

# Pin the recipe generator and its dependency lockfile. It is a build-only tool
# and uses the same package-owned compiler as both native build stages.
FROM rust-toolchain AS rust-chef
RUN cd /tmp/runner-toolchain && cargo install cargo-chef --version 0.1.73 --locked

FROM rust-chef AS runner-plan
WORKDIR /app/packages/paperclip-runner
COPY packages/paperclip-runner/rust-toolchain.toml ./
COPY packages/paperclip-runner/runner ./runner
RUN cd runner && cargo chef prepare --recipe-path /tmp/runner-recipe.json

FROM rust-chef AS runner-deps
WORKDIR /app/packages/paperclip-runner/runner
COPY packages/paperclip-runner/rust-toolchain.toml ../
# The recipe changes only when dependency manifests, the lockfile, or target
# metadata change. Source edits can reuse this compiled dependency layer.
COPY --from=runner-plan /tmp/runner-recipe.json /tmp/runner-recipe.json
RUN cargo chef cook --release --locked --package paperclip-runner-core --bin paperclip-runnerd --recipe-path /tmp/runner-recipe.json \
  && find . -mindepth 1 -maxdepth 1 ! -name target -exec rm -rf {} +

FROM runner-deps AS runner-build
WORKDIR /app/packages/paperclip-runner
# Rust embeds protocol schemas and fixtures with include_str!. Keep those
# alongside the complete Cargo workspace so every compile-time input keys
# this layer. Ordinary server/UI edits can then reuse the native build.
COPY packages/paperclip-runner/rust-toolchain.toml ./
COPY packages/paperclip-runner/runner ./runner
COPY packages/paperclip-runner/protocol ./protocol
COPY packages/paperclip-runner/acpx-profiles.json packages/paperclip-runner/antigravity-distributions.json ./
# Cargo fingerprints source mtimes. Normalize them here and after the full
# source copy below so a fresh checkout cannot invalidate unchanged inputs.
RUN find runner protocol -type f -exec touch -d @0 {} + \
  && touch -d @0 rust-toolchain.toml acpx-profiles.json antigravity-distributions.json \
  && cargo build --release --manifest-path runner/Cargo.toml --locked -p paperclip-runner-core --bin paperclip-runnerd

FROM runner-build AS build
WORKDIR /app
COPY --from=deps /app /app
COPY . .
RUN find packages/paperclip-runner/runner packages/paperclip-runner/protocol -type f -exec touch -d @0 {} + \
  && touch -d @0 packages/paperclip-runner/rust-toolchain.toml packages/paperclip-runner/acpx-profiles.json packages/paperclip-runner/antigravity-distributions.json
# Both the browser bundle and server stamp need the source commit. Declare it
# after the stable dependency layers, before either application build.
ARG PAPERCLIP_BUILD_COMMIT=""
RUN pnpm --filter @paperclipai/ui build
RUN pnpm --filter @paperclipai/plugin-sdk build
# The server build runs scripts/write-build-stamp.mjs, which stamps the built
# commit into dist/build-info.json. The build context has no .git, so the
# script reads PAPERCLIP_BUILD_COMMIT instead. Docker exposes an ARG to the
# next RUN as an environment variable. The production stage below declares the
# same ARG again for the runtime fallback; an ARG goes out of scope at the
# end of its stage. Empty for local `docker build`, which then writes no stamp.
# NODE_OPTIONS covers the Node build steps. tsc is a native binary and ignores it.
ENV NODE_OPTIONS=--max-old-space-size=4096
# The image needs no declarations, and CI type-checks this source separately.
# Emitting without either cuts the tsc step from more than 10 GiB to about 2.5 GiB.
RUN PAPERCLIP_TSC_EMIT_ONLY=1 pnpm --filter @paperclipai/server build
RUN test -f server/dist/index.js || (echo "ERROR: server build output missing" && exit 1)
RUN pnpm --filter @paperclipai/server build:runtime \
  && test -f server/dist-runtime/index.mjs || (echo "ERROR: server runtime bundle missing" && exit 1)
RUN rm -rf packages/paperclip-runner/runner/target

FROM base AS production
ARG USER_UID=10001
ARG USER_GID=10001
WORKDIR /app
# Controller-only image: provider execution is external.
# No global provider CLI installations. Built-in SDK modules remain.
RUN mkdir -p /paperclip && chown node:node /paperclip

COPY scripts/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

COPY --chown=node:node --from=build /app /app

# Native Codex remote execution does not require the Linux ACP/OpenCode pack.
# The server-vendored Runner binaries under /app remain present.

# Declare per-build metadata after the stable RUN layers. Docker includes
# in-scope ARG values in a RUN's environment even when its command does not
# mention them; declaring these earlier invalidates the weekly tool cache.
# The build stage still receives the commit before writing dist/build-info.json.
# Empty for local builds, preserving the server's normal version fallbacks.
ARG PAPERCLIP_BUILD_VERSION=""
ARG PAPERCLIP_BUILD_COMMIT=""
ENV NODE_ENV=production \
  HOME=/paperclip \
  HOST=0.0.0.0 \
  PORT=3100 \
  SERVE_UI=true \
  PAPERCLIP_HOME=/paperclip \
  PAPERCLIP_INSTANCE_ID=default \
  PAPERCLIP_BUILD_VERSION=${PAPERCLIP_BUILD_VERSION} \
  PAPERCLIP_BUILD_COMMIT=${PAPERCLIP_BUILD_COMMIT} \
  USER_UID=${USER_UID} \
  USER_GID=${USER_GID} \
  PAPERCLIP_CONFIG=/paperclip/instances/default/config.json \
  PAPERCLIP_DEPLOYMENT_MODE=authenticated \
  PAPERCLIP_DEPLOYMENT_EXPOSURE=private \
  PAPERCLIP_TELEMETRY_DISABLED=1 \
  PAPERCLIP_UI_DEV_MIDDLEWARE=false \
  HEARTBEAT_SCHEDULER_ENABLED=false

USER 10001:10001
EXPOSE 3100

# tini, not node, is PID 1. The entrypoint ends in `exec`, so without an init
# node inherits PID 1 and never wait()s the orphans the kernel re-parents onto
# it -- agent runs spawn git/claude/esbuild/sh descendants that outlive their
# leader, so they pile up as permanent zombies (~79/h measured) until the
# cgroup pid limit is exhausted and *every* fork() in the container fails.
# tini reaps adopted orphans and forwards signals, so the exec chain below and
# graceful shutdown are unchanged. Mirrors docker/agent-runtime/Dockerfile.base.
ENTRYPOINT ["/usr/bin/tini", "-s", "--", "docker-entrypoint.sh"]
CMD ["node", "server/dist-runtime/index.mjs"]

