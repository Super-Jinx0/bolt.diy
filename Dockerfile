# Deplexo deployment for the official stackblitz-labs/bolt.diy source.
# Public gateway: :5183. Private bolt.diy: 127.0.0.1:5173.
# This intentionally replaces the upstream Dockerfile in your fork.

FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV HUSKY=0 CI=true
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY package.json pnpm-lock.yaml* ./
RUN pnpm fetch
COPY . .
RUN pnpm install --offline --frozen-lockfile
# Upstream build needs a large Node heap. The builder must provide enough RAM for this step.
RUN NODE_OPTIONS=--max-old-space-size=4096 pnpm run build

# Retain dev dependencies: runtime is vite preview, and pruning removes vite.
FROM build AS runtime
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The platform's app filesystem is read-only. Preserve build-generated state in the image,
# then point known runtime-write locations at disposable /tmp paths.
RUN set -eu; mkdir -p /opt/seed /app/node_modules; \
    for p in .wrangler/state .wrangler/tmp .react-router/types .cloudflare/state .cloudflare/tmp; do \
      mkdir -p "/app/$(dirname "$p")" "/opt/seed/$(dirname "$p")"; \
      if [ -e "/app/$p" ]; then mv "/app/$p" "/opt/seed/$p"; fi; \
      ln -s "/tmp/state/$p" "/app/$p"; \
    done; \
    rm -rf /app/node_modules/.vite /app/node_modules/.vite-temp /app/node_modules/.cache; \
    ln -s /tmp/vite-cache /app/node_modules/.vite; \
    ln -s /tmp/vite-temp /app/node_modules/.vite-temp; \
    ln -s /tmp/node-cache /app/node_modules/.cache

ENV NODE_ENV=production \
    PORT=5183 \
    INTERNAL_PORT=5173 \
    RUNNING_IN_DOCKER=true \
    VITE_LOG_LEVEL=info \
    DEFAULT_NUM_CTX=32768 \
    WRANGLER_SEND_METRICS=false \
    HOME=/tmp/home \
    XDG_CONFIG_HOME=/tmp/xdg-config \
    XDG_DATA_HOME=/tmp/xdg-data \
    XDG_CACHE_HOME=/tmp/xdg-cache \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs \
    BOLT_NODE_HEAP_MB=384

USER node
EXPOSE 5183
CMD ["node", "/app/deplexo-gateway.mjs"]
