# Dockerfile — CatWAF backend API.
#
# Node 22+ is required (not just recommended) because the backend uses the
# built-in `node:sqlite` module (see backend/services/db.js) — there's no
# separate database server to run, but this does mean the base image can't
# be downgraded to save size the way a lot of "just needs Express" Dockerfiles
# do.

# The offline restore and transaction paths must validate before activating
# configuration, even while the separate Caddy service is stopped.
FROM caddy:2.11.7-builder@sha256:d842facfd63b960922e57444ff76fd8f0793a66dfdcf481af8026e1f4e6a39b4 AS caddy-build
WORKDIR /build
ENV GOTOOLCHAIN=go1.26.9 CGO_ENABLED=0
# Retain symbols so vulnerability scanners can inspect package reachability.
ENV XCADDY_GO_BUILD_FLAGS="-trimpath -tags=nobadger,nomysql,nopgx"
# Original upstream xcaddy integration, with security version pins only.
RUN xcaddy build v2.11.7 --output /usr/bin/caddy \
    --with github.com/corazawaf/coraza-caddy/v2@v2.6.2 \
    --with golang.org/x/net/http2@v0.61.0 \
    --with golang.org/x/crypto/cryptobyte@v0.58.0
RUN setcap -r /usr/bin/caddy

FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f AS base
WORKDIR /app
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
# Apply distribution fixes newer than the base image. OpenSSL supports
# legacy encrypted backup import and Cloudflare certificate requests.
RUN apk upgrade --no-cache && apk add --no-cache openssl

LABEL org.opencontainers.image.title="CatWAF" \
      org.opencontainers.image.description="Web application firewall built on Caddy + Coraza + OWASP CRS" \
      org.opencontainers.image.version="1.0.2" \
      org.opencontainers.image.source="https://github.com/agugusgeyehe-dot/catwaf" \
      org.opencontainers.image.licenses="LicenseRef-PolyForm-Internal-Use-1.0.0"

# This image is the API server only. Caddy (with Coraza) and the built
# dashboard live in docker/Caddy.Dockerfile, so:
#   CATWAF_SKIP_CADDY_DOWNLOAD  uses the validated binary copied above.
#   CATWAF_EDITION=full         this container provides the HTTP API. frontend/
#                               is deliberately not copied, and postinstall
#                               detects that and skips the dashboard install.
ENV CATWAF_SKIP_CADDY_DOWNLOAD=1 \
    CATWAF_EDITION=full

# Install backend dependencies first, separately from copying the rest of
# the source — Docker layer caching means `docker build` skips this step
# entirely on rebuilds where only application code changed, not package.json.
COPY package.json package-lock.json* ./
COPY scripts ./scripts
COPY backend/services/env.js ./backend/services/env.js
RUN npm ci --omit=dev --omit=optional && npm cache clean --force
# Runtime containers execute Node directly. Package-manager dependencies
# need not remain in the deployed image; rebuild images to install updates.
RUN rm -rf /usr/local/lib/node_modules /opt/yarn* /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg

# Now the actual application code.
COPY backend ./backend

# The CLI (224 KB of JS, no extra dependencies) so administrative commands are
# available inside the container. Without it there was no way to create the
# first admin account in a Docker deployment at all — the stack came up with
# no accounts, by design, and no means of adding one.
COPY bin ./bin
COPY src ./src

# Where the SQLite file and Caddy sync data live — created automatically at
# runtime if missing (see services/db.js), declared here so `docker volume`
# users have an obvious mount point without reading the source.
RUN mkdir -p /app/data \
    && chown -R node:node /app
VOLUME ["/app/data"]

# Run as the image's unprivileged `node` user. The API only needs to write
# /app/data (and whatever the operator mounts there); running as root gave a
# container escape or RCE in the API direct root in the container, with
# write access to the shared Caddy configuration volume on top.
USER node

ENV NODE_ENV=production
ENV PORT=8000
# The backend defaults to 127.0.0.1, which is right for a host install and
# wrong inside a container: the loopback interface here belongs to this
# container alone, so the sibling Caddy container's `reverse_proxy backend:8000`
# was refused and every dashboard API call returned 502, while the published
# host port answered nothing at all. The container boundary — not a loopback
# bind — is what keeps this off the network; docker-compose.yml decides what
# is published.
ENV HOST=0.0.0.0
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8000)+'/healthz',{signal:AbortSignal.timeout(4000)}).then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]

# --experimental-sqlite is required until node:sqlite graduates out of
# experimental status — same flag package.json's own "dev:backend" script
# uses locally, kept consistent here.
CMD ["node", "--experimental-sqlite", "backend/server.js"]
