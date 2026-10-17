# docker/Caddy.Dockerfile — builds a Caddy binary with the Coraza WAF module
# baked in, and serves the frontend's static build alongside it.
#
# Three responsibilities live in this one container, matching how the app
# already works outside Docker (see docs/reverse-proxy.md):
#   1. Serve the dashboard's built static files (the SPA)
#   2. Reverse-proxy /api to the backend container
#   3. Run the actual WAF site block(s) that protect your real application
#
# Why Caddy needs its own build stage: CatWAF is built specifically on
# Coraza (github.com/corazawaf/coraza-caddy), a native Go WAF module — not
# ModSecurity — and that module isn't part of Caddy's default build. It has
# non-Docker equivalent of this same step.

# ── Stage 1: build the frontend ──────────────────────────────────────────
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend ./
RUN npm run build
# Output: /app/frontend/dist

# ── Stage 2: build Caddy with the Coraza module ──────────────────────────
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

# Node observes the proxy's writable descriptors without sharing the PID namespace.
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f AS observer-runtime

# ── Stage 3: final runtime image ─────────────────────────────────────────
FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
RUN apk upgrade --no-cache && apk add --no-cache libstdc++
COPY --from=observer-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=observer-runtime /usr/local/LICENSE /usr/local/share/licenses/node/LICENSE
COPY scripts/caddy-supervisor.js /opt/catwaf/scripts/caddy-supervisor.js
COPY backend/services/auditWriters.js /opt/catwaf/backend/services/auditWriters.js
COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy
COPY --from=frontend-build /app/frontend/dist /srv/dashboard
COPY docker/Caddyfile /etc/caddy/Caddyfile

# CORAZA_LIST_DIR in .env.example — a place for IP/UA lists Coraza reads
# directly (separate from the WAF directives block CatWAF's backend writes
# into the Caddyfile itself).
RUN mkdir -p /etc/coraza/lists
RUN mkdir -p /run/catwaf-admin /var/log/coraza \
    && touch /var/log/coraza/audit.json \
    && chgrp -R 1000 /run/catwaf-admin /etc/caddy /var/log/coraza \
    && chmod 2770 /run/catwaf-admin /etc/caddy /var/log/coraza \
    && chmod 0660 /etc/caddy/Caddyfile /var/log/coraza/audit.json

EXPOSE 80 443 8081

# Confirm the module actually made it into the binary at build time, not
# you to run by hand.
RUN caddy list-modules | grep -q http.handlers.waf

# Keep the proxy distinct from backend UID 1000: sharing that UID would let
# it read the backend's 0600 SQLite file through the read-only asset mount.
RUN mkdir -p /data/caddy /config/caddy \
    && chown -R 1001:1000 /data /config
USER 1001:1000
ENTRYPOINT ["node", "/opt/catwaf/scripts/caddy-supervisor.js"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8081/ || exit 1
