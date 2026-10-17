FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f
RUN apk upgrade --no-cache
WORKDIR /app
COPY scripts/docker-metadata.js /app/docker-metadata.js
RUN mkdir -p /run/catwaf-discovery && chown 65532:65532 /run/catwaf-discovery \
    && rm -rf /usr/local/lib/node_modules /opt/yarn* /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["node", "-e", "const s=require('net').connect('/run/catwaf-discovery/metadata.sock',()=>s.end());s.setTimeout(3000,()=>process.exit(1));s.on('error',()=>process.exit(1))"]
CMD ["node", "/app/docker-metadata.js"]
