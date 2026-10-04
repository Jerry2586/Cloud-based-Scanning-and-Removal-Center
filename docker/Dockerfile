ARG IRONCURTAIN_NODE_IMAGE=docker.io/library/node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df
FROM ${IRONCURTAIN_NODE_IMAGE}
WORKDIR /app
COPY package.json release-public.pem ./
COPY src ./src
COPY scripts/control.js scripts/release-cache.js scripts/release-pull.js scripts/virus-db-pull.js ./scripts/
USER 10001:10001
CMD ["node", "src/local/server.js"]
