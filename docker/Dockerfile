FROM node:24.19.0-bookworm-slim
WORKDIR /app
COPY package.json release-public.pem ./
COPY src ./src
COPY scripts/control.js scripts/release-cache.js scripts/release-pull.js ./scripts/
USER 10001:10001
CMD ["node", "src/local/server.js"]
