# syntax=docker/dockerfile:1.7
FROM node:22-slim AS web
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-slim
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json tsconfig.json ./
COPY src ./src
COPY sandbox ./sandbox
COPY sandbox-servers ./sandbox-servers
COPY eval/results ./eval/results
COPY --from=web /app/web/dist ./web/dist
# Run as the unprivileged "node" user; the sandboxed MCP servers inherit it.
USER node
EXPOSE 8080
CMD ["node", "--import", "tsx", "src/main.ts"]
