FROM oven/bun:1.2-alpine AS base
WORKDIR /app

COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src

ENV NODE_ENV=production
ENV MCP_PORT=3010

RUN addgroup -S app && adduser -S app -G app
USER app

EXPOSE 3010
CMD ["bun", "src/index.ts"]
