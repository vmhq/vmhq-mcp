# Pinned by digest so a rebuild cannot pick up a different image under the
# same tag; Dependabot proposes digest bumps (.github/dependabot.yml).
FROM oven/bun:1.3-alpine@sha256:5acc90a93e91ff07bf72aa90a7c9f0fa189765aec90b47bdbf2152d2196383c0 AS base
WORKDIR /app

COPY package.json bun.lock* ./
# Bun runs the TypeScript sources directly, so the dev toolchain stays out.
RUN bun install --frozen-lockfile --production

COPY tsconfig.json ./
COPY src ./src

ENV NODE_ENV=production
ENV MCP_PORT=3010

RUN addgroup -S app && adduser -S app -G app \
  && mkdir -p /app/data \
  && chown -R app:app /app/data
USER app

EXPOSE 3010
CMD ["bun", "src/index.ts"]
