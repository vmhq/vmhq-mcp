# Pinned by digest so a rebuild cannot pick up a different image under the
# same tag; Dependabot proposes digest bumps (.github/dependabot.yml).
FROM oven/bun:1.4-alpine@sha256:d888c0ae6c86d7866ff10c5aafdd9077b36aee6455b33dd270fb93c0dd5cef6f AS base
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
