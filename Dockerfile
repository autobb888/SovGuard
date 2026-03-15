# ── Stage 1: Build ───────────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /app

# Install deps for native modules (better-sqlite3)
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

# Install deps
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile

# Copy source
COPY tsconfig.json ./
COPY src/ src/

# Build server (tsc)
RUN yarn build

# ── Stage 2: Runtime ─────────────────────────────────────────────
FROM node:20-slim

WORKDIR /app

# better-sqlite3 needs build tools for native compilation
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

# Production deps only, then remove build tools to reduce image size
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --production && yarn cache clean \
    && apt-get purge -y python3 make g++ && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Copy built artifacts
COPY --from=builder /app/dist/ dist/

ENV NODE_ENV=production

EXPOSE 3100

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
  CMD node -e "fetch('http://localhost:3100/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

USER node
CMD ["node", "dist/server.js"]
