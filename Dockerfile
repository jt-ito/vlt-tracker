# ── Stage 1: install production deps ─────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
# python3 + make + g++ are required to compile better-sqlite3 (native addon)
RUN apk add --no-cache python3 make g++
COPY package*.json ./
RUN npm ci --omit=dev

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Copy production node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy app source (no Electron files needed for web mode)
COPY index.html server.js login.html ./
COPY extensions/ ./extensions/

# Run as non-root user
RUN addgroup -S vlt && adduser -S vlt -G vlt && chown -R vlt:vlt /app
USER vlt

EXPOSE 3000
ENV NODE_ENV=production

# Mount a volume here to persist user accounts and sessions across container restarts.
# Example: docker run -v vlt-data:/app/data ...
VOLUME ["/app/data"]

# Cloudflare bypass (puppeteer-core) requires a real Chrome install.
# In container mode it will gracefully fail — the plain CORS proxy still works.
CMD ["node", "server.js"]
