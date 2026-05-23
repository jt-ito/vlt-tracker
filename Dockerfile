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

# Chromium dependencies needed when the app auto-downloads Chrome to /app/data/.chromium/
# on first use of the Cloudflare bypass feature.
RUN apk add --no-cache \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont

# Copy production node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy app source (no Electron files needed for web mode)
COPY index.html server.js login.html ./
COPY extensions/ ./extensions/

EXPOSE 3000
ENV NODE_ENV=production

# Mount a volume here to persist user accounts and sessions across container restarts.
# Example: docker run -v vlt-data:/app/data ...
VOLUME ["/app/data"]

CMD ["node", "server.js"]
