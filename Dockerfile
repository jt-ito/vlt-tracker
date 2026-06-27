# ── Stage 1: install production deps ─────────────────────────────────────────
FROM node:20-slim AS deps
WORKDIR /app
# python3 + make + g++ are required to compile better-sqlite3 (native addon)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ && \
    rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --omit=dev

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM node:20-slim
WORKDIR /app

# Runtime libs for Chrome auto-downloaded to /app/data/.chromium/ on first CF bypass use.
# node:20-slim is Debian-based (glibc), so the Google Chrome binary works correctly.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    ca-certificates \
    fonts-freefont-ttf \
    && rm -rf /var/lib/apt/lists/*

# Copy production node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy app source (no Electron files needed for web mode)
COPY index.html server.js login.html favicon.svg ./
COPY extensions/ ./extensions/

EXPOSE 3000
ENV NODE_ENV=production

# Mount a volume here to persist user accounts and sessions across container restarts.
# Example: docker run -v vlt-data:/app/data ...
VOLUME ["/app/data"]

CMD ["node", "server.js"]
