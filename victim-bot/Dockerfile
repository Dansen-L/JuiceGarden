FROM mcr.microsoft.com/playwright:v1.40.0-jammy

WORKDIR /app

# Copy package files
COPY package*.json ./

# Skip browser download — chromium is pre-installed in the base image (v1.40.0).
# playwright package version is pinned to match the base image exactly so the
# bundled browser revision is the same one that is already installed.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
RUN npm install --omit=dev

# Copy source
COPY src/ ./src/

# Launch with host-resolver-rules for garden.lab and attacker.lab routing

CMD ["node", "src/bot.js"]
