# syntax=docker/dockerfile:1
FROM node:20-alpine

WORKDIR /app

# Create a lightweight convert stub for the INJ-04 command-injection challenge.
# The real imagemagick binary (~70 MB with ghostscript deps) is replaced by a
# one-liner that echoes its first argument in an error string, which is all the
# challenge needs: the backtick-expanded flag value ends up in the path argument
# and leaks through the thumbnail error response.
# wget (busybox built-in on Alpine) is used for the healthcheck — no apk install needed.
RUN echo '#!/bin/sh' > /usr/local/bin/convert \
    && echo 'echo "convert: unable to open image '"'"'$1'"'"': No such file or directory" >&2' >> /usr/local/bin/convert \
    && echo 'exit 1' >> /usr/local/bin/convert \
    && chmod +x /usr/local/bin/convert

# Install dependencies
COPY package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev --no-audit --no-fund --prefer-offline

# Copy source
COPY src/ ./src/

# Create flag and key directories
RUN mkdir -p /app/flags /app/keys /app/uploads

# Copy flag-data mount point (populated by flag-init container at runtime)
VOLUME ["/flag-data", "/app/uploads"]

EXPOSE 3000

CMD ["node", "src/server.js"]
