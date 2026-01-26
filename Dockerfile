FROM node:18-alpine

# Metadata
LABEL maintainer="Solid Gateway + Audit Maintainer"

# Install basic deps
RUN apk add --no-cache bash

# Create writable directories
RUN mkdir -p /config /data /community-server

# Set working directory
WORKDIR /community-server

# Copy project
COPY . .

# Ensure permissions (important for audit log)
RUN chown -R node:node /community-server /data

USER node

# Expose ports
# 3001 = Gateway (public)
# 3000 = CSS (internal, optional expose for debug)
EXPOSE 3001
EXPOSE 3000

# ENV
ENV NODE_ENV=production
ENV DATA_ROOT=/data
ENV CSS_CONFIG=config/file.json

# BASE_URL MUST point to gateway
# example: http://localhost:3001 or https://solid.example.com
ENV BASE_URL=""

# Start Gateway (which spawns CSS internally)
CMD sh -c '\
  if [ -z "$BASE_URL" ]; then \
    echo "❌ ERROR: BASE_URL is not set"; exit 1; \
  fi && \
  echo "🚀 Starting Solid Gateway with BASE_URL=$BASE_URL" && \
  node gateway.js \
'
