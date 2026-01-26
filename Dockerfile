FROM node:18-alpine

LABEL maintainer="Solid Gateway + Audit"

WORKDIR /community-server

# Copy all files
COPY . .

# Install deps
RUN npm install --omit=dev

# Expose PUBLIC gateway port
EXPOSE 3001

# Environment
ENV NODE_ENV=production
ENV GATEWAY_PORT=3001
ENV CSS_PORT=3000

# Start ONLY gateway
CMD ["node", "gateway.mjs"]
