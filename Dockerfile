FROM node:18-alpine

# App directory
WORKDIR /app

# Copy project
COPY . .

ENV NODE_ENV=production

# 🚨 Railway PUBLIC port (HARUS sama)
EXPOSE 3000

# Railway injects PORT automatically
# Gateway will listen on process.env.PORT || 3000
CMD ["node", "gateway.mjs"]
