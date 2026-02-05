FROM node:18-alpine

WORKDIR /app
COPY . .

ENV NODE_ENV=production

# 🚨 Railway hanya expose 1 port → Gateway
EXPOSE 3000

CMD ["node", "gateway.mjs"]
