FROM node:18-alpine

WORKDIR /community-server

COPY . .

ENV NODE_ENV=production

# Railway listens ONLY on this
EXPOSE 8080

CMD ["npm", "run", "start:gateway"]
