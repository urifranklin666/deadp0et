FROM node:18-alpine

# Build deps for better-sqlite3 native module
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY sw.js ./
COPY index.html ./
COPY app.js ./
COPY styles.css ./
COPY logo.svg ./
COPY backend ./backend

RUN mkdir -p /app/data/media

EXPOSE 3000

CMD ["node", "server.js"]
