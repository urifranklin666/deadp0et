FROM node:18-alpine

WORKDIR /app

COPY package.json ./
COPY server.js ./
COPY index.html ./
COPY app.js ./
COPY protocol-client.js ./
COPY styles.css ./
COPY backend ./backend

RUN mkdir -p /app/data

EXPOSE 3000

CMD ["npm", "start"]
