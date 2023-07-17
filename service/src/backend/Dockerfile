FROM node:alpine

WORKDIR /app

RUN apk add sqlite

COPY app.js app.js
COPY cleanup.sh cleanup.sh
COPY middleware.js middleware.js
COPY package.json package.json

RUN chmod +x /app/cleanup.sh
RUN echo "* * * * * /bin/sh /app/cleanup.sh" >> /var/spool/cron/crontabs/root

RUN npm install

ENTRYPOINT crond && TOKEN_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) node app.js
