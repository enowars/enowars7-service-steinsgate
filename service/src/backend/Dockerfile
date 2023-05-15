FROM node:alpine

WORKDIR /app

COPY app.js app.js
COPY middleware.js middleware.js
COPY package.json package.json

RUN npm install

ENTRYPOINT TOKEN_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1) node app.js
