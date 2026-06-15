# PLANTED VIOLATION: no USER directive -- container runs as root (policy domain)
FROM node:20

WORKDIR /app

COPY package.json .
RUN npm install

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
