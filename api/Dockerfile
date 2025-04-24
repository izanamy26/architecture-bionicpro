FROM node:23-slim

WORKDIR /app

COPY package*.json package-lock.json ./

COPY . .

RUN npm install

EXPOSE 3001

ENTRYPOINT ["npm", "start"]
