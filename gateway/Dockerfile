FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
EXPOSE 3001
CMD ["sh", "-c", "node src/seed.js && node src/server.js"]
