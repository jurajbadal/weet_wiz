FROM node:20-slim

RUN apt-get update && apt-get install -y wget ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json .
RUN npm install

# Chromium only — smallest footprint
RUN npx playwright install --with-deps chromium

COPY src/ ./src/

EXPOSE 8080

CMD ["node", "src/index.js"]
