FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY tsconfig.json .env.example ./
COPY auth.ts ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package*.json ./
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/auth.ts ./auth.ts
COPY migrations ./migrations
EXPOSE 3000
CMD ["node", "dist/server.js"]
