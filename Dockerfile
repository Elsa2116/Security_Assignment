FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY tsconfig.json .env.example ./
COPY auth.ts ./
COPY src ./src
COPY scripts ./scripts
COPY public ./public
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
# The backup service invokes pg_dump/pg_restore; match the PostgreSQL 16 server
# so newer client-only SQL settings cannot break isolated restore validation.
RUN apk add --no-cache postgresql16-client \
  && addgroup -S secureflow \
  && adduser -S secureflow -G secureflow
COPY --from=build /app/package*.json ./
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/auth.ts ./auth.ts
COPY --from=build /app/public ./public
COPY migrations ./migrations
RUN mkdir -p /app/backups && chown -R secureflow:secureflow /app
USER secureflow
EXPOSE 3000
# Apply idempotent versioned SQL migrations before the API accepts requests so a
# fresh Render/production database always contains Better Auth and app tables.
CMD ["sh", "-c", "node dist/scripts/migrate.js && exec node dist/src/server.js"]
