FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20-alpine
WORKDIR /app
RUN addgroup -g 1001 nodejs && adduser -S -G nodejs -u 1001 appuser

COPY --from=builder --chown=appuser:nodejs /app /app
COPY . .
COPY animals.json /app/animals.json

# === DATA DIRS ===
RUN mkdir -p /data && \
    chown appuser:nodejs /data && \
    chmod 777 /data

# Sessions in subdirectory (FIX)
RUN mkdir -p /data/sessions && \
    chown appuser:nodejs /data/sessions && \
    chmod 777 /data/sessions

RUN mkdir -p /data/public/task-icons && \
    chown appuser:nodejs /data/public/task-icons

COPY db.sqlite* /data/
RUN chown appuser:nodejs /data/db.sqlite* || true

VOLUME /data
USER appuser
ENV NODE_ENV=production
ENV SQLITE_PATH=/data/db.sqlite
ENV PUBLIC_PATH=/data/public

EXPOSE 3000
CMD ["node", "server.js"]