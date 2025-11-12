FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:20-alpine
WORKDIR /app

# Create user
RUN addgroup -g 1001 nodejs && adduser -S -G nodejs -u 1001 appuser

# Copy app
COPY --from=builder --chown=appuser:nodejs /app /app
COPY . .
COPY animals.json /app/animals.json

# === PERSISTENT DATA DIRS ===
RUN mkdir -p /data && \
    chown appuser:nodejs /data && \
    chmod 777 /data

# Sessions
RUN mkdir -p /data/sessions && \
    chown appuser:nodejs /data/sessions && \
    chmod 777 /data/sessions

# Public files
RUN mkdir -p /data/public/task-icons && \
    chown appuser:nodejs /data/public/task-icons

# === COPY DB FROM REPO ROOT ===
COPY db.sqlite /data/db.sqlite
RUN chown appuser:nodejs /data/db.sqlite || true

# === VOLUME & ENV ===
VOLUME /data
USER appuser
ENV NODE_ENV=production
ENV SQLITE_PATH=/data/db.sqlite
ENV PUBLIC_PATH=/data/public

# RENDER EXPECTS 8080
EXPOSE 8080

CMD ["node", "server.js"]