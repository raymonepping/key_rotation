# ---- build/runtime (Node 18) ----
FROM node:18-alpine

WORKDIR /app

# Install deps first for better layer caching
COPY package*.json ./
RUN npm ci --only=production

# App code
COPY server.js ./server.js
COPY apiKeyAuth.js ./apiKeyAuth.js

# Optional: include rendered/ if you use Agent file mode
# COPY rendered ./rendered

# Env defaults (you can override via compose)
ENV PORT=3001 \
    METHOD=VAULT \
    LOG_LEVEL=INFO

EXPOSE 3001
CMD ["node", "server.js"]