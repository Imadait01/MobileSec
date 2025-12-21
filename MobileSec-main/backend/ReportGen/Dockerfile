# Build stage
FROM node:20-slim AS builder

WORKDIR /app

# Installer les dépendances système nécessaires pour Puppeteer
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-liberation \
    libappindicator3-1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de dépendances
COPY package*.json ./

# Installer les dépendances
# Utiliser npm install car package-lock.json peut être absent ou désynchronisé
RUN npm install

# Copier le code source
COPY . .

# Build TypeScript
RUN npm run build

# Production stage
FROM node:20-slim

WORKDIR /app

# Installer Chromium pour Puppeteer en production
RUN apt-get update && apt-get install -y \
    chromium \
    dumb-init \
    fonts-liberation \
    libappindicator3-1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Configuration Puppeteer pour utiliser Chromium système
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Créer un utilisateur non-root
RUN groupadd -r reportgen && useradd -r -g reportgen reportgen

# Copier les fichiers nécessaires depuis le builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/src/templates ./dist/templates

# Créer le dossier temporaire
RUN mkdir -p /app/tmp && chown -R reportgen:reportgen /app

# Variables d'environnement par défaut
ENV NODE_ENV=production
ENV PORT=3005
ENV TEMP_DIR=/app/tmp
ENV LOG_LEVEL=info

# Changer vers l'utilisateur non-root
USER reportgen

# Exposer le port
EXPOSE 3005

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3005/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"



# Démarrer l'application avec dumb-init
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/app.js"]
