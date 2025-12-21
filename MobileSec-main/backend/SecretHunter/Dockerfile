# Stage 1: Base avec dépendances système
FROM python:3.11-slim AS base

# Variables d'environnement
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    default-jre-headless \
    wget \
    unzip \
    git \
    libmagic1 \
    yara \
    curl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Installer apktool
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool && \
    wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.1.jar -O /usr/local/bin/apktool.jar && \
    chmod +x /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool.jar

# Installer gitleaks
RUN wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz -O /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks && \
    rm /tmp/gitleaks.tar.gz

# Stage 2: Build Python dependencies
FROM base AS builder

WORKDIR /app

# Copier requirements.txt
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 3: Production
FROM base

# Créer un utilisateur non-root
RUN useradd -m -u 1000 hunter && \
    mkdir -p /app /app/output /app/uploads /app/rules /app/logs /app/database && \
    chown -R hunter:hunter /app

WORKDIR /app

# Copier les dépendances Python depuis le builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copier le code source
COPY --chown=hunter:hunter core/ ./core/
COPY --chown=hunter:hunter rules/ ./rules/
COPY --chown=hunter:hunter database/ ./database/
COPY --chown=hunter:hunter cli.py .
COPY --chown=hunter:hunter api.py .

# Exposer le port
EXPOSE 5002

# Utiliser l'utilisateur non-root
USER hunter

# Variables d'environnement
ENV PORT=5002 \
    PYTHONPATH=/app

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:5002/health || exit 1

# Démarrer l'application
CMD ["python", "api.py"]
