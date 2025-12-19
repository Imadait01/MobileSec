# Stage 1: Base
FROM python:3.11-slim AS base

# Variables d'environnement
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

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
RUN useradd -m -u 1000 inspector && \
    mkdir -p /app /app/uploads /app/captures /app/logs && \
    chown -R inspector:inspector /app

# Ajouter l'utilisateur au groupe docker pour accéder au socket Docker
RUN usermod -aG docker inspector || true

WORKDIR /app

# Copier les dépendances Python depuis le builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copier le code source
COPY --chown=inspector:inspector src/ ./src/
COPY --chown=inspector:inspector requirements.txt .

# Créer les fichiers __init__.py
RUN touch src/__init__.py && \
    touch src/utils/__init__.py && \
    touch src/proxy/__init__.py

# Exposer le port
EXPOSE 5001

# Utiliser l'utilisateur non-root
USER inspector

# Variables d'environnement
ENV PORT=5001 \
    PYTHONPATH=/app/src \
    DEBUG=False

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
  CMD curl -f http://localhost:5001/health || exit 1

# Démarrer l'application
CMD ["python", "src/main.py"]
