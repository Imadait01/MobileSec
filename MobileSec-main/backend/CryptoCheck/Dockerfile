# Stage 1: Build
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Copier les fichiers de configuration Maven
COPY pom.xml .

# Télécharger les dépendances (cache)
RUN mvn dependency:go-offline -B

# Copier le code source
COPY src ./src

# Build l'application (skip test compilation)
RUN mvn clean package -Dmaven.test.skip=true -B

# Stage 2: Production
FROM eclipse-temurin:17-jre-alpine

# Créer un utilisateur non-root
RUN addgroup -g 1001 -S cryptocheck && \
    adduser -S cryptocheck -u 1001 -G cryptocheck

WORKDIR /app

# Copier le JAR depuis le builder
COPY --from=builder /app/target/*.jar app.jar

# Créer les répertoires nécessaires
RUN mkdir -p /app/uploads /app/output && \
    chown -R cryptocheck:cryptocheck /app

# Utiliser l'utilisateur non-root
USER cryptocheck

# Variables d'environnement
ENV JAVA_OPTS="-Xmx512m -Xms256m" \
    SERVER_PORT=8080

# Exposer le port
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget -q --spider http://localhost:8080/actuator/health || exit 1

# Démarrer l'application
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
