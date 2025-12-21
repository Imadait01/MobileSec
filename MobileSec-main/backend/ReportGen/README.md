# ReportGen - Microservice de Génération de Rapports de Sécurité

[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Express](https://img.shields.io/badge/Express-4.18+-lightgrey.svg)](https://expressjs.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ReportGen est un microservice Node.js/TypeScript qui agrège les résultats de plusieurs outils d'analyse de sécurité (SAST, SCA, DAST, détection de secrets) et génère des rapports professionnels dans différents formats.

## 🎯 Fonctionnalités

- **Agrégation multi-sources** : Supporte SonarQube, Snyk, TruffleHog, OWASP ZAP, et plus
- **Déduplication intelligente** : Fusionne les vulnérabilités détectées par plusieurs outils
- **Calcul de métriques** : Score de sécurité, répartition par sévérité, fichiers les plus affectés
- **Multi-format** : Export PDF, JSON, et SARIF 2.1.0
- **PDF professionnel** : Graphiques, page de garde, recommandations prioritaires

## 📋 Prérequis

- Node.js 18+
- npm ou yarn
- Chrome/Chromium (pour la génération PDF)

## 🚀 Installation

```bash
# Cloner le repository
git clone https://github.com/your-org/reportgen.git
cd reportgen

# Installer les dépendances
npm install

# Copier le fichier de configuration
cp .env.example .env

# Compiler le TypeScript
npm run build

# Démarrer le service
npm start
```

### Mode développement

```bash
npm run dev
```

## 🐳 Docker

```bash
# Build de l'image
docker build -t reportgen .

# Démarrer avec docker-compose
docker-compose up -d
```

## 📡 API Endpoints

### Health Check

```http
GET /health
```

Réponse :
```json
{
  "status": "healthy",
  "service": "ReportGen",
  "version": "1.0.0"
}
```

### Générer un rapport

```http
POST /api/reports/generate
Content-Type: application/json
```

#### Exemple de requête complète

```json
{
  "projectName": "mon-application-web",
  "scanResults": {
    "sast": [
      {
        "tool": "SonarQube",
        "findings": [
          {
            "key": "AXY123",
            "rule": "java:S2077",
            "severity": "BLOCKER",
            "message": "SQL injection vulnerability",
            "component": "src/main/java/UserController.java",
            "line": 45
          }
        ]
      }
    ],
    "sca": [
      {
        "tool": "Snyk",
        "vulnerabilities": [
          {
            "id": "SNYK-JS-LODASH-590103",
            "title": "Prototype Pollution",
            "severity": "high",
            "packageName": "lodash",
            "version": "4.17.15",
            "cvssScore": 7.4
          }
        ]
      }
    ],
    "secrets": [
      {
        "tool": "TruffleHog",
        "findings": [
          {
            "description": "AWS Access Key",
            "file": "config/aws.js",
            "line": 12,
            "detectorType": "AWS",
            "verified": true
          }
        ]
      }
    ],
    "dast": [
      {
        "tool": "OWASP ZAP",
        "findings": [
          {
            "alert": "Cross Site Scripting (Reflected)",
            "risk": "High",
            "confidence": "Medium",
            "description": "Cross-site Scripting (XSS) is an attack...",
            "uri": "https://example.com/search?q=test",
            "cweid": 79,
            "solution": "Phase: Architecture and Design..."
          }
        ]
      }
    ]
  },
  "format": "pdf",
  "options": {
    "includeSummary": true,
    "includeRecommendations": true,
    "template": "softwareX",
    "companyName": "Ma Société"
  }
}
```

#### Réponse

```json
{
  "reportId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "message": "Report generation started"
}
```

### Récupérer les informations d'un rapport

```http
GET /api/reports/{reportId}
```

### Télécharger un rapport

```http
GET /api/reports/{reportId}/download
```

### Lister les vulnérabilités

```http
GET /api/reports/{reportId}/vulnerabilities?severity=high&page=1&limit=20
```

### Supprimer un rapport

```http
DELETE /api/reports/{reportId}
```

### Lister tous les rapports

```http
GET /api/reports
```

## 📊 Formats supportés

### PDF

Rapport professionnel avec :
- Page de garde
- Résumé exécutif avec score de sécurité
- Graphiques (camembert des sévérités, barres des catégories)
- Liste détaillée des vulnérabilités
- Recommandations prioritaires

### JSON

Structure complète exploitable par d'autres systèmes :
```json
{
  "$schema": "https://reportgen.security/schemas/report-v1.json",
  "version": "1.0.0",
  "reportId": "...",
  "projectName": "...",
  "metrics": { ... },
  "vulnerabilities": [ ... ],
  "statistics": { ... }
}
```

### SARIF 2.1.0

Compatible avec GitHub Code Scanning et Azure DevOps :
```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": { "driver": { ... } },
      "results": [ ... ]
    }
  ]
}
```

## ⚙️ Configuration

| Variable | Description | Défaut |
|----------|-------------|--------|
| `PORT` | Port du serveur | `3005` |
| `NODE_ENV` | Environnement | `development` |
| `TEMP_DIR` | Dossier temporaire | `./tmp` |
| `REPORT_RETENTION_HOURS` | Durée de rétention des rapports | `24` |
| `MAX_PAYLOAD_SIZE` | Taille max des requêtes | `50mb` |
| `LOG_LEVEL` | Niveau de log | `info` |
| `PDF_TIMEOUT_SECONDS` | Timeout génération PDF | `60` |
| `RATE_LIMIT_MAX` | Max requêtes par fenêtre | `10` |
| `RATE_LIMIT_WINDOW_MS` | Fenêtre de rate limiting | `60000` |

## 🏗️ Architecture

```
src/
├── app.ts                      # Point d'entrée Express
├── controllers/
│   └── report.controller.ts    # Logique de contrôle
├── services/
│   ├── aggregator.service.ts   # Normalisation des données
│   ├── deduplicator.service.ts # Déduplication
│   ├── metrics.service.ts      # Calcul des métriques
│   ├── pdf-generator.service.ts# Génération PDF
│   ├── json-exporter.service.ts# Export JSON
│   └── sarif-exporter.service.ts# Export SARIF
├── models/
│   ├── vulnerability.model.ts  # Types vulnérabilité
│   └── report.model.ts         # Types rapport
├── routes/
│   └── report.routes.ts        # Routes API
├── middlewares/
│   ├── error.middleware.ts     # Gestion d'erreurs
│   └── logger.middleware.ts    # Logging
├── templates/
│   └── softwareX.html          # Template PDF
└── utils/
    └── logger.ts               # Configuration Winston
```

## 🔧 Outils supportés

### SAST
- SonarQube
- Semgrep
- CodeQL
- Checkmarx (générique)

### SCA
- Snyk
- npm audit
- OWASP Dependency Check
- WhiteSource

### Secrets
- TruffleHog
- GitLeaks
- detect-secrets

### DAST
- OWASP ZAP
- Burp Suite (export JSON)
- Nuclei

## 📈 Calcul du score de sécurité

Le score de sécurité (0-100) est calculé selon la formule :

| Sévérité | Points de pénalité |
|----------|-------------------|
| Critical | 25 |
| High | 15 |
| Medium | 8 |
| Low | 3 |
| Info | 1 |

Le score diminue avec le nombre et la gravité des vulnérabilités. Des plafonds sont appliqués :
- ≥5 critiques : score max 30
- ≥10 high : score max 50
- Présence de critiques : score max 60

## 🧪 Exemples d'utilisation

### Avec curl

```bash
# Générer un rapport PDF
curl -X POST http://localhost:3005/api/reports/generate \
  -H "Content-Type: application/json" \
  -d @scan-results.json

# Vérifier le statut
curl http://localhost:3005/api/reports/{reportId}

# Télécharger le rapport
curl -O http://localhost:3005/api/reports/{reportId}/download
```

### Intégration CI/CD

```yaml
# GitLab CI
generate-security-report:
  stage: report
  script:
    - |
      REPORT_ID=$(curl -s -X POST $REPORTGEN_URL/api/reports/generate \
        -H "Content-Type: application/json" \
        -d '{"projectName":"'$CI_PROJECT_NAME'","scanResults":'"$(cat scan-results.json)"',"format":"sarif"}' \
        | jq -r '.reportId')
      
      # Attendre la génération
      sleep 10
      
      # Télécharger le rapport SARIF
      curl -o report.sarif $REPORTGEN_URL/api/reports/$REPORT_ID/download
  artifacts:
    reports:
      sast: report.sarif
```

## 📝 Licence

MIT License - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🤝 Contribution

Les contributions sont les bienvenues ! Veuillez consulter le fichier [CONTRIBUTING.md](CONTRIBUTING.md) pour les directives.
