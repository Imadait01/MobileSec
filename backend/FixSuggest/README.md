# FixSuggest 🔧

Service de suggestion de corrections pour vulnérabilités utilisant **Amazon Nova 2 Lite via AWS Bedrock**.

## 📋 Description

FixSuggest analyse les vulnérabilités détectées par les autres microservices (CryptoCheck, SecretHunter, Network Inspector, APK Scanner) et propose des corrections intelligentes basées sur:

- **Règles MASVS** (Mobile Application Security Verification Standard)
- **Intelligence Artificielle** via Amazon Nova 2 Lite
- **Patches de code** personnalisés

## 🏗️ Architecture

```
FixSuggest/
├── main.py                 # Point d'entrée FastAPI
├── config/
│   ├── __init__.py
│   └── settings.py         # Configuration AWS/Bedrock
├── models/
│   ├── __init__.py
│   └── vulnerability.py    # Modèles Pydantic
├── routes/
│   ├── __init__.py
│   └── suggest.py          # Endpoints API
├── services/
│   ├── __init__.py
│   ├── rule_engine.py      # Moteur de règles MASVS
│   ├── llm_suggester.py    # Client Amazon Nova 2 Lite
│   └── generator.py        # Générateur de suggestions
├── rules/
│   └── masvs/
│       ├── crypto.yaml     # Règles cryptographie
│       ├── network.yaml    # Règles réseau
│       ├── storage.yaml    # Règles stockage
│       ├── auth.yaml       # Règles authentification
│       └── code.yaml       # Règles qualité code
├── requirements.txt
├── Dockerfile
└── README.md
```

## 🚀 Installation

### Prérequis

- Python 3.10+
- Compte AWS avec accès à Bedrock
- Amazon Nova 2 Lite activé dans votre région

### Configuration AWS

1. **Créer un utilisateur IAM** avec les permissions Bedrock:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            "Resource": "arn:aws:bedrock:*::foundation-model/amazon.nova-lite-v1:0"
        }
    ]
}
```

2. **Configurer les variables d'environnement**:

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=us-east-1
```

### Installation locale

```bash
cd FixSuggest

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/macOS
# ou
.\venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt

# Lancer le serveur
python main.py
```

### Installation Docker

```bash
# Build
docker build -t fixsuggest:latest .

# Run
docker run -p 8000:8000 \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  -e AWS_REGION=us-east-1 \
  fixsuggest:latest
```

## 📡 API Endpoints

### Health Check

```bash
GET /health
```

Réponse:
```json
{
    "status": "healthy",
    "service": "FixSuggest",
    "version": "1.0.0",
    "model": "amazon.nova-lite-v1:0",
    "rules_loaded": 27
}
```

### Générer des suggestions

```bash
POST /api/v1/suggest
Content-Type: application/json

{
    "vulnerabilities": [
        {
            "id": "VULN-001",
            "type": "weak_hash",
            "severity": "HIGH",
            "title": "Utilisation de MD5",
            "description": "MD5 est un algorithme de hachage obsolète",
            "file": "crypto/hash.java",
            "line": 42,
            "code_snippet": "MessageDigest.getInstance(\"MD5\")"
        }
    ]
}
```

Réponse:
```json
{
    "suggestions": [
        {
            "vulnerability_id": "VULN-001",
            "masvs_category": "MSTG-CRYPTO-1",
            "masvs_title": "Utilisation de cryptographie obsolète - MD5",
            "explanation": "MD5 est un algorithme de hachage cryptographiquement cassé...",
            "suggested_patch": "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");",
            "confidence": 0.95,
            "references": ["https://owasp.org/..."]
        }
    ],
    "total_processed": 1,
    "total_suggestions": 1
}
```

### Suggestion pour une vulnérabilité

```bash
POST /api/v1/suggest/single
Content-Type: application/json

{
    "id": "VULN-001",
    "type": "weak_hash",
    "severity": "HIGH",
    "title": "Utilisation de MD5",
    "description": "MD5 détecté",
    "file": "utils.java",
    "line": 15
}
```

### Lister les catégories MASVS

```bash
GET /api/v1/suggest/categories
```

Réponse:
```json
{
    "categories": {
        "MSTG-CRYPTO-1": 2,
        "MSTG-CRYPTO-2": 2,
        "MSTG-NETWORK-1": 3,
        "MSTG-STORAGE-1": 4
    },
    "total_rules": 27
}
```

## 🔧 Configuration

| Variable | Description | Défaut |
|----------|-------------|--------|
| `AWS_ACCESS_KEY_ID` | Clé d'accès AWS | - |
| `AWS_SECRET_ACCESS_KEY` | Clé secrète AWS | - |
| `AWS_REGION` | Région AWS | `us-east-1` |
| `BEDROCK_MODEL_ID` | ID du modèle Bedrock | `amazon.nova-lite-v1:0` |
| `HOST` | Host du serveur | `0.0.0.0` |
| `PORT` | Port du serveur | `8000` |
| `DEBUG` | Mode debug | `false` |
| `RULES_PATH` | Chemin des règles MASVS | `rules/masvs` |

## 📚 Catégories MASVS supportées

| Catégorie | Description | Exemples |
|-----------|-------------|----------|
| **CRYPTO** | Cryptographie | MD5, SHA1, AES-ECB, clés faibles |
| **NETWORK** | Réseau | HTTP, SSL/TLS, certificate pinning |
| **STORAGE** | Stockage | SharedPreferences, SQLite, logs |
| **AUTH** | Authentification | Tokens, sessions, biométrie |
| **CODE** | Code | Injection SQL, debug, composants exportés |

## 🧪 Tests

```bash
# Installer les dépendances de test
pip install pytest pytest-asyncio httpx

# Lancer les tests
pytest tests/ -v
```

## 📖 Documentation Swagger

Une fois le serveur lancé, accédez à:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## 🔗 Intégration avec les autres microservices

FixSuggest peut recevoir des vulnérabilités depuis:

- **CryptoCheck** (port 8080) - Vulnérabilités cryptographiques
- **SecretHunter** (port 8001) - Secrets exposés
- **Network Inspector** (port 8002) - Problèmes réseau
- **APK Scanner** (port 8003) - Analyse APK

Exemple d'intégration avec ReportGen:

```javascript
// Dans ReportGen
const vulnerabilities = await getCryptoCheckFindings();
const suggestions = await fetch('http://fixsuggest:8000/api/v1/suggest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vulnerabilities })
});
```

## 📝 Licence

MIT License

## 👥 Contributeurs

- Équipe Microservices Security Platform
