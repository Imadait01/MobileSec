# ML Model Service for Security Analysis

## Overview

Machine learning service that analyzes security vulnerabilities from CryptoCheck, SecretHunter, and NetworkInspector services and provides intelligent fix suggestions using LightGBM.

## Features

- **Data Extraction**: Automatically extracts vulnerability data from MongoDB
- **Feature Engineering**: 30+ engineered features from crypto, secrets, and network analysis
- **ML Model**: LightGBM multi-class classifier for fix category prediction
- **Real-time Inference**: API endpoints for generating fix suggestions
- **Hybrid Labeling**: Combines AI suggestions with rule-based classification

## Architecture

```
ml-model/
├── src/
│   ├── main.py                  # FastAPI application
│   ├── data/
│   │   └── data_extractor.py    # MongoDB data extraction
│   ├── model/
│   │   ├── model_config.py      # Model configuration
│   │   ├── trainer.py           # Training pipeline
│   │   └── predictor.py         # Inference engine
│   ├── utils/
│   │   └── mongodb_client.py    # MongoDB client
│   └── api/
│       └── routes.py            # API routes
├── models/                       # Trained model artifacts
├── notebooks/                    # Jupyter notebooks
└── tests/                        # Unit tests
```

## API Endpoints

### Predict by Scan ID
```bash
POST /api/v1/predict/{scan_id}?top_k=3
```

Returns fix suggestions for a specific scan ID from MongoDB.

**Response:**
```json
{
  "scan_id": "abc123",
  "primary_fix": "FIX_WEAK_CIPHER",
  "confidence": 0.89,
  "suggestions": [
    {
      "rank": 1,
      "category": "FIX_WEAK_CIPHER",
      "confidence": 0.89,
      "title":  "Upgrade to Strong Encryption Algorithms",
      "description": "Replace weak ciphers (DES, RC4) with AES-256",
      "priority": "HIGH",
      "code_example": "..."
    }
  ],
  "vulnerability_summary": {
    "crypto": 5,
    "secrets": 2,
    "network": 3,
    "total": 10,
    "severity_score": 28.5
  }
}
```

### Predict from Features
```bash
POST /api/v1/predict
Content-Type: application/json

{
  "features": {
    "crypto_total_vulns": 5,
    "crypto_high": 2,
    "secrets_count": 1,
    "network_findings": 3,
    ...
  },
  "top_k": 3
}
```

### Model Info
```bash
GET /api/v1/model/info
```

Returns model metadata (classes, features, version).

### Health Check
```bash
GET /health
GET /api/v1/health
```

## Training the Model

### 1. Extract Data from MongoDB

```bash
python -m src.data.data_extractor
```

This connects to MongoDB and extracts all scan data into `data/security_scan_dataset.csv`.

### 2. Explore Data (Optional)

```bash
jupyter notebook notebooks/01_data_exploration.ipynb
```

### 3. Train Model

```bash
python -m src.model.trainer
```

This trains the LightGBM model and saves artifacts to `models/`.

**Output:**
- `models/lightgbm_model.txt` - Trained LightGBM model
- `models/label_encoder.pkl` - Label encoder
- `models/feature_scaler.pkl` - Feature scaler
- `models/training_metrics.json` - Training metrics

## Running the Service

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run service
python -m src.main
```

Service runs on http://localhost:8001

### Docker

```bash
# Build image
docker build -t ml-model:latest .

# Run container
docker run -p 8001:8001 \
  -e MONGODB_URI=mongodb://admin:password@mongodb:27017/security_platform \
  ml-model:latest
```

### Docker Compose

The service is integrated into the microservices platform via `docker-compose.yml`.

```bash
cd backend
docker-compose up -d ml-model
```

## Model Performance

The model is evaluated on:
- **Accuracy**: Overall prediction accuracy
- **Precision/Recall/F1**: Per-class metrics
- **Confusion Matrix**: Classification patterns
- **Feature Importance**: Top contributing features

Metrics are saved in `models/training_metrics.json` after training.

## Fix Categories

The model predicts one of the following fix categories:

- `FIX_WEAK_CIPHER` - Weak encryption algorithms
- `FIX_WEAK_HASH` - Weak hashing algorithms  
- `FIX_INSECURE_RANDOM` - Insecure random number generation
- `FIX_WEAK_RSA_KEY` - Weak RSA key sizes
- `FIX_EXPOSED_API_KEY` - Hardcoded API keys
- `FIX_HARDCODED_PASSWORD` - Hardcoded passwords
- `FIX_EXPOSED_SECRET` - Other exposed secrets
- `FIX_INSECURE_HTTP` - HTTP instead of HTTPS
- `FIX_CERTIFICATE_ISSUE` - SSL/TLS certificate issues
- `FIX_CRYPTO_MEDIUM` - Medium severity crypto issues
- `FIX_CRYPTO_GENERAL` - General crypto improvements
- `NO_CRITICAL_ISSUES` - No critical issues found
- `NO_SUGGESTION` - Manual review required

## Environment Variables

- `PORT` - Service port (default: 8001)
- `MONGODB_URI` - MongoDB connection string
- `MONGODB_DATABASE` - Database name (default: security_platform)
- `MODEL_PATH` - Path to trained model (default: models/lightgbm_model.txt)

## Development

### Run Tests

```bash
pytest tests/
```

### Retrain Model

To retrain the model with new data:

1. Ensure new scans are in MongoDB
2. Extract updated dataset: `python -m src.data.data_extractor`
3. Retrain: `python -m src.model.trainer`
4. Restart service to load new model

## Integration with Existing Services

The ML model service integrates with:

- **MongoDB**: Reads vulnerability data from `crypto_results`, `secret_results`, `network_results`
- **FixSuggest**: Can complement or replace AI-based suggestions
- **ReportGen**: Can provide ML-based recommendations in PDF reports

## License

Part of the Security Platform Microservices Architecture
