# 🛡️ Mobile Security Scanning Platform

A comprehensive microservices-based security platform for analyzing Android APK files. Powered by AI and Machine Learning to detect vulnerabilities and provide intelligent fix suggestions.

---

## 🎯 Features

### Core Security Scanning
- **📱 APK Analysis** - Deep static analysis of Android applications
- **🔐 Cryptographic Checks** - Detects weak encryption, insecure algorithms, and crypto misuse
- **🔑 Secret Detection** - Finds exposed API keys, passwords, and sensitive credentials
- **🌐 Network Analysis** - Identifies insecure connections, SSL/TLS issues, and data leaks

### AI-Powered Intelligence
- **🤖 LightGBM ML Model** - Prioritizes vulnerabilities by criticality with confidence scores
- **✨ AI Fix Suggestions** - Generates detailed, actionable remediation steps via OpenRouter API
- **📊 Smart Ranking** - Automatically ranks vulnerabilities from most to least critical
- **💡 Code Patches** - Provides complete Java/Kotlin code fixes with proper imports

### Reporting & Visualization
- **📄 PDF Reports** - Professional, branded security reports with executive summaries
- **📈 Dashboard** - Real-time statistics and vulnerability breakdowns
- **🎨 Interactive UI** - Modern React-based frontend with dark mode
- **🔍 Detailed Findings** - Drill down into each vulnerability with file/line references

---

## 🏗️ Architecture

### Microservices
```
┌─────────────┐
│ CI-CONNECTOR│ (Port 3000) - Orchestrator & API Gateway
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ APK-SCANNER │ (Port 5000) - Decompiles & extracts APK resources
└──────┬──────┘
       │
   ┌───┴────┬────────────┬────────────┐
   ▼        ▼            ▼            ▼
┌──────┐ ┌──────┐ ┌──────────┐ ┌──────────┐
│CRYPTO│ │SECRET│ │ NETWORK  │ │ ML-MODEL │
│CHECK │ │HUNTER│ │INSPECTOR │ │(LightGBM)│
└──┬───┘ └──┬───┘ └────┬─────┘ └────┬─────┘
   │        │          │            │
   └────────┴──────────┴────────────┘
                  │
                  ▼
         ┌────────────────┐
         │   REPORTGEN    │ (Port 3005) - PDF generation
         └────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │   FIXSUGGEST   │ (Port 8000) - AI suggestions
         └────────────────┘
```

### Technology Stack
- **Backend**: Node.js, Python (FastAPI, Flask), Java (Spring Boot)
- **Frontend**: React, Vite
- **ML**: LightGBM, scikit-learn
- **AI**: OpenRouter API (Llama 3.2, Gemini, Amazon Nova)
- **Database**: MongoDB
- **Message Queue**: Apache Kafka
- **Containerization**: Docker, Docker Compose

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for frontend development)
- 8GB+ RAM
- OpenRouter API key (for AI suggestions)

### 1. Clone the Repository
```bash
git clone https://github.com/Imadait01/MobileSec.git
cd MobileSec
```

### 2. Configure Environment Variables
```bash
# Backend configuration
cd backend
cp .env.example .env

# Edit .env and add your OpenRouter API key:
# OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### 3. Start All Services
```bash
# Start backend microservices
cd backend
docker-compose up -d

# Start frontend (in a new terminal)
cd ../frontend
npm install
npm start
```

### 4. Access the Platform
- **Frontend**: http://localhost:3006
- **API Gateway**: http://localhost:3000
- **FixSuggest API**: http://localhost:8000/docs
- **ML Model API**: http://localhost:8001/docs
- **MongoDB Express**: http://localhost:8081

---

## 📖 Usage

### Scanning an APK

1. **Upload APK**
   - Navigate to http://localhost:3006
   - Click "Upload APK" or drag & drop your `.apk` file
   - Wait for analysis to complete (~2-5 minutes)

2. **View Results**
   - Navigate to "Scans" to see all completed scans
   - Click "View Details" to see vulnerability breakdown
   - Each scan shows:
     - Total vulnerabilities by category
     - Severity distribution
     - Security score

3. **Get AI Fix Suggestions**
   - Click "AI Suggestions" on a scan
   - View ML-prioritized vulnerabilities (top 10 critical)
   - Each suggestion includes:
     - **ML Confidence Score** (LightGBM)
     - **Detailed Analysis** (what's wrong and why)
     - **Step-by-step Fix** (how to remediate)
     - **Code Patches** (complete working code)

4. **Generate PDF Report**
   - Click "Download PDF" from scan details
   - Get professional security report with all findings

---

## 🔧 Configuration

### OpenRouter API Setup

The platform supports multiple AI models through OpenRouter:

**Free Models:**
- `meta-llama/llama-3.2-3b-instruct:free`
- `mistralai/mistral-7b-instruct:free`

**Paid Models (better quality):**
- `google/gemini-pro-1.5` (~$0.02/scan)
- `amazon/nova-lite-v1` (~$0.01/scan)

To configure:
```yaml
# backend/docker-compose.yml
services:
  fixsuggest:
    environment:
      - OPENROUTER_API_KEY=sk-or-v1-your-key-here
      - OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free
```

Get your API key at: https://openrouter.ai/

### Adjusting ML Suggestions Count

To change the number of AI-generated suggestions (default: 10):

```javascript
// frontend/src/pages/FixSuggestions.jsx (line ~46)
const response = await fixSuggestService.getMLPrioritizedSuggestions(scanId, 20); // Change 10 to 20
```

---

## 🧪 Development

### Running Tests
```bash
# Backend tests
cd backend/ReportGen
npm test

# Frontend tests
cd frontend
npm test
```

### Building for Production
```bash
# Frontend production build
cd frontend
npm run build

# Docker production images
cd backend
docker-compose -f docker-compose.prod.yml up -d
```

### Debugging
```bash
# View service logs
docker logs fixsuggest --tail 100 --follow
docker logs ml-model --tail 100 --follow

# Access MongoDB
docker exec -it mongodb mongosh -u admin -p securityplatform2024

# Restart a service
docker-compose restart fixsuggest
```

---

## 📊 API Documentation

### FixSuggest API
- **Swagger UI**: http://localhost:8000/docs
- **Endpoints**:
  - `POST /api/v1/suggest/ml-priority` - ML-prioritized suggestions
  - `GET /api/v1/suggest/scan/{scan_id}` - All suggestions for scan
  - `GET /health` - Health check

### ML Model API
- **Swagger UI**: http://localhost:8001/docs
- **Endpoints**:
  - `POST /api/v1/prioritize` - Prioritize vulnerabilities
  - `POST /api/v1/predict/{scan_id}` - Predict fix categories
  - `GET /health` - Health check

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License.

---

## 🙏 Acknowledgments

- **OWASP MASVS** - Mobile Application Security Verification Standard
- **OpenRouter** - Unified API for LLM access
- **LightGBM** - Gradient boosting framework
- **Google Gemini** - AI language model





https://github.com/user-attachments/assets/9141fc02-2b81-488a-a930-d743aa27b95a




