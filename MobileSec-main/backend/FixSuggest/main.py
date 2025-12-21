"""
FixSuggest - Microservice de suggestion de corrections pour vulnérabilités
Utilise Amazon Nova 2 Lite via OpenRouter comme LLM
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from routes import suggest_router
from models import HealthResponse
from services import get_suggestion_generator

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestion du cycle de vie de l'application.
    Initialise les services au démarrage et les nettoie à l'arrêt.
    """
    # Startup
    logger.info("🚀 Démarrage de FixSuggest...")
    logger.info(f"🤖 Model: {settings.openrouter_model}")
    logger.info(f"🔗 OpenRouter API: {settings.openrouter_base_url}")
    
    # Initialiser le générateur de suggestions
    try:
        generator = get_suggestion_generator()
        rules_count = len(generator.rule_engine.rules)
        logger.info(f"✅ {rules_count} règles MASVS chargées")
    except Exception as e:
        logger.error(f"❌ Erreur lors du chargement des règles: {e}")
    
    # Start Kafka Consumer
    from consumer import start_consumer
    await start_consumer()
    
    yield
    
    # Shutdown
    logger.info("🛑 Arrêt de FixSuggest...")


# Création de l'application FastAPI
app = FastAPI(
    title="FixSuggest API",
    description="""
## 🔧 Service de Suggestion de Corrections pour Vulnérabilités

FixSuggest analyse les vulnérabilités détectées par les autres microservices 
(CryptoCheck, SecretHunter, Network Inspector, APK Scanner) et propose 
des corrections intelligentes.

### Fonctionnalités principales:
- 📋 **Matching MASVS**: Association des vulnérabilités aux règles OWASP MASVS
- 🤖 **Enrichissement IA**: Utilisation d'Amazon Nova 2 Lite via AWS Bedrock
- 💡 **Suggestions de patch**: Génération de code de correction
- 📊 **Score de confiance**: Évaluation de la pertinence des suggestions

### Workflow:
1. Recevoir une liste de vulnérabilités
2. Associer chaque vulnérabilité à une règle MASVS
3. Enrichir avec Amazon Nova 2 Lite pour générer des explications
4. Proposer des patches de code personnalisés

### Catégories MASVS supportées:
- **CRYPTO**: Cryptographie (MD5, SHA1, AES-ECB, clés faibles...)
- **NETWORK**: Sécurité réseau (SSL/TLS, certificate pinning...)
- **STORAGE**: Stockage des données (SharedPreferences, SQLite...)
- **AUTH**: Authentification et session
- **CODE**: Qualité du code et protection

""",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, spécifier les origines autorisées
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclusion des routes
app.include_router(suggest_router, prefix="/api/v1")


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Vérification de l'état du service"
)
async def health_check() -> HealthResponse:
    """
    Vérifie que le service est opérationnel.
    
    Returns:
        HealthResponse avec le statut et les informations du service
    """
    try:
        generator = get_suggestion_generator()
        rules_count = len(generator.rule_engine.rules)
        llm_configured = generator.nova_client.is_configured
        
        return HealthResponse(
            status="healthy",
            service="FixSuggest",
            version="1.0.0",
            model=settings.openrouter_model,
            llm_configured=llm_configured,
            rules_loaded=rules_count
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthResponse(
            status="unhealthy",
            service="FixSuggest",
            version="1.0.0",
            model=settings.openrouter_model,
            llm_configured=False,
            rules_loaded=0
        )


@app.get(
    "/",
    tags=["Root"],
    summary="Page d'accueil"
)
async def root():
    """
    Page d'accueil avec informations de base.
    """
    return {
        "service": "FixSuggest",
        "version": "1.0.0",
        "description": "Service de suggestion de corrections pour vulnérabilités",
        "docs": "/docs",
        "health": "/health",
        "api": {
            "suggest": "/api/v1/suggest",
            "single": "/api/v1/suggest/single",
            "categories": "/api/v1/suggest/categories"
        }
    }


@app.get(
    "/api/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Vérification de l'état du service (Alias)"
)
async def api_health_check() -> HealthResponse:
    """Alias for health check compatible with Gateway"""
    return await health_check()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
