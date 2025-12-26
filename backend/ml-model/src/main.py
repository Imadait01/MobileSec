"""
FastAPI Application for ML Model Service
"""

import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .api.routes import router
from .model.predictor import predictor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events
    """
    # Startup: Load model
    logger.info("Starting ML Model Service...")
    try:
        predictor.load_model()
        logger.info("✅ Model loaded successfully")
    except Exception as e:
        logger.error(f"❌ Failed to load model: {e}")
        logger.warning("Service will start but predictions will fail until model is loaded")
    
    yield
    
    # Shutdown
    logger.info("Shutting down ML Model Service...")
    if predictor.data_extractor.client:
        predictor.data_extractor.disconnect()
    logger.info("✅ Service shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="ML Model Service",
    description="Machine Learning service for security fix suggestions",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api/v1", tags=["predictions"])


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "ML Model Service",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "predict_by_scan": "/api/v1/predict/{scan_id}",
            "predict_by_features": "/api/v1/predict",
            "model_info": "/api/v1/model/info",
            "health": "/api/v1/health"
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint (top-level)"""
    return {
        "status": "healthy",
        "service": "ml-model"
    }


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8001))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_level="info"
    )
