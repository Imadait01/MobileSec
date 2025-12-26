"""
FastAPI Routes for ML Model Service
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import logging

from ..model.predictor import predictor

logger = logging.getLogger(__name__)

router = APIRouter()


# Request/Response Models
class PredictionRequest(BaseModel):
    """Request model for manual predictions"""
    features: Dict[str, float] = Field(..., description="Feature dictionary")
    top_k: int = Field(3, ge=1, le=10, description="Number of suggestions to return")


class Suggestion(BaseModel):
    """Individual fix suggestion"""
    rank: int
    category: str
    confidence: float
    title: str
    description: str
    priority: str
    code_example: str


class VulnerabilitySummary(BaseModel):
    """Vulnerability counts summary"""
    crypto: int
    secrets: int
    network: int
    total: int
    severity_score: float


class PredictionResponse(BaseModel):
    """Response model for predictions"""
    scan_id: Optional[str] = None
    primary_fix: str
    confidence: float
    suggestions: List[Suggestion]
    vulnerability_summary: Optional[VulnerabilitySummary] = None


class ModelInfo(BaseModel):
    """Model metadata"""
    model_type: str
    num_classes: int
    classes: List[str]
    num_features: int
    features: List[str]
    model_path: str


# Routes
@router.post("/predict/{scan_id}", response_model=PredictionResponse, status_code=status.HTTP_200_OK)
async def predict_for_scan(scan_id: str, top_k: int = 3):
    """
    Generate fix suggestions for a specific scan
    
    Args:
        scan_id: Scan ID from MongoDB
        top_k: Number of top suggestions to return (default: 3)
        
    Returns:
        Prediction response with fix suggestions
    """
    try:
        if not predictor.is_loaded:
            predictor.load_model()
        
        result = predictor.predict_from_scan_id(scan_id, top_k=top_k)
        return result
    
    except ValueError as e:
        logger.error(f"Scan not found: {scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan ID not found: {scan_id}"
        )
    except Exception as e:
        logger.error(f"Prediction error for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )


@router.post("/predict", response_model=PredictionResponse, status_code=status.HTTP_200_OK)
async def predict_from_features(request: PredictionRequest):
    """
    Generate fix suggestions from raw features
    
    Args:
        request: Feature dictionary and top_k
        
    Returns:
        Prediction response with fix suggestions
    """
    try:
        if not predictor.is_loaded:
            predictor.load_model()
        
        result = predictor.predict_from_features(request.features, top_k=request.top_k)
        return result
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )


@router.get("/model/info", response_model=ModelInfo, status_code=status.HTTP_200_OK)
async def get_model_info():
    """
    Get model metadata
    
    Returns:
        Model information including classes and features
    """
    try:
        if not predictor.is_loaded:
            predictor.load_model()
        
        info = predictor.get_model_info()
        return info
    
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get model info: {str(e)}"
        )


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Health check endpoint
    
    Returns:
        Service health status
    """
    is_ready = predictor.is_loaded
    
    return {
        "status": "healthy" if is_ready else "initializing",
        "model_loaded": is_ready,
        "service": "ml-model"
    }
