"""
Model Predictor for Real-time Inference
Loads trained LightGBM model and provides fix suggestions
"""

import os
import logging
import joblib
import numpy as np
import lightgbm as lgb
from typing import Dict, List, Optional

from .model_config import (
    MODEL_PATH, LABEL_ENCODER_PATH, FEATURE_SCALER_PATH,
    FEATURE_COLUMNS, FIX_SUGGESTION_TEMPLATES
)
from ..data.data_extractor import DataExtractor

logger = logging.getLogger(__name__)


class ModelPredictor:
    """Inference engine for security fix suggestions"""
    
    def __init__(self):
        self.model = None
        self.label_encoder = None
        self.feature_scaler = None
        self.data_extractor = DataExtractor()
        self.is_loaded = False
        
    def load_model(self):
        """Load trained model and preprocessors"""
        try:
            # Load LightGBM model
            if not os.path.exists(MODEL_PATH):
                raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
            self.model = lgb.Booster(model_file=MODEL_PATH)
            logger.info(f"✅ Loaded model from {MODEL_PATH}")
            
            # Load label encoder
            if not os.path.exists(LABEL_ENCODER_PATH):
                raise FileNotFoundError(f"Label encoder not found: {LABEL_ENCODER_PATH}")
            self.label_encoder = joblib.load(LABEL_ENCODER_PATH)
            logger.info(f"✅ Loaded label encoder ({len(self.label_encoder.classes_)} classes)")
            
            # Load feature scaler
            if not os.path.exists(FEATURE_SCALER_PATH):
                raise FileNotFoundError(f"Feature scaler not found: {FEATURE_SCALER_PATH}")
            self.feature_scaler = joblib.load(FEATURE_SCALER_PATH)
            logger.info(f"✅ Loaded feature scaler")
            
            self.is_loaded = True
            logger.info("Model ready for predictions")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def predict_from_scan_id(self, scan_id: str, top_k: int = 3) -> Dict:
        """
        Generate fix suggestions for a scan_id
        
        Args:
            scan_id: Scan ID from MongoDB
            top_k: Number of top suggestions to return
            
        Returns:
            Dictionary with predictions and suggestions
        """
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        logger.info(f"Generating predictions for scan_id: {scan_id}")
        
        # Connect to MongoDB and extract features
        if not self.data_extractor.client.is_connected():
            self.data_extractor.connect()
        
        # Extract features
        features_dict = self.data_extractor._extract_scan_features(scan_id)
        if not features_dict:
            raise ValueError(f"No data found for scan_id: {scan_id}")
        
        # Prepare features
        features = []
        for col in FEATURE_COLUMNS:
            features.append(features_dict.get(col, 0))
        
        X = np.array(features).reshape(1, -1)
        X_scaled = self.feature_scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)[0]  # Shape: (num_classes,)
        
        # Get top-k predictions
        top_indices = np.argsort(predictions)[::-1][:top_k]
        top_classes = [self.label_encoder.classes_[idx] for idx in top_indices]
        top_probabilities = [predictions[idx] for idx in top_indices]
        
        # Generate suggestions
        suggestions = []
        for i, (fix_class, prob) in enumerate(zip(top_classes, top_probabilities)):
            template = FIX_SUGGESTION_TEMPLATES.get(fix_class, FIX_SUGGESTION_TEMPLATES['GENERAL'])
            
            suggestion = {
                'rank': i + 1,
                'category': fix_class,
                'confidence': float(prob),
                'title': template['title'],
                'description': template['description'],
                'priority': template['priority'],
                'code_example': template['code_example']
            }
            suggestions.append(suggestion)
        
        result = {
            'scan_id': scan_id,
            'primary_fix': top_classes[0],
            'confidence': float(top_probabilities[0]),
            'suggestions': suggestions,
            'vulnerability_summary': {
                'crypto': features_dict.get('crypto_total_vulns', 0),
                'secrets': features_dict.get('secrets_count', 0),
                'network': features_dict.get('network_findings', 0),
                'total': features_dict.get('total_vulnerabilities', 0),
                'severity_score': features_dict.get('severity_score', 0)
            }
        }
        
        logger.info(f"Generated {len(suggestions)} suggestions for scan_id: {scan_id}")
        return result
    
    def predict_from_features(self, features: Dict, top_k: int = 3) -> Dict:
        """
        Generate fix suggestions from raw features
        
        Args:
            features: Dictionary of feature values
            top_k: Number of top suggestions to return
            
        Returns:
            Dictionary with predictions and suggestions
        """
        if not self.is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        # Prepare features
        feature_values = []
        for col in FEATURE_COLUMNS:
            feature_values.append(features.get(col, 0))
        
        X = np.array(feature_values).reshape(1, -1)
        X_scaled = self.feature_scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)[0]
        
        # Get top-k predictions
        top_indices = np.argsort(predictions)[::-1][:top_k]
        top_classes = [self.label_encoder.classes_[idx] for idx in top_indices]
        top_probabilities = [predictions[idx] for idx in top_indices]
        
        # Generate suggestions
        suggestions = []
        for i, (fix_class, prob) in enumerate(zip(top_classes, top_probabilities)):
            template = FIX_SUGGESTION_TEMPLATES.get(fix_class, FIX_SUGGESTION_TEMPLATES['GENERAL'])
            
            suggestion = {
                'rank': i + 1,
                'category': fix_class,
                'confidence': float(prob),
                'title': template['title'],
                'description': template['description'],
                'priority': template['priority'],
                'code_example': template['code_example']
            }
            suggestions.append(suggestion)
        
        return {
            'primary_fix': top_classes[0],
            'confidence': float(top_probabilities[0]),
            'suggestions': suggestions
        }
    
    def get_model_info(self) -> Dict:
        """Get model metadata"""
        if not self.is_loaded:
            raise RuntimeError("Model not loaded")
        
        return {
            'model_type': 'LightGBM',
            'num_classes': len(self.label_encoder.classes_),
            'classes': self.label_encoder.classes_.tolist(),
            'num_features': len(FEATURE_COLUMNS),
            'features': FEATURE_COLUMNS,
            'model_path': MODEL_PATH
        }


# Singleton instance
predictor = ModelPredictor()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Load model
    predictor.load_model()
    
    # Test prediction (replace with actual scan_id)
    try:
        result = predictor.predict_from_scan_id("test_scan_id", top_k=3)
        print("Prediction result:")
        print(result)
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
