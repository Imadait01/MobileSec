"""
Model Trainer for Security Fix Suggestion
Uses LightGBM for multi-class classification
"""

import os
import json
import logging
import joblib
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from typing import Dict, Tuple

from .model_config import (
    LIGHTGBM_PARAMS, TRAINING_CONFIG, FEATURE_COLUMNS, TARGET_COLUMN,
    MODEL_PATH, LABEL_ENCODER_PATH, FEATURE_SCALER_PATH, METRICS_PATH
)

logger = logging.getLogger(__name__)


class ModelTrainer:
    """Train LightGBM model for security fix suggestions"""
    
    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_scaler = StandardScaler()
        self.feature_columns = FEATURE_COLUMNS
        self.target_column = TARGET_COLUMN
        
    def prepare_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Prepare data for training
        
        Returns: X_train, X_val, y_train, y_val
        """
        logger.info("Preparing data for training...")
        
        # Check for required columns
        missing_features = set(self.feature_columns) - set(df.columns)
        if missing_features:
            raise ValueError(f"Missing features in dataset: {missing_features}")
        
        if self.target_column not in df.columns:
            raise ValueError(f"Target column '{self.target_column}' not found in dataset")
        
        # Extract features and target
        X = df[self.feature_columns].values
        y_raw = df[self.target_column].values
        
        # Encode labels
        y = self.label_encoder.fit_transform(y_raw)
        logger.info(f"Encoded {len(self.label_encoder.classes_)} unique classes: {self.label_encoder.classes_}")
        
        # Split data
        test_size = TRAINING_CONFIG['test_size']
        val_size = TRAINING_CONFIG['validation_size']
        random_state = TRAINING_CONFIG['random_state']
        
        # First split: train+val vs test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Second split: train vs val
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=random_state, stratify=y_temp
        )
        
        # Scale features
        X_train = self.feature_scaler.fit_transform(X_train)
        X_val = self.feature_scaler.transform(X_val)
        X_test = self.feature_scaler.transform(X_test)
        
        logger.info(f"Data split: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
        
        # Store test set for final evaluation
        self.X_test = X_test
        self.y_test = y_test
        
        return X_train, X_val, y_train, y_val
    
    def train(self, X_train: np.ndarray, X_val: np.ndarray, 
              y_train: np.ndarray, y_val: np.ndarray) -> Dict:
        """
        Train LightGBM model
        
        Returns: Training metrics
        """
        logger.info("Starting model training...")
        
        # Prepare datasets
        train_data = lgb.Dataset(X_train, label=y_train)
        val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
        
        # Update params with number of classes
        params = LIGHTGBM_PARAMS.copy()
        params['num_class'] = len(self.label_encoder.classes_)
        
        # Train model
        callbacks = [
            lgb.log_evaluation(period=TRAINING_CONFIG['verbose_eval']),
            lgb.early_stopping(stopping_rounds=TRAINING_CONFIG['early_stopping_rounds'])
        ]
        
        self.model = lgb.train(
            params,
            train_data,
            num_boost_round=TRAINING_CONFIG['num_boost_round'],
            valid_sets=[train_data, val_data],
            valid_names=['train', 'val'],
            callbacks=callbacks
        )
        
        logger.info(f"Training complete. Best iteration: {self.model.best_iteration}")
        
        # Evaluate on validation set
        y_val_pred = self.model.predict(X_val, num_iteration=self.model.best_iteration)
        y_val_pred_class = np.argmax(y_val_pred, axis=1)
        
        val_accuracy = accuracy_score(y_val, y_val_pred_class)
        logger.info(f"Validation accuracy: {val_accuracy:.4f}")
        
        # Generate classification report
        class_names = self.label_encoder.classes_
        report = classification_report(
            y_val, y_val_pred_class,
            target_names=class_names,
            output_dict=True,
            zero_division=0
        )
        
        metrics = {
            'validation_accuracy': val_accuracy,
            'best_iteration': self.model.best_iteration,
            'num_classes': len(class_names),
            'class_names': class_names.tolist(),
            'classification_report': report
        }
        
        return metrics
    
    def evaluate(self) -> Dict:
        """Evaluate model on test set"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        logger.info("Evaluating model on test set...")
        
        y_test_pred = self.model.predict(self.X_test, num_iteration=self.model.best_iteration)
        y_test_pred_class = np.argmax(y_test_pred, axis=1)
        
        test_accuracy = accuracy_score(self.y_test, y_test_pred_class)
        logger.info(f"Test accuracy: {test_accuracy:.4f}")
        
        # Classification report
        class_names = self.label_encoder.classes_
        report = classification_report(
            self.y_test, y_test_pred_class,
            target_names=class_names,
            output_dict=True,
            zero_division=0
        )
        
        # Confusion matrix
        conf_matrix = confusion_matrix(self.y_test, y_test_pred_class)
        
        return {
            'test_accuracy': test_accuracy,
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist()
        }
    
    def get_feature_importance(self) -> pd.DataFrame:
        """Get feature importance from trained model"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        importance = self.model.feature_importance(importance_type='gain')
        feature_importance_df = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': importance
        }).sort_values('importance', ascending=False)
        
        return feature_importance_df
    
    def save(self):
        """Save model and preprocessors"""
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        
        # Save LightGBM model
        self.model.save_model(MODEL_PATH)
        logger.info(f"Model saved to {MODEL_PATH}")
        
        # Save label encoder
        joblib.dump(self.label_encoder, LABEL_ENCODER_PATH)
        logger.info(f"Label encoder saved to {LABEL_ENCODER_PATH}")
        
        # Save feature scaler
        joblib.dump(self.feature_scaler, FEATURE_SCALER_PATH)
        logger.info(f"Feature scaler saved to {FEATURE_SCALER_PATH}")
    
    def save_metrics(self, train_metrics: Dict, test_metrics: Dict):
        """Save training metrics to JSON"""
        metrics = {
            'train_metrics': train_metrics,
            'test_metrics': test_metrics,
            'feature_importance': self.get_feature_importance().to_dict('records')
        }
        
        with open(METRICS_PATH, 'w') as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Metrics saved to {METRICS_PATH}")


def train_model(data_path: str) -> ModelTrainer:
    """
    Main training function
    
    Args:
        data_path: Path to CSV file with extracted features
        
    Returns:
        Trained ModelTrainer instance
    """
    logger.info(f"Loading data from {data_path}")
    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df)} samples")
    
    # Initialize trainer
    trainer = ModelTrainer()
    
    # Prepare data
    X_train, X_val, y_train, y_val = trainer.prepare_data(df)
    
    # Train model
    train_metrics = trainer.train(X_train, X_val, y_train, y_val)
    
    # Evaluate on test set
    test_metrics = trainer.evaluate()
    
    # Print results
    print("\n" + "="*60)
    print("TRAINING RESULTS")
    print("="*60)
    print(f"Validation Accuracy: {train_metrics['validation_accuracy']:.4f}")
    print(f"Test Accuracy: {test_metrics['test_accuracy']:.4f}")
    print(f"Best Iteration: {train_metrics['best_iteration']}")
    print("\nTop 10 Important Features:")
    feature_importance = trainer.get_feature_importance()
    print(feature_importance.head(10).to_string(index=False))
    print("="*60 + "\n")
    
    # Save model and metrics
    trainer.save()
    trainer.save_metrics(train_metrics, test_metrics)
    
    logger.info("Training complete!")
    return trainer


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Train model
    data_path = "data/security_scan_dataset.csv"
    if os.path.exists(data_path):
        trainer = train_model(data_path)
    else:
        logger.error(f"Data file not found: {data_path}")
        logger.info("Run data extraction first or specify correct path")
