"""
Test script to verify ML model service
"""

import os
import sys
sys.path.insert(0, os.path.abspath('src'))

import logging
from data.data_extractor import DataExtractor
from model.trainer import train_model
from model.predictor import predictor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    print("="*70)
    print("ML MODEL SERVICE - END-TO-END TEST")
    print("="*70)
    
    # Step 1: Extract Data
    print("\n[1/4] Extracting data from MongoDB...")
    extractor = DataExtractor()
    
    # Update MongoDB URI for localhost  testing
    os.environ['MONGODB_URI'] = 'mongodb://admin:securityplatform2024@localhost:27017/security_platform?authSource=admin'
    
    try:
        if not extractor.connect():
            print("❌ Failed to connect to MongoDB")
            print("Make sure MongoDB is running: docker ps | grep mongodb")
            return
        
        # Get statistics
        stats = extractor.get_statistics()
        print(f"✅ Connected to MongoDB")
        print(f"   Total scans: {stats.get('total_scans', 0)}")
        print(f"   Crypto results: {stats.get('crypto_results_count', 0)}")
        print(f"   Secret results: {stats.get('secret_results_count', 0)}")
        print(f"   Network results: {stats.get('network_results_count', 0)}")
        
        # Extract data
        df = extractor.extract_all_data(limit=None)
        print(f"✅ Extracted {len(df)} scans with {len(df.columns)} features")
        
        # Save dataset
        os.makedirs('data', exist_ok=True)
        dataset_path = 'data/security_scan_dataset.csv'
        df.to_csv(dataset_path, index=False)
        print(f"✅ Dataset saved to {dataset_path}")
        
    finally:
        extractor.disconnect()
    
    # Step 2: Train Model
    print("\n[2/4] Training ML model...")
    
    if len(df) < 10:
        print(f"⚠️  Warning: Only {len(df)} samples available. Need more data for robust training.")
        print("   Consider uploading more APK scans to generate training data.")
    
    try:
        trainer = train_model(dataset_path)
        print("✅ Model training complete")
        print(f"   Model saved to: {trainer.model.save_model.__self__.model_file}")
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return
    
    # Step 3: Load Model and Test Prediction
    print("\n[3/4] Loading model for inference...")
    try:
        predictor.load_model()
        print("✅ Model loaded successfully")
        
        # Get model info
        model_info = predictor.get_model_info()
        print(f"   Model type: {model_info['model_type']}")
        print(f"   Number of classes: {model_info['num_classes']}")
        print(f"   Classes: {', '.join(model_info['classes'][:5])}...")
        
    except Exception as e:
        logger.error(f"Model loading failed: {e}")
        return
    
    # Step 4: Test Prediction
    print("\n[4/4] Testing predictions...")
    
    # Get a sample scan_id
    sample_scan_ids = df['scan_id'].head(3).tolist()
    
    for scan_id in sample_scan_ids:
        try:
            result = predictor.predict_from_scan_id(scan_id, top_k=3)
            print(f"\n📊 Prediction for scan: {scan_id}")
            print(f"   Primary fix: {result['primary_fix']}")
            print(f"   Confidence: {result['confidence']:.2%}")
            print(f"   Vulnerabilities: Crypto={result['vulnerability_summary']['crypto']}, "
                  f"Secrets={result['vulnerability_summary']['secrets']}, "
                  f"Network={result['vulnerability_summary']['network']}")
            print(f"   Top suggestion: {result['suggestions'][0]['title']}")
            
        except Exception as e:
            logger.error(f"Prediction failed for {scan_id}: {e}")
    
    print("\n" + "="*70)
    print("✅ END-TO-END TEST COMPLETE")
    print("="*70)
    print("\nNext steps:")
    print("1. Start the service: python -m src.main")
    print("2. Test API: curl http://localhost:8001/api/v1/predict/{scan_id}")
    print("3. View model info: curl http://localhost:8001/api/v1/model/info")
    print("4. Or run with Docker: docker-compose up -d ml-model")
    print("="*70)


if __name__ == "__main__":
    main()
