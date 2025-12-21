"""
MongoDB Client for SecretHunter
Handles all database operations with MongoDB
"""

import os
import logging
from datetime import datetime
from typing import Optional, Dict, List
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure

logger = logging.getLogger(__name__)


class MongoDBClient:
    """MongoDB client singleton for SecretHunter"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.uri = os.getenv('MONGODB_URI', 'mongodb://admin:securityplatform2024@localhost:27017/security_platform?authSource=admin')
        self.db_name = os.getenv('MONGODB_DATABASE', 'security_platform')
        self.input_collection = os.getenv('INPUT_COLLECTION', 'apk_results')
        self.output_collection = os.getenv('OUTPUT_COLLECTION', 'secret_results')
        
        self.client: Optional[MongoClient] = None
        self.db = None
        self._initialized = True
        
    def connect(self) -> bool:
        """Connect to MongoDB"""
        try:
            self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            logger.info(f"✅ Connected to MongoDB: {self.db_name}")
            return True
        except ConnectionFailure as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from MongoDB"""
        if self.client:
            self.client.close()
    
    def is_connected(self) -> bool:
        """Check if connected to MongoDB"""
        try:
            if self.client:
                self.client.admin.command('ping')
                return True
        except Exception:
            pass
        return False
    
    # ==================== INPUT: APK_RESULTS ====================
    
    def get_apk_results(self, scan_id: str) -> Optional[Dict]:
        """Get APK results as input from apk_results collection"""
        try:
            return self.db[self.input_collection].find_one({"scan_id": scan_id})
        except Exception as e:
            logger.error(f"Error getting APK results: {e}")
            return None
    
    # ==================== OUTPUT: SECRET_RESULTS ====================
    
    def save_secret_results(self, scan_id: str, secrets: List[Dict], summary: Dict) -> str:
        """Save secret detection results"""
        try:
            # Limit number of secrets to prevent MongoDB document size limit (16MB)
            MAX_SECRETS = 1000
            MAX_MATCH_LENGTH = 500  # Truncate long matches
            
            # Truncate and limit secrets
            limited_secrets = []
            for secret in secrets[:MAX_SECRETS]:
                truncated_secret = secret.copy()
                # Truncate long match strings
                if 'match' in truncated_secret and len(str(truncated_secret.get('match', ''))) > MAX_MATCH_LENGTH:
                    truncated_secret['match'] = str(truncated_secret['match'])[:MAX_MATCH_LENGTH] + '...[truncated]'
                if 'context' in truncated_secret and len(str(truncated_secret.get('context', ''))) > MAX_MATCH_LENGTH:
                    truncated_secret['context'] = str(truncated_secret['context'])[:MAX_MATCH_LENGTH] + '...[truncated]'
                if 'line' in truncated_secret and len(str(truncated_secret.get('line', ''))) > MAX_MATCH_LENGTH:
                    truncated_secret['line'] = str(truncated_secret['line'])[:MAX_MATCH_LENGTH] + '...[truncated]'
                limited_secrets.append(truncated_secret)
            
            # Update summary with truncation info
            if len(secrets) > MAX_SECRETS:
                summary['truncated'] = True
                summary['total_before_truncation'] = len(secrets)
                logger.warning(f"Truncated secrets from {len(secrets)} to {MAX_SECRETS}")
            
            document = {
                "scan_id": scan_id,
                "status": "completed",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "secrets_count": len(secrets),  # Original count
                "secrets_stored": len(limited_secrets),  # Stored count
                "secrets": limited_secrets,
                "summary": summary
            }
            
            self.db[self.output_collection].update_one(
                {"scan_id": scan_id},
                {"$set": document},
                upsert=True
            )
            
            logger.info(f"✅ Secret results saved for scan_id: {scan_id} ({len(limited_secrets)} secrets stored)")
            return scan_id
        except Exception as e:
            logger.error(f"Error saving secret results: {e}")
            raise
    
    def get_secret_results(self, scan_id: str) -> Optional[Dict]:
        """Get secret results by scan_id"""
        try:
            return self.db[self.output_collection].find_one({"scan_id": scan_id})
        except Exception as e:
            logger.error(f"Error getting secret results: {e}")
            return None
    
    def get_all_secret_results(self, limit: int = 100) -> List[Dict]:
        """Get all secret results"""
        try:
            cursor = self.db[self.output_collection].find().sort("created_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting all secret results: {e}")
            return []
    
    def delete_secret_results(self, scan_id: str) -> bool:
        """Delete secret results by scan_id"""
        try:
            result = self.db[self.output_collection].delete_one({"scan_id": scan_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting secret results: {e}")
            return False
    
    def update_scan_stage(self, scan_id: str, status: str):
        """Update scan stage status in scans collection"""
        try:
            self.db['scans'].update_one(
                {"scan_id": scan_id},
                {"$set": {"stages.secret_hunter": status, "updated_at": datetime.utcnow()}}
            )
        except Exception as e:
            logger.error(f"Error updating scan stage: {e}")
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        try:
            total = self.db[self.output_collection].count_documents({})
            with_secrets = self.db[self.output_collection].count_documents({"secrets_count": {"$gt": 0}})
            
            pipeline = [
                {"$group": {
                    "_id": None,
                    "total_secrets": {"$sum": "$secrets_count"},
                    "avg_secrets": {"$avg": "$secrets_count"}
                }}
            ]
            agg_result = list(self.db[self.output_collection].aggregate(pipeline))
            
            return {
                "total_scans": total,
                "scans_with_secrets": with_secrets,
                "total_secrets_found": agg_result[0]['total_secrets'] if agg_result else 0,
                "avg_secrets_per_scan": round(agg_result[0]['avg_secrets'], 2) if agg_result else 0
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


# Singleton instance
mongodb_client = MongoDBClient()
