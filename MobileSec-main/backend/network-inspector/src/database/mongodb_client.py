"""
MongoDB Client for NetworkInspector
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
    """MongoDB client singleton for NetworkInspector"""
    
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
        self.output_collection = os.getenv('OUTPUT_COLLECTION', 'network_results')
        
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
    
    # ==================== OUTPUT: NETWORK_RESULTS ====================
    
    def save_network_results(self, scan_id: str, analysis: Dict, traffic_data: Dict = None) -> str:
        """Save network analysis results"""
        try:
            document = {
                "scan_id": scan_id,
                "status": "completed",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "analysis": analysis,
                "traffic_summary": traffic_data.get('summary', {}) if traffic_data else {},
                "findings_count": len(analysis.get('security_issues', [])),
                "endpoints_count": len(analysis.get('endpoints', []))
            }
            
            self.db[self.output_collection].update_one(
                {"scan_id": scan_id},
                {"$set": document},
                upsert=True
            )
            
            logger.info(f"✅ Network results saved for scan_id: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Error saving network results: {e}")
            raise
    
    def get_network_results(self, scan_id: str) -> Optional[Dict]:
        """Get network results by scan_id"""
        try:
            return self.db[self.output_collection].find_one({"scan_id": scan_id})
        except Exception as e:
            logger.error(f"Error getting network results: {e}")
            return None
    
    def get_all_network_results(self, limit: int = 100) -> List[Dict]:
        """Get all network results"""
        try:
            cursor = self.db[self.output_collection].find().sort("created_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting all network results: {e}")
            return []
    
    def delete_network_results(self, scan_id: str) -> bool:
        """Delete network results by scan_id"""
        try:
            result = self.db[self.output_collection].delete_one({"scan_id": scan_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting network results: {e}")
            return False
    
    def update_scan_stage(self, scan_id: str, status: str):
        """Update scan stage status in scans collection"""
        try:
            self.db['scans'].update_one(
                {"scan_id": scan_id},
                {"$set": {"stages.network_inspector": status, "updated_at": datetime.utcnow()}}
            )
        except Exception as e:
            logger.error(f"Error updating scan stage: {e}")
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        try:
            total = self.db[self.output_collection].count_documents({})
            with_issues = self.db[self.output_collection].count_documents({"findings_count": {"$gt": 0}})
            
            pipeline = [
                {"$group": {
                    "_id": None,
                    "total_findings": {"$sum": "$findings_count"},
                    "total_endpoints": {"$sum": "$endpoints_count"},
                    "avg_endpoints": {"$avg": "$endpoints_count"}
                }}
            ]
            agg_result = list(self.db[self.output_collection].aggregate(pipeline))
            
            return {
                "total_scans": total,
                "scans_with_issues": with_issues,
                "total_security_issues": agg_result[0]['total_findings'] if agg_result else 0,
                "total_endpoints_discovered": agg_result[0]['total_endpoints'] if agg_result else 0,
                "avg_endpoints_per_scan": round(agg_result[0]['avg_endpoints'], 2) if agg_result else 0
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


# Singleton instance
mongodb_client = MongoDBClient()
