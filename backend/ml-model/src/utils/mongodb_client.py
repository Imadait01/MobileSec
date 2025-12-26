"""
MongoDB Client for ML Model Service
Handles connections and queries to the security_platform database
"""

import os
import logging
from typing import Optional, Dict, List
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure
from datetime import datetime

logger = logging.getLogger(__name__)


class MongoDBClient:
    """Singleton MongoDB client for ML model data extraction"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.uri = os.getenv(
            'MONGODB_URI',
            'mongodb://admin:securityplatform2024@mongodb:27017/security_platform?authSource=admin'
        )
        self.db_name = os.getenv('MONGODB_DATABASE', 'security_platform')
        
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
            logger.info("Disconnected from MongoDB")
    
    def is_connected(self) -> bool:
        """Check if connected to MongoDB"""
        try:
            if self.client:
                self.client.admin.command('ping')
                return True
        except Exception:
            pass
        return False
    
    # ==================== DATA EXTRACTION METHODS ====================
    
    def get_all_scans(self, limit: int = None) -> List[Dict]:
        """Get all scans from scans collection"""
        try:
            query = {}
            cursor = self.db['scans'].find(query).sort("created_at", DESCENDING)
            if limit:
                cursor = cursor.limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting scans: {e}")
            return []
    
    def get_crypto_results(self, scan_id: str = None, limit: int = None) -> List[Dict]:
        """Get crypto analysis results"""
        try:
            query = {"scan_id": scan_id} if scan_id else {}
            cursor = self.db['crypto_results'].find(query).sort("created_at", DESCENDING)
            if limit:
                cursor = cursor.limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting crypto results: {e}")
            return []
    
    def get_secret_results(self, scan_id: str = None, limit: int = None) -> List[Dict]:
        """Get secret detection results"""
        try:
            query = {"scan_id": scan_id} if scan_id else {}
            cursor = self.db['secret_results'].find(query).sort("created_at", DESCENDING)
            if limit:
                cursor = cursor.limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting secret results: {e}")
            return []
    
    def get_network_results(self, scan_id: str = None, limit: int = None) -> List[Dict]:
        """Get network analysis results"""
        try:
            query = {"scan_id": scan_id} if scan_id else {}
            cursor = self.db['network_results'].find(query).sort("created_at", DESCENDING)
            if limit:
                cursor = cursor.limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting network results: {e}")
            return []
    
    def get_fix_suggestions(self, scan_id: str = None, limit: int = None) -> List[Dict]:
        """Get AI-generated fix suggestions (for labeling)"""
        try:
            query = {"scan_id": scan_id} if scan_id else {}
            cursor = self.db['fix_suggestions'].find(query).sort("created_at", DESCENDING)
            if limit:
                cursor = cursor.limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting fix suggestions: {e}")
            return []
    
    def get_combined_scan_data(self, scan_id: str) -> Optional[Dict]:
        """
        Get all data for a single scan from all collections
        Returns a combined dictionary with all vulnerability data
        """
        try:
            result = {
                'scan_id': scan_id,
                'crypto': None,
                'secrets': None,
                'network': None,
                'fix_suggestions': None,
                'timestamp': datetime.utcnow()
            }
            
            # Get data from each collection
            crypto_data = self.db['crypto_results'].find_one({"scan_id": scan_id})
            secret_data = self.db['secret_results'].find_one({"scan_id": scan_id})
            network_data = self.db['network_results'].find_one({"scan_id": scan_id})
            fix_data = self.db['fix_suggestions'].find_one({"scan_id": scan_id})
            
            if crypto_data:
                result['crypto'] = crypto_data
            if secret_data:
                result['secrets'] = secret_data
            if network_data:
                result['network'] = network_data
            if fix_data:
                result['fix_suggestions'] = fix_data
            
            # Return None if no data found at all
            if all(v is None for k, v in result.items() if k not in ['scan_id', 'timestamp']):
                return None
                
            return result
            
        except Exception as e:
            logger.error(f"Error getting combined scan data: {e}")
            return None
    
    def get_all_scan_ids(self) -> List[str]:
        """Get all unique scan IDs from all collections"""
        try:
            scan_ids = set()
            
            # Get scan_ids from each collection
            for collection_name in ['crypto_results', 'secret_results', 'network_results']:
                ids = self.db[collection_name].distinct('scan_id')
                scan_ids.update(ids)
            
            return sorted(list(scan_ids))
        except Exception as e:
            logger.error(f"Error getting scan IDs: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get overall statistics from all collections"""
        try:
            return {
                'total_scans': len(self.get_all_scan_ids()),
                'crypto_results_count': self.db['crypto_results'].count_documents({}),
                'secret_results_count': self.db['secret_results'].count_documents({}),
                'network_results_count': self.db['network_results'].count_documents({}),
                'fix_suggestions_count': self.db['fix_suggestions'].count_documents({}),
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


# Singleton instance
mongodb_client = MongoDBClient()
