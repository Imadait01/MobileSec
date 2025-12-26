"""
Data Extractor for ML Model
Extracts security vulnerability data from MongoDB collections
"""

import logging
import pandas as pd
from typing import List, Dict, Optional
from datetime import datetime
from ..utils.mongodb_client import mongodb_client

logger = logging.getLogger(__name__)


class DataExtractor:
    """Extract and prepare security scan data for ML training"""
    
    def __init__(self):
        self.client = mongodb_client
        
    def connect(self) -> bool:
        """Connect to MongoDB"""
        return self.client.connect()
    
    def disconnect(self):
        """Disconnect from MongoDB"""
        self.client.disconnect()
    
    def extract_all_data(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Extract all security scan data and combine into a single DataFrame
        
        Args:
            limit: Optional limit on number of scans to extract
            
        Returns:
            DataFrame with combined features from all services
        """
        logger.info("Starting data extraction...")
        
        if not self.client.is_connected():
            logger.info("Connecting to MongoDB...")
            if not self.connect():
                raise ConnectionError("Failed to connect to MongoDB")
        
        # Get all scan IDs
        scan_ids = self.client.get_all_scan_ids()
        if limit:
            scan_ids = scan_ids[:limit]
        
        logger.info(f"Extracting data for {len(scan_ids)} scans...")
        
        # Extract data for each scan
        records = []
        for i, scan_id in enumerate(scan_ids):
            if (i + 1) % 10 == 0:
                logger.info(f"Processing scan {i+1}/{len(scan_ids)}")
            
            record = self._extract_scan_features(scan_id)
            if record:
                records.append(record)
        
        logger.info(f"Successfully extracted {len(records)} scan records")
        
        # Convert to DataFrame
        df = pd.DataFrame(records)
        return df
    
    def _extract_scan_features(self, scan_id: str) -> Optional[Dict]:
        """
        Extract features from a single scan
        
        Returns a dictionary with all features for ML training
        """
        try:
            # Get data from all collections
            combined_data = self.client.get_combined_scan_data(scan_id)
            if not combined_data:
                logger.warning(f"No data found for scan_id: {scan_id}")
                return None
            
            features = {'scan_id': scan_id}
            
            # ============ CRYPTO FEATURES ============
            crypto = combined_data.get('crypto')
            if crypto:
                features['crypto_total_vulns'] = crypto.get('total_vulnerabilities', 0)
                summary = crypto.get('summary', {})
                features['crypto_high'] = summary.get('high', 0)
                features['crypto_medium'] = summary.get('medium', 0)
                features['crypto_low'] = summary.get('low', 0)
                features['crypto_info'] = summary.get('info', 0)
                
                # Extract vulnerability types
                by_type = summary.get('by_type', {})
                features['crypto_weak_cipher'] = by_type.get('WEAK_CIPHER', 0)
                features['crypto_weak_hash'] = by_type.get('WEAK_HASH', 0)
                features['crypto_insecure_random'] = by_type.get('INSECURE_RANDOM', 0)
                features['crypto_weak_rsa'] = by_type.get('WEAK_RSA_KEY', 0)
                
                # CWE codes (most common ones)
                vulnerabilities = crypto.get('vulnerabilities', [])
                cwe_counts = {}
                for vuln in vulnerabilities:
                    cwe = vuln.get('cwe', 'UNKNOWN')
                    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
                features['crypto_cwe_codes'] = ','.join(sorted(cwe_counts.keys()))
                features['crypto_unique_cwes'] = len(cwe_counts)
                
            else:
                # Default values if no crypto data
                features.update({
                    'crypto_total_vulns': 0, 'crypto_high': 0, 'crypto_medium': 0,
                    'crypto_low': 0, 'crypto_info': 0, 'crypto_weak_cipher': 0,
                    'crypto_weak_hash': 0, 'crypto_insecure_random': 0,
                    'crypto_weak_rsa': 0, 'crypto_cwe_codes': '', 'crypto_unique_cwes': 0
                })
            
            # ============ SECRET FEATURES ============
            secrets = combined_data.get('secrets')
            if secrets:
                features['secrets_count'] = secrets.get('secrets_count', 0)
                
                # Count by type
                secret_items = secrets.get('secrets', [])
                secret_types = {}
                for secret in secret_items:
                    stype = secret.get('type', 'UNKNOWN')
                    secret_types[stype] = secret_types.get(stype, 0) + 1
                
                features['secrets_api_keys'] = secret_types.get('API_KEY', 0)
                features['secrets_passwords'] = secret_types.get('PASSWORD', 0)
                features['secrets_tokens'] = secret_types.get('TOKEN', 0)
                features['secrets_aws_keys'] = secret_types.get('AWS_KEY', 0)
                features['secrets_other'] = sum(v for k, v in secret_types.items() 
                                               if k not in ['API_KEY', 'PASSWORD', 'TOKEN', 'AWS_KEY'])
                features['secrets_unique_types'] = len(secret_types)
                
            else:
                features.update({
                    'secrets_count': 0, 'secrets_api_keys': 0, 'secrets_passwords': 0,
                    'secrets_tokens': 0, 'secrets_aws_keys': 0, 'secrets_other': 0,
                    'secrets_unique_types': 0
                })
            
            # ============ NETWORK FEATURES ============
            network = combined_data.get('network')
            if network:
                features['network_findings'] = network.get('findings_count', 0)
                features['network_endpoints'] = network.get('endpoints_count', 0)
                
                analysis = network.get('analysis', {})
                security_issues = analysis.get('security_issues', [])
                
                # Count issue types
                http_count = sum(1 for issue in security_issues if 'HTTP' in issue.get('type', ''))
                cert_count = sum(1 for issue in security_issues if 'CERTIFICATE' in issue.get('type', ''))
                domain_count = sum(1 for issue in security_issues if 'DOMAIN' in issue.get('type', ''))
                
                features['network_http_issues'] = http_count
                features['network_cert_issues'] = cert_count
                features['network_domain_issues'] = domain_count
                
            else:
                features.update({
                    'network_findings': 0, 'network_endpoints': 0,
                    'network_http_issues': 0, 'network_cert_issues': 0,
                    'network_domain_issues': 0
                })
            
            # ============ AGGREGATED FEATURES ============
            features['total_vulnerabilities'] = (
                features['crypto_total_vulns'] + 
                features['secrets_count'] + 
                features['network_findings']
            )
            
            # Severity score (weighted sum)
            features['severity_score'] = (
                features['crypto_high'] * 3 +
                features['crypto_medium'] * 2 +
                features['crypto_low'] * 1 +
                features['secrets_count'] * 2.5 +  # Secrets are critical
                features['network_findings'] * 1.5
            )
            
            # ============ LABELS (from FixSuggest) ============
            fix_suggestions = combined_data.get('fix_suggestions')
            if fix_suggestions:
                # Extract fix categories from AI suggestions
                suggestions = fix_suggestions.get('suggestions', [])
                if suggestions and len(suggestions) > 0:
                    # Use the first/primary suggestion as the label
                    primary = suggestions[0]
                    features['fix_category'] = primary.get('category', 'GENERAL')
                    features['has_fix_suggestion'] = True
                else:
                    features['fix_category'] = 'NO_SUGGESTION'
                    features['has_fix_suggestion'] = False
            else:
                # If no fix suggestions, use rule-based labeling
                features['fix_category'] = self._rule_based_label(features)
                features['has_fix_suggestion'] = False
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features for scan {scan_id}: {e}")
            return None
    
    def _rule_based_label(self, features: Dict) -> str:
        """
        Create a label based on vulnerability patterns when no AI suggestion exists
        
        Returns a fix category string
        """
        # Priority-based labeling
        if features['crypto_high'] > 0:
            if features['crypto_weak_cipher'] > 0:
                return 'FIX_WEAK_CIPHER'
            elif features['crypto_weak_hash'] > 0:
                return 'FIX_WEAK_HASH'
            elif features['crypto_insecure_random'] > 0:
                return 'FIX_INSECURE_RANDOM'
            else:
                return 'FIX_CRYPTO_GENERAL'
        
        if features['secrets_count'] > 0:
            if features['secrets_api_keys'] > 0:
                return 'FIX_EXPOSED_API_KEY'
            elif features['secrets_passwords'] > 0:
                return 'FIX_HARDCODED_PASSWORD'
            else:
                return 'FIX_EXPOSED_SECRET'
        
        if features['network_http_issues'] > 0:
            return 'FIX_INSECURE_HTTP'
        
        if features['network_cert_issues'] > 0:
            return 'FIX_CERTIFICATE_ISSUE'
        
        if features['crypto_medium'] > 0:
            return 'FIX_CRYPTO_MEDIUM'
        
        return 'NO_CRITICAL_ISSUES'
    
    def get_statistics(self) -> Dict:
        """Get data statistics"""
        return self.client.get_statistics()


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    extractor = DataExtractor()
    
    try:
        # Get statistics
        stats = extractor.get_statistics()
        print(f"Database statistics: {stats}")
        
        # Extract data
        df = extractor.extract_all_data(limit=10)
        print(f"\nExtracted DataFrame shape: {df.shape}")
        print(f"\nColumns: {df.columns.tolist()}")
        print(f"\nFirst few rows:\n{df.head()}")
        
        # Save to CSV
        output_path = "data/extracted_data.csv"
        df.to_csv(output_path, index=False)
        print(f"\nData saved to {output_path}")
        
    finally:
        extractor.disconnect()
