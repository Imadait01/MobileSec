"""
Quick test to verify MongoDB connection and data extraction
"""
import sys
import os
sys.path.insert(0, 'src')

from pymongo import MongoClient

# Connect to MongoDB
uri = 'mongodb://admin:securityplatform2024@localhost:27017/security_platform?authSource=admin'
client = MongoClient(uri, serverSelectionTimeoutMS=5000)
db = client['security_platform']

# Test connection
try:
    client.admin.command('ping')
    print("✅ Connected to MongoDB")
    
    # Get scan IDs
    crypto_ids = list(db['crypto_results'].distinct('scan_id'))
    secret_ids = list(db['secret_results'].distinct('scan_id'))
    network_ids = list(db['network_results'].distinct('scan_id'))
    
    all_scan_ids = set(crypto_ids + secret_ids + network_ids)
    
    print(f"✅ Found {len(all_scan_ids)} unique scan IDs")
    print(f"   Crypto results: {len(crypto_ids)}")
    print(f"   Secret results: {len(secret_ids)}")
    print(f"   Network results: {len(network_ids)}")
    
    # Get a sample scan
    if crypto_ids:
        sample_id = crypto_ids[0]
        print(f"\n📊 Sample scan: {sample_id}")
        
        crypto = db['crypto_results'].find_one({'scan_id': sample_id})
        if crypto:
            print(f"   Crypto vulnerabilities: {crypto.get('total_vulnerabilities', 0)}")
            summary = crypto.get('summary', {})
            print(f"   Severity: High={summary.get('high', 0)}, Medium={summary.get('medium', 0)}, Low={summary.get('low', 0)}")
        
        secrets = db['secret_results'].find_one({'scan_id': sample_id})
        if secrets:
            print(f"   Secrets found: {secrets.get('secrets_count', 0)}")
        
        network = db['network_results'].find_one({'scan_id': sample_id})
        if network:
            print(f"   Network findings: {network.get('findings_count', 0)}")
    
    print("\n✅ MongoDB connection test successful!")
    print(f"Ready to extract {len(all_scan_ids)} scans for training")
    
except Exception as e:
    print(f"❌ Error: {e}")
finally:
    client.close()
