// MongoDB Initialization Script
// Creates the security_platform database with all required collections and indexes

// Switch to the security_platform database
db = db.getSiblingDB('security_platform');

// Create collections with schemas
print("Creating collections...");

// 1. Scans collection - Central tracking for all scans
db.createCollection('scans');
db.scans.createIndex({ "scan_id": 1 }, { unique: true });
db.scans.createIndex({ "status": 1 });
db.scans.createIndex({ "created_at": -1 });
print("✅ Created 'scans' collection with indexes");

// 2. APK Results collection - Output from APK-Scanner
db.createCollection('apk_results');
db.apk_results.createIndex({ "scan_id": 1 }, { unique: true });
db.apk_results.createIndex({ "status": 1 });
db.apk_results.createIndex({ "created_at": -1 });
print("✅ Created 'apk_results' collection with indexes");

// 3. Secret Results collection - Output from SecretHunter
db.createCollection('secret_results');
db.secret_results.createIndex({ "scan_id": 1 }, { unique: true });
db.secret_results.createIndex({ "status": 1 });
db.secret_results.createIndex({ "created_at": -1 });
db.secret_results.createIndex({ "secrets_count": 1 });
print("✅ Created 'secret_results' collection with indexes");

// 4. Crypto Results collection - Output from CryptoCheck
db.createCollection('crypto_results');
db.crypto_results.createIndex({ "scan_id": 1 }, { unique: true });
db.crypto_results.createIndex({ "status": 1 });
db.crypto_results.createIndex({ "created_at": -1 });
db.crypto_results.createIndex({ "total_vulnerabilities": 1 });
print("✅ Created 'crypto_results' collection with indexes");

// 5. Network Results collection - Output from NetworkInspector
db.createCollection('network_results');
db.network_results.createIndex({ "scan_id": 1 }, { unique: true });
db.network_results.createIndex({ "status": 1 });
db.network_results.createIndex({ "created_at": -1 });
print("✅ Created 'network_results' collection with indexes");

// 6. Reports collection - Output from ReportGen
db.createCollection('reports');
db.reports.createIndex({ "scan_id": 1 }, { unique: true });
db.reports.createIndex({ "report_id": 1 });
db.reports.createIndex({ "created_at": -1 });
print("✅ Created 'reports' collection with indexes");

// Insert a test document to verify setup
db.scans.insertOne({
    scan_id: "test-init-001",
    apk_name: "test-initialization",
    source: "mongo-init",
    status: "completed",
    created_at: new Date(),
    updated_at: new Date(),
    stages: {
        apk_scanner: "completed",
        secret_hunter: "completed",
        crypto_check: "completed",
        network_inspector: "completed",
        report_gen: "completed"
    },
    note: "This is a test document created during initialization. You can delete it."
});

print("");
print("===========================================");
print("✅ MongoDB initialization complete!");
print("===========================================");
print("Database: security_platform");
print("Collections created:");
print("  - scans");
print("  - apk_results");
print("  - secret_results");
print("  - crypto_results");
print("  - network_results");
print("  - reports");
print("===========================================");
