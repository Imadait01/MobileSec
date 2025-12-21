/**
 * MongoDB Client for CI-Connector
 * Handles all database operations with MongoDB
 */

const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://admin:securityplatform2024@localhost:27017/security_platform?authSource=admin';
const DB_NAME = process.env.MONGODB_DATABASE || 'security_platform';

class MongoDBClient {
    constructor() {
        this.client = null;
        this.db = null;
    }

    async connect() {
        try {
            this.client = new MongoClient(MONGODB_URI);
            await this.client.connect();
            this.db = this.client.db(DB_NAME);
            console.log('✅ Connected to MongoDB:', DB_NAME);
            return true;
        } catch (error) {
            console.error('❌ Failed to connect to MongoDB:', error.message);
            return false;
        }
    }

    async disconnect() {
        if (this.client) {
            await this.client.close();
        }
    }

    isConnected() {
        return this.client !== null && this.db !== null;
    }

    // ==================== Scans Collection ====================

    async createScan(scanId, apkName, source = 'ci-connector') {
        const document = {
            scan_id: scanId,
            apk_name: apkName,
            source: source,
            status: 'pending',
            created_at: new Date(),
            updated_at: new Date(),
            stages: {
                apk_scanner: 'pending',
                secret_hunter: 'pending',
                crypto_check: 'pending',
                network_inspector: 'pending',
                report_gen: 'pending'
            }
        };

        await this.db.collection('scans').insertOne(document);
        console.log('✅ Scan created in MongoDB:', scanId);
        return scanId;
    }

    async getScan(scanId) {
        return this.db.collection('scans').findOne({ scan_id: scanId });
    }

    async updateScanStatus(scanId, status) {
        await this.db.collection('scans').updateOne(
            { scan_id: scanId },
            { 
                $set: { 
                    status: status,
                    updated_at: new Date()
                }
            }
        );
    }

    async getAllScans(limit = 100) {
        return this.db.collection('scans')
            .find()
            .sort({ created_at: -1 })
            .limit(limit)
            .toArray();
    }

    async deleteScan(scanId) {
        const result = await this.db.collection('scans').deleteOne({ scan_id: scanId });
        return result.deletedCount > 0;
    }

    async getStatistics() {
        const total = await this.db.collection('scans').countDocuments();
        const pending = await this.db.collection('scans').countDocuments({ status: 'pending' });
        const completed = await this.db.collection('scans').countDocuments({ status: 'completed' });
        const failed = await this.db.collection('scans').countDocuments({ status: 'failed' });

        return {
            total_scans: total,
            pending: pending,
            completed: completed,
            failed: failed
        };
    }
}

const mongoClient = new MongoDBClient();

module.exports = { mongoClient };
