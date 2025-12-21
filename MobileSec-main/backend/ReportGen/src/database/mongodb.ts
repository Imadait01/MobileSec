/**
 * MongoDB Client for ReportGen
 * Handles all database operations with MongoDB
 */

import { MongoClient, Db, Collection } from 'mongodb';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://admin:securityplatform2024@localhost:27017/security_platform?authSource=admin';
const DB_NAME = process.env.MONGODB_DATABASE || 'security_platform';

class MongoDBClient {
    private client: MongoClient | null = null;
    private db: Db | null = null;
    private static instance: MongoDBClient;

    private constructor() { }

    public static getInstance(): MongoDBClient {
        if (!MongoDBClient.instance) {
            MongoDBClient.instance = new MongoDBClient();
        }
        return MongoDBClient.instance;
    }

    async connect(): Promise<boolean> {
        try {
            this.client = new MongoClient(MONGODB_URI);
            await this.client.connect();
            this.db = this.client.db(DB_NAME);
            console.log('✅ Connected to MongoDB:', DB_NAME);
            return true;
        } catch (error) {
            console.error('❌ Failed to connect to MongoDB:', error);
            return false;
        }
    }

    async disconnect(): Promise<void> {
        if (this.client) {
            await this.client.close();
        }
    }

    isConnected(): boolean {
        return this.client !== null && this.db !== null;
    }

    // ==================== Collections ====================

    get scansCollection(): Collection {
        if (!this.db) throw new Error('Database not connected');
        return this.db.collection('scans');
    }

    get apkResultsCollection(): Collection {
        if (!this.db) throw new Error('Database not connected');
        return this.db.collection('apk_results');
    }

    get secretResultsCollection(): Collection {
        if (!this.db) throw new Error('Database not connected');
        return this.db.collection('secret_results');
    }

    get cryptoResultsCollection(): Collection {
        if (!this.db) throw new Error('Database not connected');
        return this.db.collection('crypto_results');
    }

    get networkResultsCollection(): Collection {
        if (!this.db) throw new Error('Database not connected');
        return this.db.collection('network_results');
    }

    get reportsCollection(): Collection {
        if (!this.db) throw new Error('Database not connected');
        return this.db.collection('reports');
    }

    // ==================== Input: Get all results for a scan ====================

    async getAllResultsForScan(scanId: string): Promise<{
        apk: any;
        secrets: any;
        crypto: any;
        network: any;
    }> {
        const [apk, secrets, crypto, network] = await Promise.all([
            this.apkResultsCollection.findOne({ scan_id: scanId }),
            this.secretResultsCollection.findOne({ scan_id: scanId }),
            this.cryptoResultsCollection.findOne({ scan_id: scanId }),
            this.networkResultsCollection.findOne({ scan_id: scanId })
        ]);

        return { apk, secrets, crypto, network };
    }

    async getScanInfo(scanId: string): Promise<any> {
        return this.scansCollection.findOne({ scan_id: scanId });
    }

    // ==================== Output: Reports ====================

    async saveReport(scanId: string, report: any): Promise<string> {
        const document = {
            scan_id: scanId,
            status: 'completed',
            created_at: new Date(),
            updated_at: new Date(),
            report_id: report.reportId,
            report_format: report.format,
            report_path: report.path,
            summary: report.summary,
            vulnerabilities_count: report.vulnerabilitiesCount
        };

        await this.reportsCollection.updateOne(
            { scan_id: scanId },
            { $set: document },
            { upsert: true }
        );

        console.log('✅ Report saved to MongoDB for scan_id:', scanId);
        return scanId;
    }

    async getReport(scanId: string): Promise<any> {
        return this.reportsCollection.findOne({ scan_id: scanId });
    }

    async getReportById(reportId: string): Promise<any> {
        return this.reportsCollection.findOne({ report_id: reportId });
    }

    async getAllReports(limit: number = 100): Promise<any[]> {
        return this.reportsCollection
            .find()
            .sort({ created_at: -1 })
            .limit(limit)
            .toArray();
    }

    async deleteReport(scanId: string): Promise<boolean> {
        const result = await this.reportsCollection.deleteOne({ scan_id: scanId });
        return result.deletedCount > 0;
    }

    async updateScanStage(scanId: string, status: string): Promise<void> {
        const result = await this.scansCollection.updateOne(
            { scan_id: scanId },
            {
                $set: {
                    'stages.report_gen': status,
                    updated_at: new Date()
                }
            }
        );
        console.log(`[MongoDB] Updated scan stage for ${scanId} to ${status}. Modified: ${result.modifiedCount}, Matched: ${result.matchedCount}`);
    }

    async getStatistics(): Promise<any> {
        const total = await this.reportsCollection.countDocuments();
        const pipeline = [
            {
                $group: {
                    _id: null,
                    total_vulns: { $sum: '$vulnerabilities_count' },
                    avg_vulns: { $avg: '$vulnerabilities_count' }
                }
            }
        ];
        const aggResult = await this.reportsCollection.aggregate(pipeline).toArray();

        return {
            total_reports: total,
            total_vulnerabilities: aggResult[0]?.total_vulns || 0,
            avg_vulnerabilities_per_report: Math.round(aggResult[0]?.avg_vulns || 0)
        };
    }
}

export const mongoClient = MongoDBClient.getInstance();
export default mongoClient;
