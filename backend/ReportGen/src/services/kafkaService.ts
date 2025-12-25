
import { Kafka, Consumer } from 'kafkajs';
import logger from '../utils/logger';
import { mongoClient } from '../database/mongodb';
import { v4 as uuidv4 } from 'uuid';
import {
    aggregatorService,
    deduplicatorService,
    metricsService,
    pdfGeneratorService
} from './index';
import { Report, ReportOptions } from '../models';

export class KafkaService {
    private kafka: Kafka;
    private consumer: Consumer;
    // private isConnected: boolean = false;

    constructor() {
        this.kafka = new Kafka({
            clientId: 'reportgen-service',
            brokers: (process.env.KAFKA_BROKERS || 'kafka:9092').split(',')
        });
        this.consumer = this.kafka.consumer({ groupId: 'reportgen-group' });
    }

    async connect(): Promise<void> {
        try {
            logger.info('ReportGen: Connecting to Kafka...');
            await this.consumer.connect();
            logger.info('ReportGen: Connected. Subscribing...');
            await this.consumer.subscribe({ topic: 'scan-requests', fromBeginning: false });
            logger.info('ReportGen: Subscribed to scan-requests');
            // this.isConnected = true;
            logger.info('Kafka consumer connected and subscribed to scan-requests');

            await this.consumer.run({
                eachMessage: async ({ message }) => {
                    const value = message.value?.toString();
                    if (!value) return;
                    logger.info(`ReportGen: Received message: ${value}`);

                    try {
                        const data = JSON.parse(value);
                        logger.info(`Received scan request: ${data.id}`);
                        this.handleScanRequest(data.id);
                    } catch (error) {
                        logger.error('Error parsing Kafka message', { error });
                    }
                }
            });
        } catch (error) {
            logger.error('Failed to connect to Kafka', { error });
            // this.isConnected = false;
        }
    }

    private async handleScanRequest(scanId: string): Promise<void> {
        // Wait loop: Poll MongoDB for results until ready or timeout
        let attempts = 0;
        const maxAttempts = 12; // 2 minutes
        const delayMs = 10000;

        const checkResults = async () => {
            attempts++;
            const data = await mongoClient.getAllResultsForScan(scanId);
            const hasApk = !!data.apk;
            const hasNetwork = !!data.network;
            const hasSecret = !!data.secrets;
            const hasCrypto = !!data.crypto; // CryptoCheck might file later

            // Check if scan info exists
            try {
                await mongoClient.getScanInfo(scanId);
                // We could check scanInfo.stages if we wanted stricter logic
            } catch (e) {
                // Ignore
            }

            logger.info(`Polling scan ${scanId} attempt ${attempts}/${maxAttempts}. Found: APK=${hasApk} Net=${hasNetwork} Sec=${hasSecret} Cry=${hasCrypto}`);

            if (hasApk && hasNetwork && hasSecret && hasCrypto) {
                return data; // All ready
            }

            if (attempts >= maxAttempts) {
                logger.warn(`Timeout waiting for results for ${scanId}. Proceeding with available data.`);
                return data; // Return whatever we have
            }

            return null; // Keep waiting
        };

        const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

        while (attempts < maxAttempts) {
            const data = await checkResults();
            if (data) {
                await this.generateReportFor(scanId, data);
                return;
            }
            await sleep(delayMs);
        }
    }

    private async generateReportFor(scanId: string, scanData: any): Promise<void> {
        logger.info(`Generating Report for ${scanId}`);

        // Map data to ScanResults
        const scanResults: any = {};

        if (scanData.crypto?.vulnerabilities) {
            scanResults.cryptoCheck = scanData.crypto.vulnerabilities.map((v: any) => ({
                ruleId: v.vulnerability || 'CRYPTO',
                severity: this.mapSeverity(v.severity),
                message: v.vulnerability,
                file: v.file,
                line: v.line || 1
            }));
        }

        if (scanData.secrets?.secrets) {
            scanResults.secretHunter = scanData.secrets.secrets.map((s: any) => ({
                ruleId: 'SECRET',
                severity: this.mapSeverity(s.severity),
                message: s.description || s.type,
                file: s.file_path,
                line: s.line_number || 1
            }));
        }

        if (scanData.network?.analysis?.security_issues) {
            scanResults.networkInspector = scanData.network.analysis.security_issues.map((i: any) => ({
                ruleId: i.type || 'NETWORK',
                severity: this.mapSeverity(i.severity),
                message: i.description,
                file: i.file || 'network',
                line: i.line || 1
            }));
        }

        if (scanData.apk?.results?.manifest_issues) {
            scanResults.apkScanner = scanData.apk.results.manifest_issues.map((m: any) => ({
                ruleId: m.type || 'MANIFEST',
                severity: this.mapSeverity(m.severity),
                message: m.message,
                file: 'AndroidManifest.xml',
                line: 1
            }));
        }

        const projectName = scanData.apk?.results?.app_name || `Scan ${scanId}`;
        const reportId = uuidv4();

        // Generator Flow
        const aggregated = aggregatorService.aggregateResults(scanResults);
        const deduplicated = deduplicatorService.deduplicate(aggregated);
        const metrics = metricsService.calculateMetrics(deduplicated);

        const report: Report = {
            reportId,
            projectName,
            vulnerabilities: deduplicated,
            metrics,
            scanMetadata: {
                startTime: new Date().toISOString(),
                tools: Object.keys(scanResults)
            },
            generatedAt: new Date().toISOString(),
            format: 'pdf',
            status: 'completed'
        };

        try {
            const options: ReportOptions = {
                includeSummary: true,
                includeRecommendations: true,
                includeRawFindings: false,
                // Use an available template (softwareX is included by default)
                template: 'softwareX'
            };
            const filePath = await pdfGeneratorService.generatePdf(report, options);
            report.filePath = filePath;

            // Save to Mongo
            await mongoClient.saveReport(scanId, {
                reportId,
                format: 'pdf',
                path: filePath,
                summary: metrics,
                vulnerabilitiesCount: metrics.total
            });

            logger.info(`✅ Report Generated and Saved via Kafka Trigger: ${reportId}`);
        } catch (e) {
            logger.error(`Failed to generate PDF for ${scanId}`, { e });
        }
    }

    private mapSeverity(severity: string): string {
        const s = (severity || 'info').toLowerCase();
        if (s.includes('critical')) return 'critical';
        if (s.includes('high')) return 'high';
        if (s.includes('medium')) return 'medium';
        return 'low';
    }
}

export const kafkaService = new KafkaService();
