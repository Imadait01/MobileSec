
import { Kafka, Consumer, Producer } from 'kafkajs';
import logger from '../utils/logger';
import { mongoClient } from '../database/mongodb';
import { v4 as uuidv4 } from 'uuid';

const SCAN_REQUESTS_TOPIC = process.env.KAFKA_TOPIC_SCAN_REQUESTS || 'scan-requests';
const SCAN_RESULTS_TOPIC = process.env.KAFKA_TOPIC_SCAN_RESULTS || 'scan-results';
const REPORT_GENERATED_TOPIC = process.env.KAFKA_TOPIC_REPORT_GENERATED || 'report-generated';
import {
    aggregatorService,
    deduplicatorService,
    metricsService,
    jsonExporterService
} from './index';
import { Report, ReportOptions } from '../models';

export class KafkaService {
    private kafka: Kafka;
    private consumer: Consumer;
    private producer: Producer;

    constructor() {
        this.kafka = new Kafka({
            clientId: 'reportgen-service',
            brokers: (process.env.KAFKA_BROKERS || 'kafka:9092').split(',')
        });
        this.consumer = this.kafka.consumer({ groupId: process.env.KAFKA_GROUP_ID || 'reportgen-group' });
        this.producer = this.kafka.producer();
    }

    async connect(): Promise<void> {
        try {
            logger.info('ReportGen: Connecting to Kafka...');
            await this.producer.connect();
            logger.info('ReportGen: Kafka producer connected');

            await this.consumer.connect();
            logger.info('ReportGen: Connected. Subscribing...');

            // Subscribe to both topics up-front to avoid missing messages
            try {
                await this.consumer.subscribe({ topic: SCAN_REQUESTS_TOPIC, fromBeginning: false });
                logger.info(`ReportGen: Subscribed to ${SCAN_REQUESTS_TOPIC}`);
            } catch (e) {
                logger.warn(`ReportGen: Failed to subscribe to ${SCAN_REQUESTS_TOPIC}`, { error: String(e) });
            }

            try {
                await this.consumer.subscribe({ topic: SCAN_RESULTS_TOPIC, fromBeginning: false });
                logger.info(`ReportGen: Subscribed to ${SCAN_RESULTS_TOPIC}`);
            } catch (e) {
                logger.info(`ReportGen: No scan-results topic or subscribe failed: ${String(e)}`);
            }

            await this.consumer.run({
                eachMessage: async ({ topic, message }) => {
                    const value = message.value?.toString();
                    if (!value) return;
                    logger.info(`ReportGen: Received message on ${topic}: ${value}`);

                    try {
                        const data = JSON.parse(value);

                        if (topic === SCAN_REQUESTS_TOPIC) {
                            logger.info(`Received scan request: ${data.id}`);
                            this.handleScanRequest(data.id);
                        } else if (topic === SCAN_RESULTS_TOPIC) {
                            logger.info(`Received scan result for ${data.scanId}`);
                            // Optionally persist the incoming result to MongoDB for consistency
                            try {
                                await mongoClient.saveScanPartial?.(data.scanId, data); // best-effort
                            } catch (e) {
                                logger.debug('saveScanPartial not available or failed', { error: e });
                            }
                        }
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
            const data: any = await mongoClient.getAllResultsForScan(scanId);
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

        const generatedAt = new Date().toISOString();
        const scanStart = scanData.scanInfo?.startTime || new Date().toISOString();

        // Build per-service summaries similar to controller.processReport so templates receive the expected shape
        const servicesSummary: Record<string, any> = {};
        const rawServices: any = {
            cryptoCheck: scanData.crypto || null,
            secretHunter: scanData.secrets || null,
            networkInspector: scanData.network || null,
            apkScanner: scanData.apk || null
        };

        // Attempt to attribute deduplicated vulnerabilities to each service
        for (const [svcName, svcRaw] of Object.entries(rawServices)) {
            const svcKey = String(svcName);
            const svcVulns = deduplicated.filter((v: any) => {
                try {
                    if (v.source && String(v.source).toLowerCase().includes(svcKey.toLowerCase())) return true;
                    if (Array.isArray(v.detectedBy) && v.detectedBy.some((d: string) => String(d).toLowerCase().includes(svcKey.toLowerCase()))) return true;
                } catch (e) {}
                return false;
            });

            const bySeverity = svcVulns.reduce((acc: Record<string, number>, v: any) => {
                const sev = (v.severity || 'info') as string;
                acc[sev] = (acc[sev] || 0) + 1;
                return acc;
            }, {} as Record<string, number>);

            const topFindings = svcVulns.slice(0, 10).map((v: any) => ({
                id: v.id,
                title: v.title,
                description: v.description,
                file: v.location?.file,
                severity: v.severity,
                recommendation: v.recommendation
            }));

            servicesSummary[svcKey] = {
                totalFindings: svcVulns.length,
                bySeverity,
                findings: topFindings,
                topFindings,
                raw: svcRaw,
                rawString: (() => { try { return JSON.stringify(svcRaw, null, 2); } catch (e) { return String(svcRaw); } })(),
                total: svcVulns.length,
                top: topFindings
            };
        }

        const priorityRecommendations = metricsService.generatePriorityRecommendations(deduplicated, metrics);

        const report: Report = {
            reportId,
            projectName,
            vulnerabilities: deduplicated,
            metrics,
            scanMetadata: {
                startTime: String(scanStart),
                endTime: generatedAt,
                duration: undefined,
                tools: Object.keys(scanResults),
                targetBranch: scanData.scanInfo?.targetBranch,
                commitHash: scanData.scanInfo?.commitHash,
                pipelineId: scanData.scanInfo?.pipelineId
            },
            generatedAt,
            format: 'pdf',
            status: 'completed',
            // include enriched per-service summaries
            services: servicesSummary,
            priorityRecommendations
        };

        try {
            const options: ReportOptions = {
                includeSummary: true,
                includeRecommendations: true,
                includeRawFindings: false,
                // Per-service defaults
                includePerServiceDetails: true,
                maxFindingsPerService: 10,
                includeRawServiceOutput: false,
                // Use the security_report template by default
                template: 'security_report' 
            };
            // Export JSON (PDF generation can be performed on-demand or enabled if needed)
            const jsonPath = await jsonExporterService.exportToJson(report, {
                pretty: true,
                includeRawData: false,
                includeRawServiceOutput: options.includeRawServiceOutput,
                maxFindingsPerService: options.maxFindingsPerService
            });

            report.filePath = jsonPath;

            // Save to Mongo (store as json)
            await mongoClient.saveReport(scanId, {
                reportId,
                format: 'json',
                path: jsonPath,
                summary: metrics,
                vulnerabilitiesCount: metrics.total
            });

            logger.info(`✅ JSON Report Generated and Saved via Kafka Trigger: ${reportId}`);

            // Emit a report-generated event for downstream consumers (e.g., FixSuggest)
            try {
                const payload = {
                    reportId,
                    scanId,
                    reportPath: jsonPath,
                    format: 'json',
                    generatedAt
                };
                await this.producer.send({
                    topic: REPORT_GENERATED_TOPIC,
                    messages: [{ key: reportId, value: JSON.stringify(payload) }]
                });
                logger.info(`Published report-generated event for ${reportId} to ${REPORT_GENERATED_TOPIC}`);
            } catch (e) {
                logger.warn('Failed to publish report-generated event', { error: e });
            }

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
