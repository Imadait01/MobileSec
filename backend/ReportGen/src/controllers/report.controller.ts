import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs/promises';
import multer from 'multer';
import path from 'path';
import logger from '../utils/logger';
import { mongoClient } from '../database/mongodb';
import {
  GenerateReportRequest,
  GenerateReportRequestSchema,
  Report,
  ReportOptions,
  ReportOptionsSchema,
  ReportStatus
} from '../models';
import {
  aggregatorService,
  deduplicatorService,
  metricsService,
  pdfGeneratorService,
  jsonExporterService,
  sarifExporterService,
  fileWatcherService
} from '../services';

// Store des rapports en mémoire (en production, utiliser Redis ou une BDD)
const reportsStore = new Map<string, Report>();

// Configuration de Multer pour l'upload de fichiers JSON
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    const uploadDir = process.env.TEMP_DIR || './tmp';
    cb(null, uploadDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, `upload-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});

const fileFilter = (_req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
    cb(null, true);
  } else {
    cb(new Error('Only JSON files are allowed'));
  }
};

export const uploadMiddleware = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB max
  }
});

export class ReportController {
  private tempDir: string;

  constructor() {
    this.tempDir = process.env.TEMP_DIR || './tmp';
    this.ensureTempDir();
  }

  /**
   * S'assure que le dossier temporaire existe
   */
  private async ensureTempDir(): Promise<void> {
    try {
      await fs.mkdir(this.tempDir, { recursive: true });
    } catch (error) {
      logger.error('Failed to create temp directory', { error });
    }
  }

  /**
   * POST /api/reports/generate
   * Génère un nouveau rapport
   */
  generateReport = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let reportId: string | null = null;

    try {
      // Valider les données d'entrée
      const validationResult = GenerateReportRequestSchema.safeParse(req.body);

      if (!validationResult.success) {
        res.status(400).json({
          error: 'Validation error',
          details: validationResult.error.errors
        });
        return;
      }

      const requestData: GenerateReportRequest = validationResult.data;
      reportId = uuidv4();

      logger.info(`Starting report generation`, {
        reportId,
        projectName: requestData.projectName,
        format: requestData.format
      });

      // Créer le rapport initial avec statut "pending"
      const initialReport: Report = {
        reportId,
        projectName: requestData.projectName,
        vulnerabilities: [],
        metrics: {
          total: 0,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          byCategory: {},
          securityScore: 100,
          topAffectedFiles: []
        },
        scanMetadata: {
          startTime: new Date().toISOString(),
          tools: this.extractToolNames(requestData.scanResults)
        },
        generatedAt: new Date().toISOString(),
        format: requestData.format,
        status: 'pending'
      };

      reportsStore.set(reportId, initialReport);

      // Répondre immédiatement avec le statut pending
      res.status(202).json({
        reportId,
        status: 'pending',
        message: 'Report generation started'
      });

      // Continuer la génération en arrière-plan
      this.processReport(reportId, requestData).catch(error => {
        logger.error('Background report generation failed', { error, reportId });
      });

    } catch (error) {
      logger.error('Failed to start report generation', { error, reportId });
      next(error);
    }
  };

  /**
   * POST /api/reports/upload
   * Génère un rapport à partir d'un fichier JSON uploadé
   */
  generateFromFile = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let reportId: string | null = null;
    let uploadedFilePath: string | null = null;

    try {
      // Vérifier si un fichier a été uploadé
      if (!req.file) {
        res.status(400).json({
          error: 'No file uploaded',
          message: 'Please upload a JSON file containing scan results'
        });
        return;
      }

      uploadedFilePath = req.file.path;
      logger.info('File uploaded', {
        filename: req.file.originalname,
        size: req.file.size,
        path: uploadedFilePath
      });

      // Lire et parser le fichier JSON
      const fileContent = await fs.readFile(uploadedFilePath, 'utf-8');
      let requestData: GenerateReportRequest;

      try {
        requestData = JSON.parse(fileContent);
      } catch (parseError) {
        res.status(400).json({
          error: 'Invalid JSON',
          message: 'The uploaded file is not valid JSON'
        });
        // Nettoyer le fichier uploadé
        await fs.unlink(uploadedFilePath).catch(() => { });
        return;
      }

      // Valider les données
      const validationResult = GenerateReportRequestSchema.safeParse(requestData);

      if (!validationResult.success) {
        res.status(400).json({
          error: 'Validation error',
          message: 'The JSON file does not match the expected schema',
          details: validationResult.error.errors
        });
        // Nettoyer le fichier uploadé
        await fs.unlink(uploadedFilePath).catch(() => { });
        return;
      }

      requestData = validationResult.data;
      reportId = uuidv4();

      logger.info(`Starting report generation from uploaded file`, {
        reportId,
        projectName: requestData.projectName,
        format: requestData.format,
        originalFilename: req.file.originalname
      });

      // Créer le rapport initial avec statut "pending"
      const initialReport: Report = {
        reportId,
        projectName: requestData.projectName,
        vulnerabilities: [],
        metrics: {
          total: 0,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          byCategory: {},
          securityScore: 100,
          topAffectedFiles: []
        },
        scanMetadata: {
          startTime: new Date().toISOString(),
          tools: this.extractToolNames(requestData.scanResults)
        },
        generatedAt: new Date().toISOString(),
        format: requestData.format,
        status: 'pending'
      };

      reportsStore.set(reportId, initialReport);

      // Répondre immédiatement avec le statut pending
      res.status(202).json({
        reportId,
        status: 'pending',
        message: 'Report generation started from uploaded file',
        uploadedFile: req.file.originalname
      });

      // Continuer la génération en arrière-plan
      this.processReport(reportId, requestData).catch(error => {
        logger.error('Background report generation failed', { error, reportId });
      });

      // Nettoyer le fichier uploadé après traitement
      await fs.unlink(uploadedFilePath).catch(() => { });

    } catch (error) {
      logger.error('Failed to process uploaded file', { error, reportId });
      // Nettoyer le fichier uploadé en cas d'erreur
      if (uploadedFilePath) {
        await fs.unlink(uploadedFilePath).catch(() => { });
      }
      next(error);
    }
  };

  /**
   * POST /api/reports/generate-from-folder
   * Génère un rapport à partir de tous les fichiers JSON dans le dossier input
   */
  generateFromFolder = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let reportId: string | null = null;

    try {
      const { projectName, format = 'pdf', options, clearAfterGeneration = false } = req.body;

      if (!projectName) {
        res.status(400).json({
          error: 'Missing projectName',
          message: 'Please provide a projectName in the request body'
        });
        return;
      }

      // Lire tous les fichiers du dossier input
      const { files, errors } = await fileWatcherService.readAllInputFiles();

      if (files.length === 0) {
        res.status(400).json({
          error: 'No valid scan files found',
          message: `No JSON files found in the input directory: ${fileWatcherService.getInputDirectory()}`,
          errors,
          hint: 'Place your scan result JSON files in the input folder and try again'
        });
        return;
      }

      // Combiner les fichiers en une requête
      const requestData = fileWatcherService.combineFilesToRequest(
        files,
        projectName,
        format,
        options
      );

      reportId = uuidv4();

      logger.info(`Starting report generation from input folder`, {
        reportId,
        projectName,
        format,
        filesCount: files.length,
        files: files.map(f => ({ filename: f.filename, type: f.type, tool: f.tool }))
      });

      // Créer le rapport initial avec statut "pending"
      const initialReport: Report = {
        reportId,
        projectName: requestData.projectName,
        vulnerabilities: [],
        metrics: {
          total: 0,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          byCategory: {},
          securityScore: 100,
          topAffectedFiles: []
        },
        scanMetadata: {
          startTime: new Date().toISOString(),
          tools: this.extractToolNames(requestData.scanResults)
        },
        generatedAt: new Date().toISOString(),
        format: requestData.format,
        status: 'pending'
      };

      reportsStore.set(reportId, initialReport);

      // Répondre immédiatement avec le statut pending
      res.status(202).json({
        reportId,
        status: 'pending',
        message: 'Report generation started from input folder',
        filesProcessed: files.map(f => ({
          filename: f.filename,
          type: f.type,
          tool: f.tool
        })),
        errors: errors.length > 0 ? errors : undefined
      });

      // Continuer la génération en arrière-plan
      this.processReport(reportId, requestData).catch(error => {
        logger.error('Background report generation failed', { error, reportId });
      });

      // Nettoyer le dossier input si demandé
      if (clearAfterGeneration) {
        const deleted = await fileWatcherService.clearInputDirectory();
        logger.info(`Cleared ${deleted} files from input directory`);
      }

    } catch (error) {
      logger.error('Failed to generate report from folder', { error, reportId });
      next(error);
    }
  };

  /**
   * GET /api/reports/input-files
   * Liste les fichiers présents dans le dossier input
   */
  listInputFiles = async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { files, errors } = await fileWatcherService.readAllInputFiles();

      res.json({
        inputDirectory: fileWatcherService.getInputDirectory(),
        filesCount: files.length,
        files: files.map(f => ({
          filename: f.filename,
          type: f.type,
          tool: f.tool
        })),
        errors: errors.length > 0 ? errors : undefined
      });

    } catch (error) {
      logger.error('Failed to list input files', { error });
      next(error);
    }
  };

  /**
   * DELETE /api/reports/input-files
   * Vide le dossier input
   */
  clearInputFiles = async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const deleted = await fileWatcherService.clearInputDirectory();

      res.json({
        message: `Deleted ${deleted} files from input directory`,
        deletedCount: deleted
      });

    } catch (error) {
      logger.error('Failed to clear input files', { error });
      next(error);
    }
  };

  /**
   * POST /api/reports/generate-from-scan
   * Génère un rapport à partir des données MongoDB pour un scan_id
   */
  generateFromScan = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    let reportId: string | null = null;

    try {
      const { scanId, format = 'pdf', options } = req.body;

      if (!scanId) {
        res.status(400).json({
          error: 'Missing scanId',
          message: 'Please provide a scanId in the request body'
        });
        return;
      }

      // Vérifier la connexion MongoDB
      if (!mongoClient.isConnected()) {
        await mongoClient.connect();
      }

      // Récupérer toutes les données du scan depuis MongoDB
      const scanData = await mongoClient.getAllResultsForScan(scanId);

      if (!scanData.apk && !scanData.secrets && !scanData.crypto && !scanData.network) {
        res.status(404).json({
          error: 'Scan not found',
          message: `No results found for scan_id: ${scanId}`
        });
        return;
      }

      // Construire les scanResults à partir des données MongoDB
      const scanResults: any = {};

      // Convertir les résultats crypto
      if (scanData.crypto?.vulnerabilities) {
        scanResults.cryptoCheck = scanData.crypto.vulnerabilities.map((v: any) => ({
          ruleId: v.vulnerability || v.type || 'CRYPTO_ISSUE',
          severity: this.mapSeverityFromCWE(v.cwe) || this.mapSeverity(v.severity) || 'high',
          message: v.vulnerability || v.description || v.message,
          file: v.file || v.filePath,
          line: v.line || v.lineNumber || 1,
          recommendation: v.recommendation,
          cwe: v.cwe
        }));
      }

      // Convertir les résultats secrets
      if (scanData.secrets?.secrets) {
        scanResults.secretHunter = scanData.secrets.secrets.map((s: any) => ({
          ruleId: s.rule_id || s.type || 'SECRET_EXPOSED',
          severity: this.mapSeverity(s.severity) || 'high',
          message: s.description || s.match || `Secret found: ${s.type}`,
          file: s.file_path || s.file || s.filePath,
          line: s.line_number || s.line || 1
        }));
      }

      // Convertir les résultats network
      if (scanData.network?.analysis?.security_issues) {
        scanResults.networkInspector = scanData.network.analysis.security_issues.map((i: any) => ({
          ruleId: i.type || 'NETWORK_ISSUE',
          severity: this.mapSeverity(i.severity) || 'medium',
          message: i.description || i.message,
          file: i.file || 'network-analysis',
          line: i.line || 1
        }));
      }

      // Convertir les résultats APK (manifest issues)
      if (scanData.apk?.results?.manifest_issues) {
        scanResults.apkScanner = scanData.apk.results.manifest_issues.map((m: any) => ({
          ruleId: m.type || 'MANIFEST_ISSUE',
          severity: this.mapSeverity(m.severity) || 'medium',
          message: m.message,
          file: 'AndroidManifest.xml',
          line: 1
        }));
      }

      const projectName = scanData.apk?.results?.app_name ||
        scanData.apk?.results?.package_name ||
        `Scan ${scanId}`;

      reportId = uuidv4();

      logger.info(`Starting report generation from MongoDB`, {
        reportId,
        scanId,
        projectName,
        format,
        resultsFound: {
          apk: !!scanData.apk,
          secrets: !!scanData.secrets,
          crypto: !!scanData.crypto,
          network: !!scanData.network
        }
      });

      // Créer la requête de génération
      const requestData: GenerateReportRequest = {
        projectName,
        scanId,
        scanResults,
        format,
        options
      };

      // Créer le rapport initial avec statut "pending"
      const initialReport: Report = {
        reportId,
        projectName,
        vulnerabilities: [],
        metrics: {
          total: 0,
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          byCategory: {},
          securityScore: 100,
          topAffectedFiles: []
        },
        scanMetadata: {
          startTime: new Date().toISOString(),
          tools: Object.keys(scanResults)
        },
        generatedAt: new Date().toISOString(),
        format,
        status: 'pending'
      };

      reportsStore.set(reportId, initialReport);

      // Répondre immédiatement avec le statut pending
      res.status(202).json({
        reportId,
        scanId,
        status: 'pending',
        message: 'Report generation started from MongoDB data',
        dataFound: {
          apk: !!scanData.apk,
          secrets: scanData.secrets?.secrets?.length || 0,
          crypto: scanData.crypto?.vulnerabilities?.length || 0,
          network: scanData.network?.analysis?.security_issues?.length || 0
        }
      });

      // Continuer la génération en arrière-plan
      this.processReport(reportId, requestData).catch(error => {
        logger.error('Background report generation failed', { error, reportId });
      });

    } catch (error) {
      logger.error('Failed to generate report from scan', { error, reportId });
      next(error);
    }
  };

  /**
   * Helper pour mapper les sévérités
   */
  private mapSeverity(severity: string): string {
    const s = (severity || 'info').toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'medium' || s === 'moderate') return 'medium';
    if (s === 'low') return 'low';
    return 'info';
  }

  /**
   * Helper pour mapper les sévérités depuis CWE
   */
  private mapSeverityFromCWE(cwe: string): string | null {
    if (!cwe) return null;
    // CWE-327 (Broken Crypto), CWE-330 (Weak Random) = HIGH
    // CWE-798 (Hardcoded Credentials) = CRITICAL
    // CWE-321 (Hardcoded Key) = HIGH
    const highSeverityCWEs = ['CWE-327', 'CWE-330', 'CWE-321', 'CWE-295'];
    const criticalCWEs = ['CWE-798', 'CWE-259'];

    if (criticalCWEs.includes(cwe)) return 'critical';
    if (highSeverityCWEs.includes(cwe)) return 'high';
    return null;
  }

  /**
   * Traite la génération du rapport en arrière-plan
   */
  private async processReport(reportId: string, requestData: GenerateReportRequest): Promise<void> {
    const startTime = Date.now();

    try {
      // Mettre à jour le statut
      this.updateReportStatus(reportId, 'processing');

      // 1. Agréger les résultats de tous les outils
      logger.debug('Aggregating scan results', { reportId });
      const aggregatedVulns = aggregatorService.aggregateResults(requestData.scanResults);

      // 2. Dédupliquer les vulnérabilités
      logger.debug('Deduplicating vulnerabilities', { reportId });
      const deduplicatedVulns = deduplicatorService.deduplicate(aggregatedVulns);

      // 3. Calculer les métriques
      logger.debug('Calculating metrics', { reportId });
      const metrics = metricsService.calculateMetrics(deduplicatedVulns);

      // 4. Préparer les options
      const options: ReportOptions = ReportOptionsSchema.parse(requestData.options || {});

      // 5. Construire le rapport complet
      const report: Report = {
        reportId,
        projectName: requestData.projectName,
        vulnerabilities: deduplicatedVulns,
        metrics,
        scanMetadata: {
          startTime: new Date().toISOString(),
          endTime: new Date().toISOString(),
          duration: Math.round((Date.now() - startTime) / 1000),
          tools: this.extractToolNames(requestData.scanResults)
        },
        generatedAt: new Date().toISOString(),
        format: requestData.format,
        status: 'processing'
      };

      // 6. Générer le fichier selon le format demandé
      let filePath: string;

      try {
        switch (requestData.format) {
          case 'pdf':
            try {
              filePath = await pdfGeneratorService.generatePdf(report, options);
            } catch (pdfErr) {
              logger.error('PDF generation failed, attempting JSON fallback', { error: String(pdfErr), reportId });
              // Try to fall back to JSON so users still have a downloadable report
              report.format = 'json';
              const jsonPath = await jsonExporterService.exportToJson(report, {
                pretty: true,
                includeRawData: options.includeRawFindings
              });

              // Attempt to convert the generated JSON to PDF using a simple renderer (pdfkit)
              try {
                const pdfPath = jsonPath.replace(/\.json$/i, '.pdf');
                const outPdf = await (await import('../services/jsonToPdf.service')).jsonToPdfService.convert(jsonPath, pdfPath);
                filePath = outPdf;
                report.format = 'pdf';
                logger.info('Converted JSON to PDF fallback successfully', { pdfPath: outPdf });
              } catch (convErr) {
                logger.error('JSON to PDF fallback failed', { error: String(convErr), reportId });
                // Keep JSON file as final artifact
                filePath = jsonPath;
              }
            }
            break;
          case 'json':
            filePath = await jsonExporterService.exportToJson(report, {
              pretty: true,
              includeRawData: options.includeRawFindings
            });
            break;
          case 'sarif':
            filePath = await sarifExporterService.exportToSarif(report);
            break;
          default:
            throw new Error(`Unsupported format: ${requestData.format}`);
        }
      } catch (err) {
        throw err;
      }

      // 7. Mettre à jour le rapport avec le statut final
      report.status = 'completed';
      report.filePath = filePath;
      report.scanMetadata.duration = Math.round((Date.now() - startTime) / 1000);

      reportsStore.set(reportId, report);

      // 8. Sauvegarder dans MongoDB
      try {
        await mongoClient.saveReport(requestData.scanId || reportId, {
          reportId: report.reportId,
          format: report.format,
          path: report.filePath,
          summary: report.metrics,
          vulnerabilitiesCount: report.metrics.total
        });

        // Update Scan Stage to completed
        if (requestData.scanId) {
          await mongoClient.updateScanStage(requestData.scanId, 'completed');
        }

        logger.info('Report saved to MongoDB', { reportId, scanId: requestData.scanId });
      } catch (dbError) {
        logger.warn('Failed to save report to MongoDB', { error: dbError, reportId });
      }

      logger.info('Report generation completed', {
        reportId,
        format: requestData.format,
        duration: report.scanMetadata.duration,
        vulnerabilities: metrics.total
      });

    } catch (error) {
      logger.error('Report generation failed', { error, reportId });

      // Mettre à jour le statut en échec
      const existingReport = reportsStore.get(reportId);
      if (existingReport) {
        existingReport.status = 'failed';
        existingReport.error = error instanceof Error ? error.message : 'Unknown error';
        reportsStore.set(reportId, existingReport);
      }

      // Update Scan Stage to failed
      if (requestData.scanId) {
        try {
          await mongoClient.updateScanStage(requestData.scanId, 'failed');
        } catch (e) {
          logger.error('Failed to update scan stage to failed', { error: e });
        }
      }
    }
  }

  /**
   * GET /api/reports/:reportId
   * Récupère les informations d'un rapport
   */
  getReportInfo = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { reportId } = req.params;

      const report = reportsStore.get(reportId);

      if (!report) {
        res.status(404).json({
          error: 'Report not found',
          reportId
        });
        return;
      }

      // Retourner les infos sans les vulnérabilités complètes
      res.json({
        reportId: report.reportId,
        projectName: report.projectName,
        status: report.status,
        format: report.format,
        metrics: report.status === 'completed' ? report.metrics : undefined,
        scanMetadata: report.scanMetadata,
        generatedAt: report.generatedAt,
        error: report.error
      });

    } catch (error) {
      logger.error('Failed to get report info', { error });
      next(error);
    }
  };

  /**
   * GET /api/reports/:reportId/download
   * Télécharge le fichier du rapport
   */
  downloadReport = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { reportId } = req.params;
      let reportPath: string | null = null;
      let reportFormat: string = 'pdf';
      let projectName: string = 'Security Report';

      // Check memory first
      const memoryReport = reportsStore.get(reportId);
      if (memoryReport && memoryReport.filePath) {
        reportPath = memoryReport.filePath;
        reportFormat = memoryReport.format;
        projectName = memoryReport.projectName;
      } else {
        // Fallback to MongoDB
        if (!mongoClient.isConnected()) await mongoClient.connect();
        // Since getReport searches by scanId, but we need by reportId, we might need a better query
        // Actually safeReport uses upsert on scan_id. 
        // We probably stored report_id in the doc.
        // Let's rely on listReports approach or add getReportById
        // For now, let's assume valid file path check if we can find it via scan metadata?
        // Actually, let's look at listReports first.
        // If we change listReports to return mongo docs, frontend has reportId.
        // We need a way to look up specific report by reportId in Mongo.
        // The current mongoClient.getReport(scanId) is limited.
        // Let's blindly try to find the file if we can't find the record? No.
        // Let's implement a quick lookup in the collection directly here or update MongoDB class.
        // Access collection directly if possible or iterate?
        // Better: Update MongoDBClient to support getReportByReportId.
        // But for this patch, let's access collection via public getter if available?
        // mongoClient.reportsCollection is public but explicit helper is cleaner
        const doc = await mongoClient.getReportById(reportId);
        if (doc) {
          const d = doc as any; // Force cast
          reportPath = d.report_path;
          reportFormat = d.report_format;
          // projectName isn't in DB doc? Schema in saveReport only has scanId.
          // We can fetch scan doc to get project name? or default.
          projectName = `Report-${reportId}`;
        }
      }

      if (!reportPath) {
        res.status(404).json({ error: 'Report not found (Memory/DB miss)', reportId });
        return;
      }

      // If the client requests a PDF but we only have JSON, attempt on-demand conversion
      if (String(req.query.forcePdf) === 'true' && reportFormat === 'json') {
        try {
          const pdfPath = reportPath.replace(/\.json$/i, '.pdf');
          const { jsonToPdfService } = await import('../services/jsonToPdf.service');
          await jsonToPdfService.convert(reportPath, pdfPath);
          reportPath = pdfPath;
          reportFormat = 'pdf';
          logger.info('On-demand JSON -> PDF conversion completed', { reportId, pdfPath });
        } catch (convErr) {
          logger.error('Failed to convert JSON report to PDF on-demand', { error: String(convErr), reportId });
          res.status(500).json({ error: 'Failed to convert report to PDF' });
          return;
        }
      }

      if (memoryReport && (memoryReport.status === 'pending' || memoryReport.status === 'processing')) {
        res.status(202).json({
          error: 'Report is still being generated',
          status: memoryReport.status,
          reportId
        });
        return;
      }

      // Skip status check if loaded from DB (assumed completed)
      if (memoryReport && memoryReport.status === 'failed') {
        res.status(500).json({
          error: 'Report generation failed',
          details: memoryReport.error,
          reportId
        });
        return;
      }

      if (!reportPath) {
        res.status(500).json({ error: 'Report file path missing', reportId });
        return;
      }
      // Vérifier que le fichier existe
      try {
        await fs.access(reportPath);
      } catch {
        res.status(404).json({
          error: 'Report file has been deleted or moved',
          reportId
        });
        return;
      }

      // Déterminer le type MIME et l'extension
      const mimeTypes: Record<string, string> = {
        pdf: 'application/pdf',
        json: 'application/json',
        sarif: 'application/json'
      };

      const contentType = mimeTypes[reportFormat] || 'application/octet-stream';
      const extension = reportFormat === 'sarif' ? 'sarif.json' : reportFormat;
      const filename = `${projectName}-security-report.${extension}`;

      // Envoyer le fichier
      const disposition = req.query.inline === 'true' ? 'inline' : 'attachment';
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `${disposition}; filename="${filename}"`);

      const fileContent = await fs.readFile(reportPath);
      res.send(fileContent);

      logger.info('Report downloaded', { reportId, format: reportFormat });

    } catch (error) {
      logger.error('Failed to download report', { error });
      next(error);
    }
  };

  /**
   * GET /api/reports/:reportId/vulnerabilities
   * Récupère la liste des vulnérabilités d'un rapport
   */
  getVulnerabilities = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { reportId } = req.params;
      const { severity, category, page = '1', limit = '20' } = req.query;

      const report = reportsStore.get(reportId);

      if (!report) {
        res.status(404).json({
          error: 'Report not found',
          reportId
        });
        return;
      }

      if (report.status !== 'completed') {
        res.status(202).json({
          error: 'Report is not ready',
          status: report.status
        });
        return;
      }

      // Filtrer les vulnérabilités
      let vulnerabilities = [...report.vulnerabilities];

      if (severity && typeof severity === 'string') {
        vulnerabilities = vulnerabilities.filter(v => v.severity === severity);
      }

      if (category && typeof category === 'string') {
        vulnerabilities = vulnerabilities.filter(v => v.category === category);
      }

      // Pagination
      const pageNum = parseInt(page as string, 10);
      const limitNum = parseInt(limit as string, 10);
      const startIndex = (pageNum - 1) * limitNum;
      const endIndex = startIndex + limitNum;

      const paginatedVulns = vulnerabilities.slice(startIndex, endIndex);

      res.json({
        total: vulnerabilities.length,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(vulnerabilities.length / limitNum),
        data: paginatedVulns
      });

    } catch (error) {
      logger.error('Failed to get vulnerabilities', { error });
      next(error);
    }
  };

  /**
   * DELETE /api/reports/:reportId
   * Supprime un rapport
   */
  deleteReport = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const { reportId } = req.params;

      const report = reportsStore.get(reportId);

      if (!report) {
        res.status(404).json({
          error: 'Report not found',
          reportId
        });
        return;
      }

      // Supprimer le fichier si existant
      if (report.filePath) {
        try {
          await fs.unlink(report.filePath);
        } catch (error) {
          logger.warn('Failed to delete report file', { error, filePath: report.filePath });
        }
      }

      // Supprimer du store
      reportsStore.delete(reportId);

      res.status(204).send();

      logger.info('Report deleted', { reportId });

    } catch (error) {
      logger.error('Failed to delete report', { error });
      next(error);
    }
  };

  /**
   * GET /api/reports
   * Liste tous les rapports
   */
  listReports = async (_req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Fetch from MongoDB for persistence
      if (!mongoClient.isConnected()) await mongoClient.connect();
      const docs = await mongoClient.getAllReports(100);

      const reports = docs.map(doc => ({
        reportId: doc.report_id,
        // Project name might be missing in DB save, fallback or fetch scan
        projectName: doc.project_name || doc.scan_id || 'Security Report',
        status: doc.status,
        format: doc.report_format,
        generatedAt: doc.created_at,
        scanId: doc.scan_id,
        metrics: {
          total: doc.vulnerabilities_count || 0,
          securityScore: 0 // Not persisted currently
        }
      }));

      // Merge with memory store for latest status on active jobs?
      // For simplicity, just return DB records as they are "completed" usually.
      // If pending, they might not be in DB yet? 
      // saveReport is called on completion.
      // So pending jobs are ONLY in memory.
      // We should append memory-only jobs.

      const memoryReports = Array.from(reportsStore.values()).filter(r => !docs.find(d => d.report_id === r.reportId));
      const memoryMapped = memoryReports.map(report => ({
        reportId: report.reportId,
        projectName: report.projectName,
        status: report.status,
        format: report.format,
        generatedAt: report.generatedAt,
        metrics: { total: report.metrics.total, securityScore: report.metrics.securityScore }
      }));

      const allReports = [...reports, ...memoryMapped];

      // Sort by date desc
      allReports.sort((a, b) => new Date(b.generatedAt).getTime() - new Date(a.generatedAt).getTime());

      res.json({
        total: allReports.length,
        data: allReports
      });

    } catch (error) {
      logger.error('Failed to list reports', { error });
      next(error);
    }
  };

  /**
   * Extrait les noms des outils depuis les résultats de scan
   */
  private extractToolNames(scanResults: GenerateReportRequest['scanResults']): string[] {
    const tools = new Set<string>();

    if (scanResults.sast) {
      scanResults.sast.forEach(s => tools.add(s.tool));
    }
    if (scanResults.sca) {
      scanResults.sca.forEach(s => tools.add(s.tool));
    }
    if (scanResults.secrets) {
      scanResults.secrets.forEach(s => tools.add(s.tool));
    }
    if (scanResults.dast) {
      scanResults.dast.forEach(s => tools.add(s.tool));
    }

    return Array.from(tools);
  }

  /**
   * Met à jour le statut d'un rapport
   */
  private updateReportStatus(reportId: string, status: ReportStatus): void {
    const report = reportsStore.get(reportId);
    if (report) {
      report.status = status;
      reportsStore.set(reportId, report);
    }
  }

  /**
   * Nettoie les rapports expirés
   */
  async cleanupExpiredReports(): Promise<number> {
    const retentionHours = parseInt(process.env.REPORT_RETENTION_HOURS || '24', 10);
    const cutoffTime = Date.now() - (retentionHours * 60 * 60 * 1000);
    let deletedCount = 0;

    for (const [reportId, report] of reportsStore.entries()) {
      const reportTime = new Date(report.generatedAt).getTime();

      if (reportTime < cutoffTime) {
        // Supprimer le fichier
        if (report.filePath) {
          try {
            await fs.unlink(report.filePath);
          } catch {
            // Ignorer si le fichier n'existe pas
          }
        }

        // Supprimer du store
        reportsStore.delete(reportId);
        deletedCount++;
      }
    }

    if (deletedCount > 0) {
      logger.info(`Cleaned up ${deletedCount} expired reports`);
    }

    return deletedCount;
  }
}

export const reportController = new ReportController();
