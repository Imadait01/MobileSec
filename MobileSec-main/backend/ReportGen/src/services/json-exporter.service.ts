import fs from 'fs/promises';
import path from 'path';
import logger from '../utils/logger';
import { Report, Vulnerability } from '../models';

export interface JsonExportOptions {
  pretty?: boolean;
  includeRawData?: boolean;
}

export class JsonExporterService {
  private tempDir: string;

  constructor() {
    this.tempDir = process.env.TEMP_DIR || './tmp';
  }

  /**
   * Exporte un rapport au format JSON
   */
  async exportToJson(report: Report, options: JsonExportOptions = {}): Promise<string> {
    logger.info(`Exporting report to JSON`, { reportId: report.reportId });

    try {
      // Préparer les données pour l'export
      const exportData = this.prepareExportData(report, options);

      // Sérialiser en JSON
      const jsonContent = options.pretty
        ? JSON.stringify(exportData, null, 2)
        : JSON.stringify(exportData);

      // Écrire le fichier
      const outputPath = path.join(this.tempDir, `${report.reportId}.json`);
      await fs.writeFile(outputPath, jsonContent, 'utf-8');

      logger.info(`JSON export completed`, { reportId: report.reportId, outputPath });

      return outputPath;
    } catch (error) {
      logger.error('Failed to export to JSON', { error, reportId: report.reportId });
      throw error;
    }
  }

  /**
   * Prépare les données pour l'export JSON
   */
  private prepareExportData(report: Report, options: JsonExportOptions): Record<string, unknown> {
    // Clone profond pour éviter de modifier l'original
    const exportData: Record<string, unknown> = {
      $schema: 'https://reportgen.security/schemas/report-v1.json',
      version: '1.0.0',
      reportId: report.reportId,
      projectName: report.projectName,
      generatedAt: report.generatedAt,
      status: report.status,
      format: 'json',

      // Métadonnées du scan
      scanMetadata: {
        ...report.scanMetadata,
        toolsUsed: report.scanMetadata.tools.length,
        scanDurationSeconds: report.scanMetadata.duration
      },

      // Métriques agrégées
      metrics: {
        summary: {
          totalVulnerabilities: report.metrics.total,
          securityScore: report.metrics.securityScore,
          riskLevel: this.calculateRiskLevel(report.metrics)
        },
        distribution: {
          bySeverity: report.metrics.bySeverity,
          byCategory: report.metrics.byCategory
        },
        topAffectedFiles: report.metrics.topAffectedFiles
      },

      // Vulnérabilités
      vulnerabilities: report.vulnerabilities.map((vuln: Vulnerability) => {
        const exportVuln: Record<string, unknown> = {
          id: vuln.id,
          title: vuln.title,
          severity: vuln.severity,
          category: vuln.category,
          description: vuln.description,
          location: vuln.location,
          source: vuln.source,
          confidence: vuln.confidence,
          detectedBy: vuln.detectedBy
        };

        // Champs optionnels
        if (vuln.cwe) exportVuln.cwe = vuln.cwe;
        if (vuln.cvss) exportVuln.cvss = vuln.cvss;
        if (vuln.recommendation) exportVuln.recommendation = vuln.recommendation;
        if (vuln.references.length > 0) exportVuln.references = vuln.references;

        // Données brutes si demandé
        if (options.includeRawData && vuln.rawData) {
          exportVuln.rawData = vuln.rawData;
        }

        return exportVuln;
      }),

      // Statistiques supplémentaires
      statistics: this.calculateStatistics(report)
    };

    return exportData;
  }

  /**
   * Calcule le niveau de risque
   */
  private calculateRiskLevel(metrics: Report['metrics']): string {
    if (metrics.bySeverity.critical > 0) return 'CRITICAL';
    if (metrics.bySeverity.high > 5) return 'CRITICAL';
    if (metrics.bySeverity.high > 0) return 'HIGH';
    if (metrics.bySeverity.medium > 10) return 'HIGH';
    if (metrics.bySeverity.medium > 0) return 'MEDIUM';
    if (metrics.bySeverity.low > 0) return 'LOW';
    return 'NONE';
  }

  /**
   * Calcule des statistiques supplémentaires
   */
  private calculateStatistics(report: Report): Record<string, unknown> {
    const vulns = report.vulnerabilities;

    // Sources de détection
    const sourceCount: Record<string, number> = {};
    for (const vuln of vulns) {
      sourceCount[vuln.source] = (sourceCount[vuln.source] || 0) + 1;
    }

    // Vulnérabilités avec CVSS
    const vulnsWithCVSS = vulns.filter((v: Vulnerability) => v.cvss?.score);
    const avgCVSS = vulnsWithCVSS.length > 0
      ? vulnsWithCVSS.reduce((sum: number, v: Vulnerability) => sum + (v.cvss?.score || 0), 0) / vulnsWithCVSS.length
      : null;

    // CWE les plus fréquents
    const cweCount: Record<string, number> = {};
    for (const vuln of vulns) {
      if (vuln.cwe) {
        cweCount[vuln.cwe] = (cweCount[vuln.cwe] || 0) + 1;
      }
    }

    const topCWEs = Object.entries(cweCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([cwe, count]) => ({ cwe, count }));

    // Confiance
    const confidenceCount: Record<string, number> = {
      high: 0,
      medium: 0,
      low: 0
    };
    for (const vuln of vulns) {
      confidenceCount[vuln.confidence]++;
    }

    return {
      bySource: sourceCount,
      byConfidence: confidenceCount,
      averageCVSS: avgCVSS ? Math.round(avgCVSS * 10) / 10 : null,
      topCWEs,
      uniqueFiles: new Set(vulns.map((v: Vulnerability) => v.location.file)).size,
      vulnsWithRecommendation: vulns.filter((v: Vulnerability) => v.recommendation).length,
      vulnsWithCVSS: vulnsWithCVSS.length
    };
  }

  /**
   * Retourne les données JSON sans les écrire (pour streaming)
   */
  getJsonData(report: Report, options: JsonExportOptions = {}): string {
    const exportData = this.prepareExportData(report, options);
    return options.pretty
      ? JSON.stringify(exportData, null, 2)
      : JSON.stringify(exportData);
  }
}

export const jsonExporterService = new JsonExporterService();
