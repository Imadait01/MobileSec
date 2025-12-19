import fs from 'fs/promises';
import path from 'path';
import logger from '../utils/logger';
import { Report, Vulnerability, Severity } from '../models';

// Interface SARIF 2.1.0
interface SarifLog {
  version: '2.1.0';
  $schema: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  invocations?: SarifInvocation[];
  artifacts?: SarifArtifact[];
}

interface SarifTool {
  driver: SarifToolDriver;
}

interface SarifToolDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  help?: { text: string; markdown?: string };
  helpUri?: string;
  defaultConfiguration?: {
    level: SarifLevel;
    enabled: boolean;
  };
  properties?: Record<string, unknown>;
}

interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine?: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
      snippet?: { text: string };
    };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
  toolExecutionNotifications?: SarifNotification[];
}

interface SarifNotification {
  level: SarifLevel;
  message: { text: string };
}

interface SarifArtifact {
  location: {
    uri: string;
  };
}

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export class SarifExporterService {
  private tempDir: string;

  constructor() {
    this.tempDir = process.env.TEMP_DIR || './tmp';
  }

  /**
   * Exporte un rapport au format SARIF 2.1.0
   */
  async exportToSarif(report: Report): Promise<string> {
    logger.info(`Exporting report to SARIF`, { reportId: report.reportId });

    try {
      const sarifLog = this.buildSarifLog(report);

      // Sérialiser en JSON
      const sarifContent = JSON.stringify(sarifLog, null, 2);

      // Écrire le fichier
      const outputPath = path.join(this.tempDir, `${report.reportId}.sarif`);
      await fs.writeFile(outputPath, sarifContent, 'utf-8');

      logger.info(`SARIF export completed`, { reportId: report.reportId, outputPath });

      return outputPath;
    } catch (error) {
      logger.error('Failed to export to SARIF', { error, reportId: report.reportId });
      throw error;
    }
  }

  /**
   * Construit l'objet SARIF complet
   */
  private buildSarifLog(report: Report): SarifLog {
    // Extraire les règles uniques
    const rules = this.extractRules(report.vulnerabilities);
    const ruleIndexMap = new Map<string, number>();
    rules.forEach((rule, index) => ruleIndexMap.set(rule.id, index));

    // Construire les résultats
    const results = report.vulnerabilities.map(vuln =>
      this.buildSarifResult(vuln, ruleIndexMap)
    );

    // Construire les artifacts (fichiers uniques)
    const artifacts = this.extractArtifacts(report.vulnerabilities);

    // Construire l'objet SARIF
    const sarifLog: SarifLog = {
      version: '2.1.0',
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'ReportGen Security Scanner',
              version: '1.0.0',
              informationUri: 'https://github.com/reportgen/reportgen',
              rules
            }
          },
          results,
          invocations: [
            {
              executionSuccessful: true,
              startTimeUtc: report.scanMetadata.startTime,
              endTimeUtc: report.scanMetadata.endTime
            }
          ],
          artifacts
        }
      ]
    };

    return sarifLog;
  }

  /**
   * Extrait les règles uniques des vulnérabilités
   */
  private extractRules(vulnerabilities: Vulnerability[]): SarifRule[] {
    const rulesMap = new Map<string, SarifRule>();

    for (const vuln of vulnerabilities) {
      const ruleId = this.generateRuleId(vuln);

      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: vuln.title,
          shortDescription: {
            text: vuln.title
          },
          fullDescription: {
            text: vuln.description
          },
          help: vuln.recommendation ? {
            text: vuln.recommendation,
            markdown: `**Recommandation:** ${vuln.recommendation}`
          } : undefined,
          helpUri: vuln.references[0],
          defaultConfiguration: {
            level: this.mapSeverityToLevel(vuln.severity),
            enabled: true
          },
          properties: {
            category: vuln.category,
            cwe: vuln.cwe,
            security_severity: this.getSecuritySeverity(vuln.severity)
          }
        });
      }
    }

    return Array.from(rulesMap.values());
  }

  /**
   * Génère un ID de règle unique
   */
  private generateRuleId(vuln: Vulnerability): string {
    if (vuln.cwe) {
      return vuln.cwe;
    }

    // Générer un ID basé sur la catégorie et un hash du titre
    const sanitizedTitle = vuln.title
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '-')
      .substring(0, 30);

    return `${vuln.category}/${sanitizedTitle}`;
  }

  /**
   * Construit un résultat SARIF à partir d'une vulnérabilité
   */
  private buildSarifResult(
    vuln: Vulnerability,
    ruleIndexMap: Map<string, number>
  ): SarifResult {
    const ruleId = this.generateRuleId(vuln);

    const result: SarifResult = {
      ruleId,
      ruleIndex: ruleIndexMap.get(ruleId),
      level: this.mapSeverityToLevel(vuln.severity),
      message: {
        text: this.buildResultMessage(vuln)
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: this.normalizeUri(vuln.location.file),
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: vuln.location.line,
              startColumn: vuln.location.column,
              endLine: vuln.location.endLine || vuln.location.line,
              endColumn: vuln.location.endColumn,
              snippet: vuln.location.codeSnippet ? {
                text: vuln.location.codeSnippet
              } : undefined
            }
          }
        }
      ],
      partialFingerprints: {
        primaryLocationLineHash: this.generateFingerprint(vuln)
      },
      properties: {
        id: vuln.id,
        source: vuln.source,
        confidence: vuln.confidence,
        detectedBy: vuln.detectedBy,
        cvss: vuln.cvss
      }
    };

    return result;
  }

  /**
   * Construit le message du résultat
   */
  private buildResultMessage(vuln: Vulnerability): string {
    let message = vuln.description;

    if (vuln.recommendation) {
      message += `\n\n**Recommandation:** ${vuln.recommendation}`;
    }

    if (vuln.references.length > 0) {
      message += `\n\n**Références:** ${vuln.references.join(', ')}`;
    }

    return message;
  }

  /**
   * Extrait les artifacts (fichiers) uniques
   */
  private extractArtifacts(vulnerabilities: Vulnerability[]): SarifArtifact[] {
    const files = new Set<string>();

    for (const vuln of vulnerabilities) {
      files.add(this.normalizeUri(vuln.location.file));
    }

    return Array.from(files).map(uri => ({
      location: { uri }
    }));
  }

  /**
   * Normalise une URI de fichier
   */
  private normalizeUri(filePath: string): string {
    return filePath
      .replace(/\\/g, '/')
      .replace(/^\/+/, '');
  }

  /**
   * Génère une empreinte pour la déduplication
   */
  private generateFingerprint(vuln: Vulnerability): string {
    const data = `${vuln.location.file}:${vuln.location.line}:${vuln.category}:${vuln.cwe || ''}`;
    // Hash simple (en production, utiliser crypto)
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Mappe la sévérité vers le niveau SARIF
   */
  private mapSeverityToLevel(severity: Severity): SarifLevel {
    const mapping: Record<Severity, SarifLevel> = {
      critical: 'error',
      high: 'error',
      medium: 'warning',
      low: 'warning',
      info: 'note'
    };
    return mapping[severity];
  }

  /**
   * Obtient la sévérité de sécurité pour GitHub (0-10)
   */
  private getSecuritySeverity(severity: Severity): string {
    const mapping: Record<Severity, string> = {
      critical: '9.0',
      high: '7.0',
      medium: '5.0',
      low: '3.0',
      info: '1.0'
    };
    return mapping[severity];
  }

  /**
   * Retourne les données SARIF sans les écrire
   */
  getSarifData(report: Report): string {
    const sarifLog = this.buildSarifLog(report);
    return JSON.stringify(sarifLog, null, 2);
  }

  /**
   * Valide un fichier SARIF existant
   */
  async validateSarif(filePath: string): Promise<{ valid: boolean; errors?: string[] }> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const sarif = JSON.parse(content) as SarifLog;

      const errors: string[] = [];

      // Vérifications basiques
      if (sarif.version !== '2.1.0') {
        errors.push(`Invalid SARIF version: ${sarif.version}`);
      }

      if (!sarif.runs || sarif.runs.length === 0) {
        errors.push('SARIF must contain at least one run');
      }

      for (const run of sarif.runs || []) {
        if (!run.tool?.driver?.name) {
          errors.push('Each run must have a tool driver name');
        }

        if (!run.results) {
          errors.push('Each run must have a results array');
        }
      }

      return {
        valid: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined
      };
    } catch (error) {
      return {
        valid: false,
        errors: [`Failed to parse SARIF: ${error}`]
      };
    }
  }
}

export const sarifExporterService = new SarifExporterService();
