import fs from 'fs/promises';
import path from 'path';
import logger from '../utils/logger';
import { GenerateReportRequestSchema, GenerateReportRequest } from '../models';

export interface ScanFile {
  filename: string;
  path: string;
  tool: string;
  type: 'sast' | 'sca' | 'secrets' | 'dast';
  data: unknown;
}

export class FileWatcherService {
  private inputDir: string;

  constructor() {
    this.inputDir = process.env.INPUT_DIR || './input';
    this.ensureInputDir();
  }

  /**
   * S'assure que le dossier input existe
   */
  private async ensureInputDir(): Promise<void> {
    try {
      await fs.mkdir(this.inputDir, { recursive: true });
      logger.info(`Input directory ensured: ${this.inputDir}`);
    } catch (error) {
      logger.error('Failed to create input directory', { error });
    }
  }

  /**
   * Liste tous les fichiers JSON dans le dossier input
   */
  async listInputFiles(): Promise<string[]> {
    try {
      const files = await fs.readdir(this.inputDir);
      return files.filter(f => f.endsWith('.json'));
    } catch (error) {
      logger.error('Failed to list input files', { error });
      return [];
    }
  }

  /**
   * Lit et parse un fichier JSON
   */
  async readJsonFile(filename: string): Promise<unknown> {
    const filePath = path.join(this.inputDir, filename);
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content);
  }

  /**
   * Détecte automatiquement le type et l'outil d'un fichier de scan
   */
  detectScanType(data: unknown, filename: string): { type: ScanFile['type']; tool: string } | null {
    const obj = data as Record<string, unknown>;

    // Détection SonarQube
    if (obj.issues && Array.isArray(obj.issues)) {
      return { type: 'sast', tool: 'SonarQube' };
    }

    // Détection Semgrep
    if (obj.results && Array.isArray(obj.results) && obj.version) {
      return { type: 'sast', tool: 'Semgrep' };
    }

    // Détection Snyk
    if (obj.vulnerabilities && Array.isArray(obj.vulnerabilities)) {
      return { type: 'sca', tool: 'Snyk' };
    }

    // Détection OWASP Dependency-Check
    if (obj.dependencies && Array.isArray(obj.dependencies)) {
      return { type: 'sca', tool: 'OWASP Dependency-Check' };
    }

    // Détection TruffleHog
    if (Array.isArray(data) && (data as Record<string, unknown>[]).some(item => item.DetectorType || item.detectorType)) {
      return { type: 'secrets', tool: 'TruffleHog' };
    }

    // Détection GitLeaks
    if (Array.isArray(data) && (data as Record<string, unknown>[]).some(item => item.Secret || item.Match)) {
      return { type: 'secrets', tool: 'GitLeaks' };
    }

    // Détection OWASP ZAP
    if (obj.site && Array.isArray(obj.site)) {
      return { type: 'dast', tool: 'OWASP ZAP' };
    }
    if (obj.alerts && Array.isArray(obj.alerts)) {
      return { type: 'dast', tool: 'OWASP ZAP' };
    }

    // Détection par nom de fichier
    const lowerFilename = filename.toLowerCase();
    if (lowerFilename.includes('sonar')) return { type: 'sast', tool: 'SonarQube' };
    if (lowerFilename.includes('semgrep')) return { type: 'sast', tool: 'Semgrep' };
    if (lowerFilename.includes('snyk')) return { type: 'sca', tool: 'Snyk' };
    if (lowerFilename.includes('dependency')) return { type: 'sca', tool: 'OWASP Dependency-Check' };
    if (lowerFilename.includes('truffle')) return { type: 'secrets', tool: 'TruffleHog' };
    if (lowerFilename.includes('gitleak')) return { type: 'secrets', tool: 'GitLeaks' };
    if (lowerFilename.includes('zap')) return { type: 'dast', tool: 'OWASP ZAP' };
    if (lowerFilename.includes('burp')) return { type: 'dast', tool: 'Burp Suite' };

    // Format déjà normalisé (notre format)
    if (obj.tool && obj.findings) {
      const toolName = obj.tool as string;
      if (toolName.toLowerCase().includes('sonar') || toolName.toLowerCase().includes('semgrep')) {
        return { type: 'sast', tool: toolName };
      }
      if (toolName.toLowerCase().includes('snyk') || toolName.toLowerCase().includes('dependency')) {
        return { type: 'sca', tool: toolName };
      }
      if (toolName.toLowerCase().includes('truffle') || toolName.toLowerCase().includes('gitleak')) {
        return { type: 'secrets', tool: toolName };
      }
      if (toolName.toLowerCase().includes('zap') || toolName.toLowerCase().includes('burp')) {
        return { type: 'dast', tool: toolName };
      }
    }

    // Format avec vulnerabilities (SCA)
    if (obj.tool && obj.vulnerabilities) {
      return { type: 'sca', tool: obj.tool as string };
    }

    return null;
  }

  /**
   * Lit tous les fichiers du dossier input et les combine en une requête de génération
   */
  async readAllInputFiles(): Promise<{ files: ScanFile[]; errors: string[] }> {
    const files: ScanFile[] = [];
    const errors: string[] = [];

    const jsonFiles = await this.listInputFiles();

    if (jsonFiles.length === 0) {
      errors.push('No JSON files found in input directory');
      return { files, errors };
    }

    for (const filename of jsonFiles) {
      try {
        const data = await this.readJsonFile(filename);
        const detected = this.detectScanType(data, filename);

        if (detected) {
          files.push({
            filename,
            path: path.join(this.inputDir, filename),
            tool: detected.tool,
            type: detected.type,
            data
          });
          logger.info(`Loaded scan file: ${filename}`, { type: detected.type, tool: detected.tool });
        } else {
          // Essayer de charger comme fichier de requête complet
          const validationResult = GenerateReportRequestSchema.safeParse(data);
          if (validationResult.success) {
            // C'est un fichier de requête complet, on l'ajoute comme fichier spécial
            files.push({
              filename,
              path: path.join(this.inputDir, filename),
              tool: 'complete-request',
              type: 'sast', // placeholder
              data: validationResult.data
            });
            logger.info(`Loaded complete request file: ${filename}`);
          } else {
            errors.push(`${filename}: Unable to detect scan type or invalid format`);
            logger.warn(`Unable to detect scan type for file: ${filename}`);
          }
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        errors.push(`${filename}: ${errorMessage}`);
        logger.error(`Failed to read file: ${filename}`, { error });
      }
    }

    return { files, errors };
  }

  /**
   * Combine les fichiers scannés en une requête de génération de rapport
   */
  combineFilesToRequest(
    files: ScanFile[],
    projectName: string,
    format: 'pdf' | 'json' | 'sarif' = 'pdf',
    options?: Record<string, unknown>
  ): GenerateReportRequest {
    const scanResults: GenerateReportRequest['scanResults'] = {
      sast: [],
      sca: [],
      secrets: [],
      dast: []
    };

    for (const file of files) {
      // Si c'est un fichier de requête complet, on fusionne ses résultats
      if (file.tool === 'complete-request') {
        const completeRequest = file.data as GenerateReportRequest;
        if (completeRequest.scanResults.sast) {
          scanResults.sast!.push(...completeRequest.scanResults.sast);
        }
        if (completeRequest.scanResults.sca) {
          scanResults.sca!.push(...completeRequest.scanResults.sca);
        }
        if (completeRequest.scanResults.secrets) {
          scanResults.secrets!.push(...completeRequest.scanResults.secrets);
        }
        if (completeRequest.scanResults.dast) {
          scanResults.dast!.push(...completeRequest.scanResults.dast);
        }
        continue;
      }

      // Convertir les données brutes au format attendu
      const converted = this.convertToExpectedFormat(file);
      
      if (converted) {
        switch (file.type) {
          case 'sast':
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            scanResults.sast!.push(converted as any);
            break;
          case 'sca':
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            scanResults.sca!.push(converted as any);
            break;
          case 'secrets':
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            scanResults.secrets!.push(converted as any);
            break;
          case 'dast':
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            scanResults.dast!.push(converted as any);
            break;
        }
      }
    }

    return {
      projectName,
      scanResults,
      format,
      options: options as GenerateReportRequest['options']
    };
  }

  /**
   * Convertit les données brutes d'un outil au format attendu
   */
  private convertToExpectedFormat(file: ScanFile): unknown {
    const data = file.data as Record<string, unknown>;

    switch (file.tool) {
      case 'SonarQube':
        // Format SonarQube natif
        if (data.issues) {
          return {
            tool: 'SonarQube',
            findings: data.issues
          };
        }
        // Déjà au bon format
        if (data.findings) {
          return { tool: 'SonarQube', findings: data.findings };
        }
        return { tool: 'SonarQube', findings: data };

      case 'Semgrep':
        if (data.results) {
          return {
            tool: 'Semgrep',
            findings: (data.results as unknown[]).map((r: unknown) => {
              const result = r as Record<string, unknown>;
              return {
                check_id: result.check_id,
                path: result.path,
                start: result.start,
                end: result.end,
                message: (result.extra as Record<string, unknown>)?.message,
                severity: (result.extra as Record<string, unknown>)?.severity
              };
            })
          };
        }
        return { tool: 'Semgrep', findings: data };

      case 'Snyk':
        if (data.vulnerabilities) {
          return { tool: 'Snyk', vulnerabilities: data.vulnerabilities };
        }
        return { tool: 'Snyk', vulnerabilities: data };

      case 'OWASP Dependency-Check':
        if (data.dependencies) {
          const vulns: unknown[] = [];
          (data.dependencies as unknown[]).forEach((dep: unknown) => {
            const dependency = dep as Record<string, unknown>;
            if (dependency.vulnerabilities) {
              (dependency.vulnerabilities as unknown[]).forEach((v: unknown) => {
                const vuln = v as Record<string, unknown>;
                const cvssv3 = vuln.cvssv3 as Record<string, unknown> | undefined;
                const cvssv2 = vuln.cvssv2 as Record<string, unknown> | undefined;
                vulns.push({
                  id: vuln.name,
                  title: vuln.description,
                  severity: this.mapDependencyCheckSeverity(vuln.severity as string),
                  packageName: dependency.fileName,
                  cvssScore: cvssv3?.baseScore || cvssv2?.score
                });
              });
            }
          });
          return { tool: 'OWASP Dependency-Check', vulnerabilities: vulns };
        }
        return { tool: 'OWASP Dependency-Check', vulnerabilities: data };

      case 'TruffleHog':
        if (Array.isArray(data)) {
          return {
            tool: 'TruffleHog',
            findings: data.map((item: unknown) => {
              const finding = item as Record<string, unknown>;
              const sourceMetadata = finding.SourceMetadata as Record<string, unknown> | undefined;
              const metaData = sourceMetadata?.Data as Record<string, unknown> | undefined;
              const filesystem = metaData?.Filesystem as Record<string, unknown> | undefined;
              return {
                description: finding.Raw || finding.DetectorName || 'Secret detected',
                file: filesystem?.file || finding.File,
                line: filesystem?.line || finding.Line,
                detectorType: finding.DetectorType || finding.DetectorName,
                verified: finding.Verified
              };
            })
          };
        }
        if (data.findings) {
          return { tool: 'TruffleHog', findings: data.findings };
        }
        return { tool: 'TruffleHog', findings: [data] };

      case 'GitLeaks':
        if (Array.isArray(data)) {
          return {
            tool: 'GitLeaks',
            findings: data.map((item: unknown) => {
              const finding = item as Record<string, unknown>;
              return {
                description: finding.Description || finding.RuleID,
                file: finding.File,
                line: finding.StartLine,
                detectorType: finding.RuleID,
                verified: false
              };
            })
          };
        }
        return { tool: 'GitLeaks', findings: data };

      case 'OWASP ZAP':
        if (data.site && Array.isArray(data.site)) {
          const alerts: unknown[] = [];
          (data.site as unknown[]).forEach((site: unknown) => {
            const s = site as Record<string, unknown>;
            if (s.alerts) {
              alerts.push(...(s.alerts as unknown[]));
            }
          });
          return { tool: 'OWASP ZAP', findings: alerts };
        }
        if (data.alerts) {
          return { tool: 'OWASP ZAP', findings: data.alerts };
        }
        if (data.findings) {
          return { tool: 'OWASP ZAP', findings: data.findings };
        }
        return { tool: 'OWASP ZAP', findings: data };

      default:
        // Format générique
        if (data.findings) {
          return { tool: file.tool, findings: data.findings };
        }
        if (data.vulnerabilities) {
          return { tool: file.tool, vulnerabilities: data.vulnerabilities };
        }
        return { tool: file.tool, findings: Array.isArray(data) ? data : [data] };
    }
  }

  /**
   * Mappe la sévérité de OWASP Dependency-Check au format standard
   */
  private mapDependencyCheckSeverity(severity: string): string {
    const severityLower = severity?.toLowerCase() || '';
    if (severityLower.includes('critical')) return 'critical';
    if (severityLower.includes('high')) return 'high';
    if (severityLower.includes('medium') || severityLower.includes('moderate')) return 'medium';
    if (severityLower.includes('low')) return 'low';
    return 'info';
  }

  /**
   * Supprime un fichier du dossier input
   */
  async deleteInputFile(filename: string): Promise<void> {
    const filePath = path.join(this.inputDir, filename);
    await fs.unlink(filePath);
  }

  /**
   * Vide le dossier input
   */
  async clearInputDirectory(): Promise<number> {
    const files = await this.listInputFiles();
    let deleted = 0;

    for (const file of files) {
      try {
        await this.deleteInputFile(file);
        deleted++;
      } catch (error) {
        logger.error(`Failed to delete file: ${file}`, { error });
      }
    }

    return deleted;
  }

  /**
   * Retourne le chemin du dossier input
   */
  getInputDirectory(): string {
    return path.resolve(this.inputDir);
  }
}

export const fileWatcherService = new FileWatcherService();
