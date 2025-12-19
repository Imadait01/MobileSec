import { v4 as uuidv4 } from 'uuid';
import logger from '../utils/logger';
import {
  Vulnerability,
  Category,
  Severity,
  Confidence,
  ScanResults
} from '../models';

// Interface pour les findings SAST (SonarQube style)
interface SonarQubeFinding {
  key: string;
  rule: string;
  severity: string;
  message: string;
  component: string;
  line?: number;
  textRange?: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  flows?: Array<{
    locations: Array<{
      component: string;
      textRange: { startLine: number };
    }>;
  }>;
}

// Interface pour les findings Snyk
interface SnykVulnerability {
  id: string;
  title: string;
  severity: string;
  packageName: string;
  version: string;
  description?: string;
  cvssScore?: number;
  cvssVector?: string;
  cwe?: string[];
  references?: string[];
  remediation?: string;
}

// Interface pour les findings TruffleHog
interface TruffleHogFinding {
  description: string;
  file: string;
  line?: number;
  secret?: string;
  detectorType?: string;
  verified?: boolean;
}

// Interface pour les findings DAST (ZAP style)
interface ZAPFinding {
  alert: string;
  risk: string;
  confidence: string;
  description: string;
  uri: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  solution?: string;
  reference?: string;
  cweid?: number;
}

export class AggregatorService {
  /**
   * Agrège et normalise tous les résultats de scan
   */
  aggregateResults(scanResults: ScanResults): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    try {
      // Traitement SAST
      if (scanResults.sast) {
        for (const sastResult of scanResults.sast) {
          const mapped = this.mapSastFindings(sastResult.tool, sastResult.findings);
          vulnerabilities.push(...mapped);
        }
      }

      // Traitement SCA
      if (scanResults.sca) {
        for (const scaResult of scanResults.sca) {
          const mapped = this.mapScaFindings(scaResult.tool, scaResult.vulnerabilities);
          vulnerabilities.push(...mapped);
        }
      }

      // Traitement Secrets
      if (scanResults.secrets) {
        for (const secretResult of scanResults.secrets) {
          const mapped = this.mapSecretFindings(secretResult.tool, secretResult.findings);
          vulnerabilities.push(...mapped);
        }
      }

      // Traitement DAST
      if (scanResults.dast) {
        for (const dastResult of scanResults.dast) {
          const mapped = this.mapDastFindings(dastResult.tool, dastResult.findings);
          vulnerabilities.push(...mapped);
        }
      }

      // ========== Support pour nos microservices custom ==========
      
      // CryptoCheck results
      if ((scanResults as any).cryptoCheck) {
        const mapped = this.mapCryptoCheckFindings((scanResults as any).cryptoCheck);
        vulnerabilities.push(...mapped);
      }

      // SecretHunter results
      if ((scanResults as any).secretHunter) {
        const mapped = this.mapSecretHunterFindings((scanResults as any).secretHunter);
        vulnerabilities.push(...mapped);
      }

      // NetworkInspector results
      if ((scanResults as any).networkInspector) {
        const mapped = this.mapNetworkInspectorFindings((scanResults as any).networkInspector);
        vulnerabilities.push(...mapped);
      }

      // APK Scanner results
      if ((scanResults as any).apkScanner) {
        const mapped = this.mapApkScannerFindings((scanResults as any).apkScanner);
        vulnerabilities.push(...mapped);
      }

      logger.info(`Aggregated ${vulnerabilities.length} vulnerabilities from scan results`);
    } catch (error) {
      logger.error('Error aggregating scan results', { error });
      throw error;
    }

    return vulnerabilities;
  }

  /**
   * Mappe les findings CryptoCheck
   */
  private mapCryptoCheckFindings(findings: any[]): Vulnerability[] {
    return findings.map((f: any) => ({
      id: uuidv4(),
      title: String(f.ruleId || f.message || 'Cryptographic Issue'),
      description: String(f.message || f.ruleId || 'Cryptographic vulnerability detected'),
      severity: this.normalizeSeverity(f.severity || 'high'),
      category: 'cryptography' as Category,
      confidence: 'high' as Confidence,
      location: {
        file: String(f.file || 'unknown'),
        startLine: f.line || 1,
        endLine: f.line || 1
      },
      cwe: f.cwe || 'CWE-327',
      references: [] as string[],
      source: 'CryptoCheck',
      detectedBy: ['CryptoCheck'] as string[],
      rawData: f,
      recommendation: f.recommendation
    }));
  }

  /**
   * Mappe les findings SecretHunter
   */
  private mapSecretHunterFindings(findings: any[]): Vulnerability[] {
    return findings.map((f: any) => ({
      id: uuidv4(),
      title: String(f.ruleId || 'Secret Exposed'),
      description: String(f.message || `Secret found: ${f.ruleId}`),
      severity: this.normalizeSeverity(f.severity || 'high'),
      category: 'secrets' as Category,
      confidence: 'high' as Confidence,
      location: {
        file: String(f.file || 'unknown'),
        startLine: f.line || 1,
        endLine: f.line || 1
      },
      references: [] as string[],
      source: 'SecretHunter',
      detectedBy: ['SecretHunter'] as string[],
      rawData: f
    }));
  }

  /**
   * Mappe les findings NetworkInspector
   */
  private mapNetworkInspectorFindings(findings: any[]): Vulnerability[] {
    return findings.map((f: any) => ({
      id: uuidv4(),
      title: String(f.ruleId || 'Network Issue'),
      description: String(f.message || f.ruleId || 'Network vulnerability detected'),
      severity: this.normalizeSeverity(f.severity || 'medium'),
      category: 'configuration' as Category,
      confidence: 'medium' as Confidence,
      location: {
        file: String(f.file || 'network-analysis'),
        startLine: f.line || 1,
        endLine: f.line || 1
      },
      references: [] as string[],
      source: 'NetworkInspector',
      detectedBy: ['NetworkInspector'] as string[],
      rawData: f
    }));
  }

  /**
   * Mappe les findings APK Scanner
   */
  private mapApkScannerFindings(findings: any[]): Vulnerability[] {
    return findings.map((f: any) => ({
      id: uuidv4(),
      title: String(f.ruleId || 'Manifest Issue'),
      description: String(f.message || f.ruleId || 'Android manifest issue detected'),
      severity: this.normalizeSeverity(f.severity || 'medium'),
      category: 'configuration' as Category,
      confidence: 'high' as Confidence,
      location: {
        file: String(f.file || 'AndroidManifest.xml'),
        startLine: f.line || 1,
        endLine: f.line || 1
      },
      references: [] as string[],
      source: 'APKScanner',
      detectedBy: ['APKScanner'] as string[],
      rawData: f
    }));
  }

  /**
   * Mappe les findings SAST vers le format normalisé
   */
  private mapSastFindings(tool: string, findings: unknown[]): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const finding of findings) {
      try {
        if (tool.toLowerCase().includes('sonar')) {
          vulnerabilities.push(this.mapSonarQubeFinding(finding as SonarQubeFinding));
        } else {
          // Mapping générique pour autres outils SAST
          vulnerabilities.push(this.mapGenericSastFinding(tool, finding as Record<string, unknown>));
        }
      } catch (error) {
        logger.warn(`Failed to map SAST finding from ${tool}`, { error, finding });
      }
    }

    return vulnerabilities;
  }

  /**
   * Mappe un finding SonarQube
   */
  private mapSonarQubeFinding(finding: SonarQubeFinding): Vulnerability {
    return {
      id: uuidv4(),
      title: finding.message,
      severity: this.mapSonarQubeSeverity(finding.severity),
      category: this.inferCategoryFromRule(finding.rule),
      description: finding.message,
      location: {
        file: finding.component,
        line: finding.line || finding.textRange?.startLine,
        endLine: finding.textRange?.endLine,
        column: finding.textRange?.startOffset,
        endColumn: finding.textRange?.endOffset
      },
      cwe: this.extractCweFromRule(finding.rule),
      recommendation: this.getRecommendationForRule(finding.rule),
      references: [`https://rules.sonarsource.com/${finding.rule}`],
      source: 'SonarQube',
      confidence: 'high',
      detectedBy: ['SonarQube'],
      rawData: finding
    };
  }

  /**
   * Mapping générique pour les outils SAST non spécifiques
   */
  private mapGenericSastFinding(tool: string, finding: Record<string, unknown>): Vulnerability {
    return {
      id: uuidv4(),
      title: (finding.title || finding.message || finding.name || 'Unknown vulnerability') as string,
      severity: this.normalizeSeverity((finding.severity || 'medium') as string),
      category: this.normalizeCategory((finding.category || finding.type || 'code-quality') as string),
      description: (finding.description || finding.message || '') as string,
      location: {
        file: (finding.file || finding.path || finding.component || 'unknown') as string,
        line: finding.line as number | undefined,
        codeSnippet: finding.snippet as string | undefined
      },
      cwe: finding.cwe as string | undefined,
      recommendation: finding.recommendation as string | undefined,
      references: (finding.references || []) as string[],
      source: tool,
      confidence: 'medium',
      detectedBy: [tool],
      rawData: finding
    };
  }

  /**
   * Mappe les findings SCA vers le format normalisé
   */
  private mapScaFindings(tool: string, vulnerabilities: unknown[]): Vulnerability[] {
    const mapped: Vulnerability[] = [];

    for (const vuln of vulnerabilities) {
      try {
        if (tool.toLowerCase().includes('snyk')) {
          mapped.push(this.mapSnykVulnerability(vuln as SnykVulnerability));
        } else {
          mapped.push(this.mapGenericScaVulnerability(tool, vuln as Record<string, unknown>));
        }
      } catch (error) {
        logger.warn(`Failed to map SCA vulnerability from ${tool}`, { error, vuln });
      }
    }

    return mapped;
  }

  /**
   * Mappe une vulnérabilité Snyk
   */
  private mapSnykVulnerability(vuln: SnykVulnerability): Vulnerability {
    return {
      id: uuidv4(),
      title: `${vuln.title} in ${vuln.packageName}@${vuln.version}`,
      severity: this.normalizeSeverity(vuln.severity),
      category: 'dependency',
      description: vuln.description || vuln.title,
      location: {
        file: `package.json (${vuln.packageName}@${vuln.version})`
      },
      cwe: vuln.cwe?.[0],
      cvss: vuln.cvssScore ? {
        score: vuln.cvssScore,
        vector: vuln.cvssVector
      } : undefined,
      recommendation: vuln.remediation || `Mettre à jour ${vuln.packageName} vers une version non vulnérable`,
      references: vuln.references || [`https://snyk.io/vuln/${vuln.id}`],
      source: 'Snyk',
      confidence: 'high',
      detectedBy: ['Snyk'],
      rawData: vuln
    };
  }

  /**
   * Mapping générique pour les outils SCA
   */
  private mapGenericScaVulnerability(tool: string, vuln: Record<string, unknown>): Vulnerability {
    const packageName = (vuln.packageName || vuln.package || vuln.name || 'unknown') as string;
    const version = (vuln.version || 'unknown') as string;

    return {
      id: uuidv4(),
      title: (vuln.title || `Vulnerability in ${packageName}@${version}`) as string,
      severity: this.normalizeSeverity((vuln.severity || 'medium') as string),
      category: 'dependency',
      description: (vuln.description || '') as string,
      location: {
        file: `package.json (${packageName}@${version})`
      },
      cwe: vuln.cwe as string | undefined,
      cvss: vuln.cvssScore ? {
        score: vuln.cvssScore as number,
        vector: vuln.cvssVector as string | undefined
      } : undefined,
      recommendation: (vuln.remediation || vuln.recommendation || `Mettre à jour ${packageName}`) as string,
      references: (vuln.references || []) as string[],
      source: tool,
      confidence: 'medium',
      detectedBy: [tool],
      rawData: vuln
    };
  }

  /**
   * Mappe les findings de secrets vers le format normalisé
   */
  private mapSecretFindings(tool: string, findings: unknown[]): Vulnerability[] {
    const mapped: Vulnerability[] = [];

    for (const finding of findings) {
      try {
        if (tool.toLowerCase().includes('trufflehog')) {
          mapped.push(this.mapTruffleHogFinding(finding as TruffleHogFinding));
        } else {
          mapped.push(this.mapGenericSecretFinding(tool, finding as Record<string, unknown>));
        }
      } catch (error) {
        logger.warn(`Failed to map secret finding from ${tool}`, { error, finding });
      }
    }

    return mapped;
  }

  /**
   * Mappe un finding TruffleHog
   */
  private mapTruffleHogFinding(finding: TruffleHogFinding): Vulnerability {
    const secretType = finding.detectorType || 'Secret';
    const isVerified = finding.verified;

    return {
      id: uuidv4(),
      title: `${secretType} exposé dans le code`,
      severity: isVerified ? 'critical' : 'high',
      category: 'secrets',
      description: `${finding.description}. ${isVerified ? 'Ce secret a été vérifié comme étant actif.' : 'Ce secret nécessite une vérification manuelle.'}`,
      location: {
        file: finding.file,
        line: finding.line,
        codeSnippet: finding.secret ? this.maskSecret(finding.secret) : undefined
      },
      cwe: 'CWE-798',
      recommendation: 'Révoquer immédiatement ce secret, le retirer du code source et utiliser un gestionnaire de secrets sécurisé (HashiCorp Vault, AWS Secrets Manager, etc.)',
      references: ['https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials'],
      source: 'TruffleHog',
      confidence: isVerified ? 'high' : 'medium',
      detectedBy: ['TruffleHog'],
      rawData: { ...finding, secret: finding.secret ? this.maskSecret(finding.secret) : undefined }
    };
  }

  /**
   * Mapping générique pour les détecteurs de secrets
   */
  private mapGenericSecretFinding(tool: string, finding: Record<string, unknown>): Vulnerability {
    return {
      id: uuidv4(),
      title: (finding.title || finding.description || 'Secret exposé') as string,
      severity: 'high',
      category: 'secrets',
      description: (finding.description || 'Un secret a été détecté dans le code source') as string,
      location: {
        file: (finding.file || finding.path || 'unknown') as string,
        line: finding.line as number | undefined,
        codeSnippet: finding.secret ? this.maskSecret(finding.secret as string) : undefined
      },
      cwe: 'CWE-798',
      recommendation: 'Révoquer ce secret et utiliser un gestionnaire de secrets sécurisé',
      references: [],
      source: tool,
      confidence: 'medium',
      detectedBy: [tool],
      rawData: finding
    };
  }

  /**
   * Mappe les findings DAST vers le format normalisé
   */
  private mapDastFindings(tool: string, findings: unknown[]): Vulnerability[] {
    const mapped: Vulnerability[] = [];

    for (const finding of findings) {
      try {
        if (tool.toLowerCase().includes('zap') || tool.toLowerCase().includes('owasp')) {
          mapped.push(this.mapZAPFinding(finding as ZAPFinding));
        } else {
          mapped.push(this.mapGenericDastFinding(tool, finding as Record<string, unknown>));
        }
      } catch (error) {
        logger.warn(`Failed to map DAST finding from ${tool}`, { error, finding });
      }
    }

    return mapped;
  }

  /**
   * Mappe un finding OWASP ZAP
   */
  private mapZAPFinding(finding: ZAPFinding): Vulnerability {
    return {
      id: uuidv4(),
      title: finding.alert,
      severity: this.mapZAPRisk(finding.risk),
      category: this.inferCategoryFromCWE(finding.cweid),
      description: finding.description,
      location: {
        file: finding.uri,
        codeSnippet: finding.evidence
      },
      cwe: finding.cweid ? `CWE-${finding.cweid}` : undefined,
      recommendation: finding.solution,
      references: finding.reference ? [finding.reference] : [],
      source: 'OWASP ZAP',
      confidence: this.mapZAPConfidence(finding.confidence),
      detectedBy: ['OWASP ZAP'],
      rawData: finding
    };
  }

  /**
   * Mapping générique pour les outils DAST
   */
  private mapGenericDastFinding(tool: string, finding: Record<string, unknown>): Vulnerability {
    return {
      id: uuidv4(),
      title: (finding.title || finding.alert || finding.name || 'Web vulnerability') as string,
      severity: this.normalizeSeverity((finding.severity || finding.risk || 'medium') as string),
      category: this.normalizeCategory((finding.category || finding.type || 'other') as string),
      description: (finding.description || '') as string,
      location: {
        file: (finding.url || finding.uri || 'unknown') as string,
        codeSnippet: finding.evidence as string | undefined
      },
      cwe: finding.cwe as string | undefined,
      recommendation: (finding.solution || finding.recommendation) as string | undefined,
      references: (finding.references || []) as string[],
      source: tool,
      confidence: 'medium',
      detectedBy: [tool],
      rawData: finding
    };
  }

  /**
   * Normalise une sévérité vers notre format
   */
  private normalizeSeverity(severity: string): Severity {
    const normalized = severity.toLowerCase().trim();

    const severityMap: Record<string, Severity> = {
      // SonarQube
      'blocker': 'critical',
      'critical': 'critical',
      // Commun
      'high': 'high',
      'major': 'high',
      'medium': 'medium',
      'moderate': 'medium',
      'minor': 'low',
      'low': 'low',
      'info': 'info',
      'informational': 'info',
      'note': 'info',
      // ZAP
      '3': 'high',
      '2': 'medium',
      '1': 'low',
      '0': 'info'
    };

    return severityMap[normalized] || 'medium';
  }

  /**
   * Normalise une catégorie vers notre format
   */
  private normalizeCategory(category: string): Category {
    const normalized = category.toLowerCase().trim();

    const categoryMap: Record<string, Category> = {
      'injection': 'injection',
      'sql': 'injection',
      'sql-injection': 'injection',
      'command-injection': 'injection',
      'xss': 'xss',
      'cross-site-scripting': 'xss',
      'secret': 'secrets',
      'secrets': 'secrets',
      'credential': 'secrets',
      'hardcoded-credentials': 'secrets',
      'auth': 'authentication',
      'authentication': 'authentication',
      'authorization': 'authorization',
      'access-control': 'authorization',
      'crypto': 'cryptography',
      'cryptography': 'cryptography',
      'encryption': 'cryptography',
      'config': 'configuration',
      'configuration': 'configuration',
      'misconfiguration': 'configuration',
      'dependency': 'dependency',
      'vulnerable-dependency': 'dependency',
      'outdated-dependency': 'dependency',
      'information-disclosure': 'information-disclosure',
      'information-leak': 'information-disclosure',
      'dos': 'denial-of-service',
      'denial-of-service': 'denial-of-service',
      'code-quality': 'code-quality',
      'code-smell': 'code-quality',
      'bug': 'code-quality'
    };

    return categoryMap[normalized] || 'other';
  }

  /**
   * Mappe la sévérité SonarQube
   */
  private mapSonarQubeSeverity(severity: string): Severity {
    const map: Record<string, Severity> = {
      'BLOCKER': 'critical',
      'CRITICAL': 'critical',
      'MAJOR': 'high',
      'MINOR': 'medium',
      'INFO': 'info'
    };
    return map[severity.toUpperCase()] || 'medium';
  }

  /**
   * Mappe le risque ZAP
   */
  private mapZAPRisk(risk: string): Severity {
    const map: Record<string, Severity> = {
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Informational': 'info',
      '3': 'high',
      '2': 'medium',
      '1': 'low',
      '0': 'info'
    };
    return map[risk] || 'medium';
  }

  /**
   * Mappe la confiance ZAP
   */
  private mapZAPConfidence(confidence: string): Confidence {
    const map: Record<string, Confidence> = {
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Confirmed': 'high',
      '3': 'high',
      '2': 'medium',
      '1': 'low'
    };
    return map[confidence] || 'medium';
  }

  /**
   * Infère la catégorie à partir d'une règle SonarQube
   */
  private inferCategoryFromRule(rule: string): Category {
    const ruleLower = rule.toLowerCase();

    if (ruleLower.includes('injection') || ruleLower.includes('sql')) return 'injection';
    if (ruleLower.includes('xss') || ruleLower.includes('cross-site')) return 'xss';
    if (ruleLower.includes('secret') || ruleLower.includes('credential') || ruleLower.includes('password')) return 'secrets';
    if (ruleLower.includes('auth')) return 'authentication';
    if (ruleLower.includes('access') || ruleLower.includes('permission')) return 'authorization';
    if (ruleLower.includes('crypto') || ruleLower.includes('cipher') || ruleLower.includes('hash')) return 'cryptography';
    if (ruleLower.includes('config')) return 'configuration';

    return 'code-quality';
  }

  /**
   * Infère la catégorie à partir d'un CWE
   */
  private inferCategoryFromCWE(cweId?: number): Category {
    if (!cweId) return 'other';

    // Mapping basé sur les catégories CWE communes
    const cweCategories: Record<number, Category> = {
      // Injection
      89: 'injection',  // SQL Injection
      78: 'injection',  // OS Command Injection
      77: 'injection',  // Command Injection
      94: 'injection',  // Code Injection
      // XSS
      79: 'xss',
      80: 'xss',
      // Secrets
      798: 'secrets',  // Hardcoded Credentials
      259: 'secrets',  // Hardcoded Password
      // Auth
      287: 'authentication',
      306: 'authentication',
      // Crypto
      327: 'cryptography',
      328: 'cryptography',
      // Config
      16: 'configuration'
    };

    return cweCategories[cweId] || 'other';
  }

  /**
   * Extrait le CWE d'une règle SonarQube
   */
  private extractCweFromRule(_rule: string): string | undefined {
    // Les règles SonarQube ne contiennent pas directement le CWE
    // On pourrait avoir un mapping mais pour l'instant on retourne undefined
    return undefined;
  }

  /**
   * Génère une recommandation basée sur la règle
   */
  private getRecommendationForRule(rule: string): string {
    const ruleLower = rule.toLowerCase();

    if (ruleLower.includes('sql') || ruleLower.includes('injection')) {
      return 'Utiliser des requêtes préparées (prepared statements) ou un ORM pour éviter les injections SQL.';
    }
    if (ruleLower.includes('xss')) {
      return 'Échapper ou encoder toutes les données utilisateur avant de les afficher dans le HTML.';
    }
    if (ruleLower.includes('password') || ruleLower.includes('credential')) {
      return 'Ne jamais stocker de credentials dans le code. Utiliser des variables d\'environnement ou un gestionnaire de secrets.';
    }

    return 'Corriger cette vulnérabilité selon les bonnes pratiques de sécurité.';
  }

  /**
   * Masque un secret pour l'affichage
   */
  private maskSecret(secret: string): string {
    if (secret.length <= 8) {
      return '****';
    }
    return secret.substring(0, 4) + '****' + secret.substring(secret.length - 4);
  }
}

export const aggregatorService = new AggregatorService();
