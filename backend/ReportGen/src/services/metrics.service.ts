import logger from '../utils/logger';
import {
  Vulnerability,
  ReportMetrics,
  SeverityMetrics,
  CategoryMetrics,
  Severity
} from '../models';

export class MetricsService {
  /**
   * Calcule toutes les métriques pour un ensemble de vulnérabilités
   */
  calculateMetrics(vulnerabilities: Vulnerability[]): ReportMetrics {
    logger.info(`Calculating metrics for ${vulnerabilities.length} vulnerabilities`);

    const metrics: ReportMetrics = {
      total: vulnerabilities.length,
      bySeverity: this.calculateBySeverity(vulnerabilities),
      byCategory: this.calculateByCategory(vulnerabilities),
      securityScore: this.calculateSecurityScore(vulnerabilities),
      topAffectedFiles: this.calculateTopAffectedFiles(vulnerabilities)
    };

    logger.info('Metrics calculated', {
      total: metrics.total,
      securityScore: metrics.securityScore,
      critical: metrics.bySeverity.critical,
      high: metrics.bySeverity.high
    });

    return metrics;
  }

  /**
   * Calcule la répartition par sévérité
   */
  private calculateBySeverity(vulnerabilities: Vulnerability[]): SeverityMetrics {
    const metrics: SeverityMetrics = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    for (const vuln of vulnerabilities) {
      metrics[vuln.severity]++;
    }

    return metrics;
  }

  /**
   * Calcule la répartition par catégorie
   */
  private calculateByCategory(vulnerabilities: Vulnerability[]): CategoryMetrics {
    const metrics: CategoryMetrics = {};

    for (const vuln of vulnerabilities) {
      const category = vuln.category;
      metrics[category] = (metrics[category] || 0) + 1;
    }

    return metrics;
  }

  /**
   * Calcule le score de sécurité global (0-100, 100 étant le meilleur)
   */
  private calculateSecurityScore(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length === 0) {
      return 100;
    }

    // Poids par sévérité (plus c'est grave, plus ça pénalise)
    const weights: Record<Severity, number> = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3,
      info: 1
    };

    // Calculer le score de pénalité
    let penaltyScore = 0;
    for (const vuln of vulnerabilities) {
      penaltyScore += weights[vuln.severity];
    }

    // Score maximum théorique (si tout était critique)
    const maxPenalty = 200;

    // Normaliser et inverser (plus de pénalité = score plus bas)
    const normalizedPenalty = Math.min(penaltyScore, maxPenalty) / maxPenalty;
    const score = Math.round((1 - normalizedPenalty) * 100);

    // Ajustements basés sur la présence de vulnérabilités critiques
    const bySeverity = this.calculateBySeverity(vulnerabilities);

    // Si plus de 5 critiques, le score ne peut pas dépasser 30
    if (bySeverity.critical >= 5) {
      return Math.min(score, 30);
    }

    // Si plus de 10 high, le score ne peut pas dépasser 50
    if (bySeverity.high >= 10) {
      return Math.min(score, 50);
    }

    // Si des critiques existent, le score ne peut pas dépasser 60
    if (bySeverity.critical > 0) {
      return Math.min(score, 60);
    }

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Calcule les fichiers les plus affectés
   */
  private calculateTopAffectedFiles(
    vulnerabilities: Vulnerability[],
    limit: number = 10
  ): Array<{ file: string; count: number }> {
    const fileCounts = new Map<string, number>();

    for (const vuln of vulnerabilities) {
      const file = this.normalizeFilePath(vuln.location.file);
      fileCounts.set(file, (fileCounts.get(file) || 0) + 1);
    }

    return Array.from(fileCounts.entries())
      .map(([file, count]) => ({ file, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  /**
   * Normalise un chemin de fichier
   */
  private normalizeFilePath(path: string): string {
    return path.replace(/\\/g, '/');
  }

  /**
   * Calcule des statistiques avancées
   */
  calculateAdvancedStats(vulnerabilities: Vulnerability[]): Record<string, unknown> {
    const bySource = this.calculateBySource(vulnerabilities);
    const byConfidence = this.calculateByConfidence(vulnerabilities);
    const averageCVSS = this.calculateAverageCVSS(vulnerabilities);
    const cweDistribution = this.calculateCWEDistribution(vulnerabilities);

    return {
      bySource,
      byConfidence,
      averageCVSS,
      cweDistribution,
      duplicateDetectionRate: this.estimateDuplicateRate(vulnerabilities)
    };
  }

  /**
   * Calcule la répartition par source
   */
  private calculateBySource(vulnerabilities: Vulnerability[]): Record<string, number> {
    const counts: Record<string, number> = {};

    for (const vuln of vulnerabilities) {
      counts[vuln.source] = (counts[vuln.source] || 0) + 1;
    }

    return counts;
  }

  /**
   * Calcule la répartition par niveau de confiance
   */
  private calculateByConfidence(vulnerabilities: Vulnerability[]): Record<string, number> {
    const counts: Record<string, number> = {
      high: 0,
      medium: 0,
      low: 0
    };

    for (const vuln of vulnerabilities) {
      counts[vuln.confidence]++;
    }

    return counts;
  }

  /**
   * Calcule le score CVSS moyen
   */
  private calculateAverageCVSS(vulnerabilities: Vulnerability[]): number | null {
    const vulnsWithCVSS = vulnerabilities.filter(v => v.cvss?.score);

    if (vulnsWithCVSS.length === 0) {
      return null;
    }

    const sum = vulnsWithCVSS.reduce((acc, v) => acc + (v.cvss?.score || 0), 0);
    return Math.round((sum / vulnsWithCVSS.length) * 10) / 10;
  }

  /**
   * Calcule la distribution des CWE
   */
  private calculateCWEDistribution(vulnerabilities: Vulnerability[]): Record<string, number> {
    const counts: Record<string, number> = {};

    for (const vuln of vulnerabilities) {
      if (vuln.cwe) {
        counts[vuln.cwe] = (counts[vuln.cwe] || 0) + 1;
      }
    }

    return counts;
  }

  /**
   * Estime le taux de doublons potentiels
   */
  private estimateDuplicateRate(vulnerabilities: Vulnerability[]): number {
    if (vulnerabilities.length <= 1) return 0;

    let potentialDuplicates = 0;

    // Compter les vulnérabilités avec plusieurs sources (déjà fusionnées)
    for (const vuln of vulnerabilities) {
      if (vuln.detectedBy.length > 1) {
        potentialDuplicates += vuln.detectedBy.length - 1;
      }
    }

    const originalCount = vulnerabilities.length + potentialDuplicates;
    return Math.round((potentialDuplicates / originalCount) * 100);
  }

  /**
   * Génère un résumé textuel des métriques
   */
  generateSummary(metrics: ReportMetrics): string {
    const lines: string[] = [];

    lines.push(`📊 Résumé de l'analyse de sécurité`);
    lines.push(`─────────────────────────────────`);
    lines.push(`Total des vulnérabilités : ${metrics.total}`);
    lines.push(`Score de sécurité : ${metrics.securityScore}/100`);
    lines.push(``);
    lines.push(`Répartition par sévérité :`);
    lines.push(`  🔴 Critique : ${metrics.bySeverity.critical}`);
    lines.push(`  🟠 Élevée   : ${metrics.bySeverity.high}`);
    lines.push(`  🟡 Moyenne  : ${metrics.bySeverity.medium}`);
    lines.push(`  🔵 Faible   : ${metrics.bySeverity.low}`);
    lines.push(`  ⚪ Info     : ${metrics.bySeverity.info}`);

    if (metrics.topAffectedFiles.length > 0) {
      lines.push(``);
      lines.push(`Fichiers les plus affectés :`);
      for (const file of metrics.topAffectedFiles.slice(0, 5)) {
        lines.push(`  - ${file.file} (${file.count})`);
      }
    }

    return lines.join('\n');
  }

  /**
   * Détermine le niveau de risque global
   */
  getRiskLevel(metrics: ReportMetrics): 'critical' | 'high' | 'medium' | 'low' | 'none' {
    if (metrics.bySeverity.critical > 0) return 'critical';
    if (metrics.bySeverity.high > 5) return 'critical';
    if (metrics.bySeverity.high > 0) return 'high';
    if (metrics.bySeverity.medium > 10) return 'high';
    if (metrics.bySeverity.medium > 0) return 'medium';
    if (metrics.bySeverity.low > 0) return 'low';
    return 'none';
  }

  /**
   * Génère des recommandations prioritaires basées sur les métriques
   */
  generatePriorityRecommendations(
    vulnerabilities: Vulnerability[],
    metrics: ReportMetrics
  ): string[] {
    const recommendations: string[] = [];

    // Critiques en premier
    if (metrics.bySeverity.critical > 0) {
      recommendations.push(
        `🚨 URGENT: Corriger immédiatement les ${metrics.bySeverity.critical} vulnérabilité(s) critique(s).`
      );
    }

    // Secrets exposés
    const secretsCount = vulnerabilities.filter(v => v.category === 'secrets').length;
    if (secretsCount > 0) {
      recommendations.push(
        `🔑 Révoquer et remplacer les ${secretsCount} secret(s) exposé(s) dans le code.`
      );
    }

    // Dépendances vulnérables
    const depsCount = vulnerabilities.filter(v => v.category === 'dependency').length;
    if (depsCount > 0) {
      recommendations.push(
        `📦 Mettre à jour ${depsCount} dépendance(s) vulnérable(s).`
      );
    }

    // Injections
    const injectionsCount = vulnerabilities.filter(v => v.category === 'injection').length;
    if (injectionsCount > 0) {
      recommendations.push(
        `💉 Corriger ${injectionsCount} vulnérabilité(s) d'injection (SQL, commandes, etc.).`
      );
    }

    // XSS
    const xssCount = vulnerabilities.filter(v => v.category === 'xss').length;
    if (xssCount > 0) {
      recommendations.push(
        `🌐 Corriger ${xssCount} vulnérabilité(s) XSS en échappant les données utilisateur.`
      );
    }

    // Fichiers les plus touchés
    if (metrics.topAffectedFiles.length > 0) {
      const topFile = metrics.topAffectedFiles[0];
      if (topFile.count >= 5) {
        recommendations.push(
          `📁 Prioriser la revue du fichier "${topFile.file}" (${topFile.count} vulnérabilités).`
        );
      }
    }

    // Score global
    if (metrics.securityScore < 50) {
      recommendations.push(
        `⚠️ Le score de sécurité est critique (${metrics.securityScore}/100). Une revue de sécurité approfondie est recommandée.`
      );
    }

    return recommendations;
  }
}

export const metricsService = new MetricsService();
