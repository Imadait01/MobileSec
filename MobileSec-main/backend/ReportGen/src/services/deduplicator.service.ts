import { v4 as uuidv4 } from 'uuid';
import logger from '../utils/logger';
import { Vulnerability, severityOrder } from '../models';

interface DuplicateGroup {
  master: Vulnerability;
  duplicates: Vulnerability[];
}

export class DeduplicatorService {
  /**
   * Déduplique les vulnérabilités en fusionnant les doublons
   */
  deduplicate(vulnerabilities: Vulnerability[]): Vulnerability[] {
    if (vulnerabilities.length === 0) {
      return [];
    }

    logger.info(`Starting deduplication of ${vulnerabilities.length} vulnerabilities`);

    const groups = this.groupDuplicates(vulnerabilities);
    const deduplicated = this.mergeGroups(groups);

    const removedCount = vulnerabilities.length - deduplicated.length;
    logger.info(`Deduplication complete: ${removedCount} duplicates removed, ${deduplicated.length} unique vulnerabilities`);

    return deduplicated;
  }

  /**
   * Groupe les vulnérabilités en identifiant les doublons potentiels
   */
  private groupDuplicates(vulnerabilities: Vulnerability[]): DuplicateGroup[] {
    const groups: DuplicateGroup[] = [];
    const processed = new Set<string>();

    for (const vuln of vulnerabilities) {
      if (processed.has(vuln.id)) {
        continue;
      }

      const group: DuplicateGroup = {
        master: vuln,
        duplicates: []
      };

      for (const other of vulnerabilities) {
        if (vuln.id !== other.id && !processed.has(other.id)) {
          if (this.areDuplicates(vuln, other)) {
            group.duplicates.push(other);
            processed.add(other.id);
          }
        }
      }

      processed.add(vuln.id);
      groups.push(group);
    }

    return groups;
  }

  /**
   * Détermine si deux vulnérabilités sont des doublons
   */
  private areDuplicates(a: Vulnerability, b: Vulnerability): boolean {
    // Score de similarité
    let score = 0;

    // Même fichier (très important)
    if (this.normalizeFilePath(a.location.file) === this.normalizeFilePath(b.location.file)) {
      score += 40;
    }

    // Même ligne ou lignes proches (± 5 lignes)
    if (a.location.line && b.location.line) {
      if (a.location.line === b.location.line) {
        score += 30;
      } else if (Math.abs(a.location.line - b.location.line) <= 5) {
        score += 15;
      }
    }

    // Même catégorie
    if (a.category === b.category) {
      score += 20;
    }

    // Même CWE (très pertinent)
    if (a.cwe && b.cwe && a.cwe === b.cwe) {
      score += 25;
    }

    // Titres similaires
    if (this.areTitlesSimilar(a.title, b.title)) {
      score += 15;
    }

    // Même sévérité
    if (a.severity === b.severity) {
      score += 5;
    }

    // Seuil de similarité: 60% est considéré comme un doublon
    return score >= 60;
  }

  /**
   * Normalise un chemin de fichier pour la comparaison
   */
  private normalizeFilePath(path: string): string {
    return path
      .toLowerCase()
      .replace(/\\/g, '/')
      .replace(/^\/+/, '')
      .replace(/\/+$/, '');
  }

  /**
   * Vérifie si deux titres sont similaires
   */
  private areTitlesSimilar(title1: string, title2: string): boolean {
    const normalize = (s: string) => s.toLowerCase()
      .replace(/[^a-z0-9]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

    const t1 = normalize(title1);
    const t2 = normalize(title2);

    // Égalité exacte après normalisation
    if (t1 === t2) return true;

    // Similarité basée sur les mots communs
    const words1 = new Set(t1.split(' ').filter(w => w.length > 2));
    const words2 = new Set(t2.split(' ').filter(w => w.length > 2));

    if (words1.size === 0 || words2.size === 0) return false;

    let commonWords = 0;
    for (const word of words1) {
      if (words2.has(word)) {
        commonWords++;
      }
    }

    const similarity = commonWords / Math.max(words1.size, words2.size);
    return similarity >= 0.5;
  }

  /**
   * Fusionne les groupes de doublons en une seule vulnérabilité
   */
  private mergeGroups(groups: DuplicateGroup[]): Vulnerability[] {
    return groups.map(group => this.mergeVulnerabilities(group));
  }

  /**
   * Fusionne un groupe de vulnérabilités en une seule
   */
  private mergeVulnerabilities(group: DuplicateGroup): Vulnerability {
    if (group.duplicates.length === 0) {
      return group.master;
    }

    const all = [group.master, ...group.duplicates];

    // Sélectionner la vulnérabilité principale (celle avec le plus d'infos)
    const master = this.selectBestMaster(all);

    // Fusionner les informations
    const merged: Vulnerability = {
      id: uuidv4(), // Nouvel ID pour la vulnérabilité fusionnée
      title: master.title,
      severity: this.getMostSevereSeverity(all),
      category: master.category,
      description: this.getBestDescription(all),
      location: master.location,
      cwe: this.getFirstNonNull(all.map(v => v.cwe)),
      cvss: this.getBestCVSS(all),
      recommendation: this.getBestRecommendation(all),
      references: this.mergeReferences(all),
      source: master.source,
      confidence: this.getHighestConfidence(all),
      detectedBy: this.mergeDetectedBy(all),
      rawData: master.rawData
    };

    logger.debug(`Merged ${all.length} vulnerabilities into one`, {
      sources: merged.detectedBy,
      file: merged.location.file
    });

    return merged;
  }

  /**
   * Sélectionne la meilleure vulnérabilité comme master
   */
  private selectBestMaster(vulnerabilities: Vulnerability[]): Vulnerability {
    // Prioriser par score de qualité
    return vulnerabilities.reduce((best, current) => {
      const bestScore = this.calculateQualityScore(best);
      const currentScore = this.calculateQualityScore(current);
      return currentScore > bestScore ? current : best;
    });
  }

  /**
   * Calcule un score de qualité pour une vulnérabilité
   */
  private calculateQualityScore(vuln: Vulnerability): number {
    let score = 0;

    if (vuln.description && vuln.description.length > 50) score += 10;
    if (vuln.cwe) score += 15;
    if (vuln.cvss) score += 10;
    if (vuln.recommendation && vuln.recommendation.length > 20) score += 10;
    if (vuln.references.length > 0) score += 5;
    if (vuln.location.line) score += 5;
    if (vuln.location.codeSnippet) score += 5;
    if (vuln.confidence === 'high') score += 10;

    return score;
  }

  /**
   * Obtient la sévérité la plus élevée
   */
  private getMostSevereSeverity(vulnerabilities: Vulnerability[]): Vulnerability['severity'] {
    return vulnerabilities.reduce((highest, current) => {
      return severityOrder[current.severity] > severityOrder[highest]
        ? current.severity
        : highest;
    }, vulnerabilities[0].severity);
  }

  /**
   * Obtient la meilleure description
   */
  private getBestDescription(vulnerabilities: Vulnerability[]): string {
    const descriptions = vulnerabilities
      .map(v => v.description)
      .filter(d => d && d.length > 0)
      .sort((a, b) => b.length - a.length);

    return descriptions[0] || 'Aucune description disponible';
  }

  /**
   * Obtient le meilleur score CVSS
   */
  private getBestCVSS(vulnerabilities: Vulnerability[]): Vulnerability['cvss'] {
    const cvssScores = vulnerabilities
      .filter(v => v.cvss)
      .map(v => v.cvss!);

    if (cvssScores.length === 0) return undefined;

    return cvssScores.reduce((highest, current) =>
      current.score > highest.score ? current : highest
    );
  }

  /**
   * Obtient la meilleure recommandation
   */
  private getBestRecommendation(vulnerabilities: Vulnerability[]): string | undefined {
    const recommendations = vulnerabilities
      .map(v => v.recommendation)
      .filter((r): r is string => !!r && r.length > 0)
      .sort((a, b) => b.length - a.length);

    return recommendations[0];
  }

  /**
   * Fusionne les références
   */
  private mergeReferences(vulnerabilities: Vulnerability[]): string[] {
    const allRefs = new Set<string>();

    for (const vuln of vulnerabilities) {
      for (const ref of vuln.references) {
        allRefs.add(ref);
      }
    }

    return Array.from(allRefs);
  }

  /**
   * Obtient la confiance la plus élevée
   */
  private getHighestConfidence(vulnerabilities: Vulnerability[]): Vulnerability['confidence'] {
    const confidenceOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };

    return vulnerabilities.reduce((highest: Vulnerability['confidence'], current) => {
      return confidenceOrder[current.confidence] > confidenceOrder[highest]
        ? current.confidence
        : highest;
    }, vulnerabilities[0].confidence);
  }

  /**
   * Fusionne les sources de détection
   */
  private mergeDetectedBy(vulnerabilities: Vulnerability[]): string[] {
    const sources = new Set<string>();

    for (const vuln of vulnerabilities) {
      sources.add(vuln.source);
      for (const detector of vuln.detectedBy) {
        sources.add(detector);
      }
    }

    return Array.from(sources);
  }

  /**
   * Obtient la première valeur non nulle
   */
  private getFirstNonNull<T>(values: (T | undefined)[]): T | undefined {
    return values.find(v => v !== undefined && v !== null);
  }
}

export const deduplicatorService = new DeduplicatorService();
