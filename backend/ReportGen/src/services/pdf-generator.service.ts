import puppeteer from 'puppeteer';
import Handlebars from 'handlebars';
import fs from 'fs/promises';
import path from 'path';
import logger from '../utils/logger';
import {
  Report,
  ReportOptions,
  Vulnerability,
  severityColors,
  severityLabels,
  categoryLabels,
  severityOrder
} from '../models';

export class PdfGeneratorService {
  private templatesDir: string;
  private tempDir: string;
  private timeout: number;

  constructor() {
    this.templatesDir = path.join(__dirname, '..', 'templates');
    this.tempDir = process.env.TEMP_DIR || './tmp';
    this.timeout = (parseInt(process.env.PDF_TIMEOUT_SECONDS || '60', 10)) * 1000;
  }

  /**
   * Génère un PDF à partir d'un rapport
   */
  async generatePdf(report: Report, options: ReportOptions): Promise<string> {
    logger.info(`Generating PDF report for ${report.projectName}`, {
      reportId: report.reportId,
      template: options.template
    });

    const startTime = Date.now();

    try {
      // Charger le template
      const templatePath = path.join(this.templatesDir, `${options.template}.html`);
      const templateContent = await fs.readFile(templatePath, 'utf-8');

      // Préparer les données pour le template
      const templateData = this.prepareTemplateData(report, options);

      // Compiler le template Handlebars
      this.registerHandlebarsHelpers();
      const template = Handlebars.compile(templateContent);
      const html = template(templateData);

      // Générer le PDF avec Puppeteer
      const outputPath = path.join(this.tempDir, `${report.reportId}.pdf`);
      await this.htmlToPdf(html, outputPath);

      const duration = Date.now() - startTime;
      logger.info(`PDF generated successfully in ${duration}ms`, {
        reportId: report.reportId,
        outputPath
      });

      return outputPath;
    } catch (error) {
      logger.error('Failed to generate PDF', { error, reportId: report.reportId });
      throw error;
    }
  }

  /**
   * Prépare les données pour le template
   */
  private prepareTemplateData(report: Report, options: ReportOptions): Record<string, unknown> {
    // Trier les vulnérabilités par sévérité
    const sortedVulns = [...report.vulnerabilities].sort((a, b) => {
      return severityOrder[b.severity] - severityOrder[a.severity];
    });

    // Grouper par sévérité
    const vulnsBySeverity = this.groupBySeverity(sortedVulns);

    // Préparer les données pour les graphiques
    const chartData = this.prepareChartData(report);

    // Générer les recommandations prioritaires
    const priorityRecommendations = this.generatePriorityRecommendations(sortedVulns);

    return {
      // Infos projet
      projectName: report.projectName,
      reportId: report.reportId,
      generatedAt: new Date(report.generatedAt).toLocaleDateString('fr-FR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      }),

      // Options
      includeSummary: options.includeSummary,
      includeRecommendations: options.includeRecommendations,
      companyName: options.companyName || 'Security Report',
      logoUrl: options.logoUrl,

      // Métriques
      metrics: report.metrics,
      securityScoreColor: this.getScoreColor(report.metrics.securityScore),
      riskLevel: this.getRiskLevel(report.metrics),
      riskLevelColor: this.getRiskLevelColor(report.metrics),

      // Vulnérabilités
      vulnerabilities: sortedVulns.map(v => ({
        ...v,
        severityColor: severityColors[v.severity],
        severityLabel: severityLabels[v.severity],
        categoryLabel: categoryLabels[v.category] || v.category
      })),
      vulnsBySeverity,

      // Données pour les graphiques
      chartData: JSON.stringify(chartData),
      severityChartData: JSON.stringify(chartData.severity),
      categoryChartData: JSON.stringify(chartData.category),

      // Recommandations
      priorityRecommendations,

      // Métadonnées
      scanMetadata: {
        ...report.scanMetadata,
        formattedStartTime: new Date(report.scanMetadata.startTime).toLocaleString('fr-FR'),
        formattedDuration: report.scanMetadata.duration
          ? this.formatDuration(report.scanMetadata.duration)
          : 'N/A'
      },

      // Statistiques additionnelles
      hasVulnerabilities: sortedVulns.length > 0,
      hasCritical: report.metrics.bySeverity.critical > 0,
      hasHigh: report.metrics.bySeverity.high > 0,

      // Couleurs
      severityColors,
      severityLabels
    };
  }

  /**
   * Groupe les vulnérabilités par sévérité
   */
  private groupBySeverity(vulnerabilities: Vulnerability[]): Record<string, Vulnerability[]> {
    const groups: Record<string, Vulnerability[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    for (const vuln of vulnerabilities) {
      groups[vuln.severity].push(vuln);
    }

    return groups;
  }

  /**
   * Prépare les données pour les graphiques Chart.js
   */
  private prepareChartData(report: Report): Record<string, unknown> {
    // Données pour le graphique des sévérités
    const severityData = {
      labels: ['Critique', 'Élevée', 'Moyenne', 'Faible', 'Info'],
      data: [
        report.metrics.bySeverity.critical,
        report.metrics.bySeverity.high,
        report.metrics.bySeverity.medium,
        report.metrics.bySeverity.low,
        report.metrics.bySeverity.info
      ],
      colors: [
        severityColors.critical,
        severityColors.high,
        severityColors.medium,
        severityColors.low,
        severityColors.info
      ]
    };

    // Données pour le graphique des catégories
    const categoryEntries = Object.entries(report.metrics.byCategory)
      .sort((a, b) => (b[1] as number) - (a[1] as number))
      .slice(0, 10);

    const categoryData = {
      labels: categoryEntries.map(([cat]) => categoryLabels[cat as keyof typeof categoryLabels] || cat),
      data: categoryEntries.map(([, count]) => count),
      colors: this.generateCategoryColors(categoryEntries.length)
    };

    return {
      severity: severityData,
      category: categoryData
    };
  }

  /**
   * Génère des couleurs pour les catégories
   */
  private generateCategoryColors(count: number): string[] {
    const baseColors = [
      '#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6',
      '#EC4899', '#06B6D4', '#84CC16', '#F97316', '#6366F1'
    ];
    return baseColors.slice(0, count);
  }

  /**
   * Génère les recommandations prioritaires
   */
  private generatePriorityRecommendations(vulnerabilities: Vulnerability[]): string[] {
    const recommendations: string[] = [];
    const seen = new Set<string>();

    // Parcourir les vulnérabilités par ordre de sévérité
    for (const vuln of vulnerabilities) {
      if (vuln.recommendation && !seen.has(vuln.recommendation)) {
        recommendations.push(vuln.recommendation);
        seen.add(vuln.recommendation);
      }

      if (recommendations.length >= 10) break;
    }

    return recommendations;
  }

  /**
   * Obtient la couleur du score de sécurité
   */
  private getScoreColor(score: number): string {
    if (score >= 80) return '#10B981';
    if (score >= 60) return '#F59E0B';
    if (score >= 40) return '#F97316';
    return '#EF4444';
  }

  /**
   * Détermine le niveau de risque
   */
  private getRiskLevel(metrics: Report['metrics']): string {
    if (metrics.bySeverity.critical > 0) return 'CRITIQUE';
    if (metrics.bySeverity.high > 5) return 'CRITIQUE';
    if (metrics.bySeverity.high > 0) return 'ÉLEVÉ';
    if (metrics.bySeverity.medium > 10) return 'ÉLEVÉ';
    if (metrics.bySeverity.medium > 0) return 'MOYEN';
    if (metrics.bySeverity.low > 0) return 'FAIBLE';
    return 'AUCUN';
  }

  /**
   * Obtient la couleur du niveau de risque
   */
  private getRiskLevelColor(metrics: Report['metrics']): string {
    const level = this.getRiskLevel(metrics);
    const colors: Record<string, string> = {
      'CRITIQUE': '#DC2626',
      'ÉLEVÉ': '#EA580C',
      'MOYEN': '#CA8A04',
      'FAIBLE': '#2563EB',
      'AUCUN': '#10B981'
    };
    return colors[level] || '#6B7280';
  }

  /**
   * Formate la durée en texte lisible
   */
  private formatDuration(seconds: number): string {
    if (seconds < 60) return `${seconds} secondes`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes} min ${remainingSeconds} sec`;
  }

  /**
   * Enregistre les helpers Handlebars
   */
  private registerHandlebarsHelpers(): void {
    // Helper pour comparer des valeurs
    Handlebars.registerHelper('eq', (a: unknown, b: unknown) => a === b);

    // Helper pour vérifier si une valeur est supérieure
    Handlebars.registerHelper('gt', (a: number, b: number) => a > b);

    // Helper pour formater un nombre
    Handlebars.registerHelper('formatNumber', (num: unknown) =>
      typeof num === 'number' ? num.toLocaleString('fr-FR') : num
    );

    // Helper pour obtenir la couleur de sévérité
    Handlebars.registerHelper('severityColor', (severity: string) =>
      severityColors[severity as keyof typeof severityColors] || '#6B7280'
    );

    // Helper pour tronquer du texte
    Handlebars.registerHelper('truncate', (text: string, length: number) => {
      if (!text) return '';
      if (text.length <= length) return text;
      return text.substring(0, length) + '...';
    });

    // Helper pour échapper le HTML dans les snippets de code
    Handlebars.registerHelper('escapeCode', (code: string) => {
      if (!code) return '';
      return Handlebars.Utils.escapeExpression(code);
    });

    // Helper pour itérer sur un objet
    Handlebars.registerHelper('eachObject', function (this: unknown, context: Record<string, unknown>, options: Handlebars.HelperOptions) {
      let result = '';
      for (const key in context) {
        if (Object.prototype.hasOwnProperty.call(context, key)) {
          result += options.fn({ key, value: context[key] });
        }
      }
      return result;
    });

    // Helper pour ajouter un index
    Handlebars.registerHelper('addIndex', function (this: unknown, array: unknown[], options: Handlebars.HelperOptions) {
      return array.map((item: unknown, index: number) =>
        options.fn({ ...item as object, index: index + 1 })
      ).join('');
    });
  }

  /**
   * Convertit le HTML en PDF avec Puppeteer
   */
  private async htmlToPdf(html: string, outputPath: string): Promise<void> {
    let browser;

    try {
      logger.info('Launching Puppeteer with Chromium...');
      browser = await puppeteer.launch({
        headless: 'new',
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined,
        dumpio: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--no-first-run',
          '--disable-extensions',
          '--disable-accelerated-2d-canvas',
          '--disable-software-rasterizer',
          '--disable-web-security',
          '--disable-features=IsolateOrigins,site-per-process'
        ]
      });
      logger.info('Puppeteer launched successfully');

      const page = await browser.newPage();

      // Définir le contenu HTML
      await page.setContent(html, {
        waitUntil: 'networkidle0',
        timeout: this.timeout
      });

      // Attendre que les graphiques Chart.js soient rendus
      await page.waitForFunction(
        `document.querySelectorAll('canvas').length === 0 || Array.from(document.querySelectorAll('canvas')).every(c => c.getContext('2d'))`,
        { timeout: 10000 }
      ).catch(() => {
        logger.warn('Charts may not be fully rendered');
      });

      // Générer le PDF
      await page.pdf({
        path: outputPath,
        format: 'A4',
        printBackground: true,
        margin: {
          top: '20mm',
          right: '15mm',
          bottom: '20mm',
          left: '15mm'
        },
        displayHeaderFooter: true,
        headerTemplate: `
          <div style="font-size: 9px; width: 100%; text-align: center; color: #666;">
            Rapport de sécurité
          </div>
        `,
        footerTemplate: `
          <div style="font-size: 9px; width: 100%; display: flex; justify-content: space-between; padding: 0 20px; color: #666;">
            <span>Généré le ${new Date().toLocaleDateString('fr-FR')}</span>
            <span>Page <span class="pageNumber"></span> sur <span class="totalPages"></span></span>
          </div>
        `
      });

      logger.debug('PDF file written', { outputPath });
    } finally {
      if (browser) {
        await browser.close();
      }
    }
  }

  /**
   * Vérifie si le template existe
   */
  async templateExists(templateName: string): Promise<boolean> {
    try {
      const templatePath = path.join(this.templatesDir, `${templateName}.html`);
      await fs.access(templatePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Liste les templates disponibles
   */
  async listTemplates(): Promise<string[]> {
    try {
      const files = await fs.readdir(this.templatesDir);
      return files
        .filter((f: string) => f.endsWith('.html'))
        .map((f: string) => f.replace('.html', ''));
    } catch {
      return ['softwareX'];
    }
  }
}

export const pdfGeneratorService = new PdfGeneratorService();
