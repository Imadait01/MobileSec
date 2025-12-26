#!/usr/bin/env node
/**
 * Script CLI pour générer automatiquement un rapport
 * à partir des fichiers JSON dans le dossier input
 * 
 * Usage: 
 *   npx ts-node src/cli.ts
 *   node dist/cli.js
 *   npm run generate
 */

import dotenv from 'dotenv';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Charger les variables d'environnement
dotenv.config();

import logger from './utils/logger';
import { fileWatcherService } from './services/file-watcher.service';
import { aggregatorService } from './services/aggregator.service';
import { deduplicatorService } from './services/deduplicator.service';
import { metricsService } from './services/metrics.service';
import { pdfGeneratorService } from './services/pdf-generator.service';
import { jsonExporterService } from './services/json-exporter.service';
import { sarifExporterService } from './services/sarif-exporter.service';
import { Report, ReportOptions, ReportOptionsSchema } from './models';

// Configuration depuis les variables d'environnement ou valeurs par défaut
const CONFIG = {
  projectName: process.env.PROJECT_NAME || 'Security Scan Report',
  format: (process.env.REPORT_FORMAT || 'pdf') as 'pdf' | 'json' | 'sarif',
  outputDir: process.env.OUTPUT_DIR || './reports',
  template: process.env.REPORT_TEMPLATE || 'security_report',
  companyName: process.env.COMPANY_NAME || 'Security Team',
  inputDir: process.env.INPUT_DIR || './input',
  autoOpen: process.env.AUTO_OPEN === 'true',
  clearInputAfter: process.env.CLEAR_INPUT_AFTER === 'true'
};

async function ensureOutputDir(): Promise<void> {
  await fs.mkdir(CONFIG.outputDir, { recursive: true });
}

async function generateReport(): Promise<void> {
  const startTime = Date.now();
  
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   🔒 ReportGen - Automatic Security Report Generator         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
  `);

  console.log('📁 Input directory:', path.resolve(CONFIG.inputDir));
  console.log('📄 Output directory:', path.resolve(CONFIG.outputDir));
  console.log('📝 Project name:', CONFIG.projectName);
  console.log('📊 Format:', CONFIG.format.toUpperCase());
  console.log('');

  // 1. Lire les fichiers d'entrée
  console.log('🔍 Scanning input directory for JSON files...');
  const { files, errors } = await fileWatcherService.readAllInputFiles();

  if (files.length === 0) {
    console.log('');
    console.log('❌ No valid scan files found in input directory!');
    console.log('');
    console.log('💡 Please place your JSON scan results in the input folder:');
    console.log(`   ${path.resolve(CONFIG.inputDir)}`);
    console.log('');
    console.log('   Supported formats:');
    console.log('   • SonarQube results (SAST)');
    console.log('   • Snyk results (SCA)');
    console.log('   • TruffleHog results (Secrets)');
    console.log('   • OWASP ZAP results (DAST)');
    console.log('');
    
    if (errors.length > 0) {
      console.log('⚠️  Errors encountered:');
      errors.forEach(err => console.log(`   - ${err}`));
    }
    
    process.exit(1);
  }

  console.log(`✅ Found ${files.length} scan file(s):`);
  files.forEach(f => {
    console.log(`   • ${f.filename} (${f.type.toUpperCase()} - ${f.tool})`);
  });
  console.log('');

  if (errors.length > 0) {
    console.log('⚠️  Some files had errors:');
    errors.forEach(err => console.log(`   - ${err}`));
    console.log('');
  }

  // 2. Combiner les fichiers
  console.log('🔄 Combining scan results...');
  const requestData = fileWatcherService.combineFilesToRequest(
    files,
    CONFIG.projectName,
    CONFIG.format,
    {
      template: CONFIG.template,
      companyName: CONFIG.companyName,
      includeSummary: true,
      includeRecommendations: true
    }
  );

  // 3. Agréger les résultats
  console.log('📊 Aggregating vulnerabilities...');
  const aggregatedVulns = aggregatorService.aggregateResults(requestData.scanResults);
  console.log(`   Found ${aggregatedVulns.length} raw vulnerabilities`);

  // 4. Dédupliquer
  console.log('🔍 Deduplicating vulnerabilities...');
  const deduplicatedVulns = deduplicatorService.deduplicate(aggregatedVulns);
  console.log(`   ${deduplicatedVulns.length} unique vulnerabilities after deduplication`);

  // 5. Calculer les métriques
  console.log('📈 Calculating security metrics...');
  const metrics = metricsService.calculateMetrics(deduplicatedVulns);

  // 6. Construire le rapport
  const reportId = uuidv4();
  const report: Report = {
    reportId,
    projectName: CONFIG.projectName,
    vulnerabilities: deduplicatedVulns,
    metrics,
    scanMetadata: {
      startTime: new Date().toISOString(),
      endTime: new Date().toISOString(),
      duration: Math.round((Date.now() - startTime) / 1000),
      tools: files.map(f => f.tool).filter((v, i, a) => a.indexOf(v) === i)
    },
    generatedAt: new Date().toISOString(),
    format: CONFIG.format,
    status: 'processing'
  };

  // 7. Générer le fichier de sortie
  console.log('');
  console.log(`📝 Generating ${CONFIG.format.toUpperCase()} report...`);
  
  const options: ReportOptions = ReportOptionsSchema.parse({
    template: CONFIG.template,
    companyName: CONFIG.companyName,
    includeSummary: true,
    includeRecommendations: true
  });

  let outputPath: string;
  
  switch (CONFIG.format) {
    case 'pdf':
      outputPath = await pdfGeneratorService.generatePdf(report, options);
      break;
    case 'json':
      outputPath = await jsonExporterService.exportToJson(report, { pretty: true });
      break;
    case 'sarif':
      outputPath = await sarifExporterService.exportToSarif(report);
      break;
    default:
      throw new Error(`Unsupported format: ${CONFIG.format}`);
  }

  // 8. Copier vers le dossier de sortie avec un nom propre
  await ensureOutputDir();
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const extension = CONFIG.format === 'sarif' ? 'sarif.json' : CONFIG.format;
  const finalFilename = `${CONFIG.projectName.replace(/[^a-zA-Z0-9]/g, '-')}_${timestamp}.${extension}`;
  const finalPath = path.join(CONFIG.outputDir, finalFilename);
  
  await fs.copyFile(outputPath, finalPath);

  const duration = Math.round((Date.now() - startTime) / 1000);

  // 9. Afficher le résumé
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║                    📊 REPORT SUMMARY                         ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`   🎯 Security Score: ${metrics.securityScore}/100`);
  console.log('');
  console.log('   📊 Vulnerabilities by Severity:');
  console.log(`      🔴 Critical: ${metrics.bySeverity.critical}`);
  console.log(`      🟠 High:     ${metrics.bySeverity.high}`);
  console.log(`      🟡 Medium:   ${metrics.bySeverity.medium}`);
  console.log(`      🟢 Low:      ${metrics.bySeverity.low}`);
  console.log(`      ⚪ Info:     ${metrics.bySeverity.info}`);
  console.log('');
  console.log(`   📁 Total: ${metrics.total} vulnerabilities`);
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');
  console.log(`✅ Report generated successfully!`);
  console.log(`📄 Output: ${path.resolve(finalPath)}`);
  console.log(`⏱️  Duration: ${duration}s`);
  console.log('');

  // 10. Nettoyer le dossier input si demandé
  if (CONFIG.clearInputAfter) {
    console.log('🧹 Clearing input directory...');
    await fileWatcherService.clearInputDirectory();
  }

  // 11. Ouvrir automatiquement le rapport si demandé
  if (CONFIG.autoOpen && CONFIG.format === 'pdf') {
    console.log('📂 Opening report...');
    const { exec } = await import('child_process');
    const openCommand = process.platform === 'win32' ? 'start' :
                        process.platform === 'darwin' ? 'open' : 'xdg-open';
    exec(`${openCommand} "${finalPath}"`);
  }
}

// Exécuter
generateReport()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error('');
    console.error('❌ Error generating report:', error.message);
    logger.error('Report generation failed', { error });
    process.exit(1);
  });
