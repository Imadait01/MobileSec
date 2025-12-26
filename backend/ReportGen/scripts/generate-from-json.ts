import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';
dotenv.config();

import { pdfGeneratorService } from '../src/services/index';
import { metricsService } from '../src/services/index';

async function main() {
  const fp = process.argv[2] || path.join(process.cwd(), 'payload_pdf.json');
  const outDir = process.env.OUTPUT_DIR || path.join(process.cwd(), 'tmp');
  await fs.mkdir(outDir, { recursive: true });

  console.log('Reading file:', fp);
  const raw = await fs.readFile(fp, 'utf-8');
  const parsed = JSON.parse(raw);

  // Build a Report object expected by pdfGeneratorService
  const reportId = parsed.reportId || `cli-${Date.now()}`;
  const projectName = parsed.projectName || parsed.project || parsed.name || 'Report Security';
  const services = parsed.services || parsed.scanResults || parsed.results || {};
  const vulnerabilities = parsed.vulnerabilities || [];
  const metrics = parsed.metrics || metricsService.calculateMetrics(vulnerabilities);

  const report: any = {
    reportId,
    projectName,
    vulnerabilities,
    metrics,
    scanMetadata: {
      startTime: new Date().toISOString(),
      tools: Object.keys(services || {})
    },
    services,
    generatedAt: new Date().toISOString(),
    format: 'pdf',
    status: 'completed'
  };

  console.log('Generating PDF to tmp folder...');
  try {
    const pdfPath = await pdfGeneratorService.generatePdf(report, { template: 'security_report' } as any, path.join(outDir, `report-${reportId}.pdf`));
    console.log('PDF generated at:', pdfPath);
  } catch (e: any) {
    console.error('PDF generation failed:', e && (e.stack || e.message || e));
    process.exit(2);
  }
}

main().catch(e => { console.error('Error:', e); process.exit(1); });