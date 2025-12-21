import { z } from 'zod';
import { VulnerabilitySchema } from './vulnerability.model';

// Énumération des formats de rapport
export const ReportFormatEnum = z.enum(['pdf', 'json', 'sarif']);
export type ReportFormat = z.infer<typeof ReportFormatEnum>;

// Énumération des statuts de rapport
export const ReportStatusEnum = z.enum(['pending', 'processing', 'completed', 'failed']);
export type ReportStatus = z.infer<typeof ReportStatusEnum>;

// Schéma des métriques par sévérité
export const SeverityMetricsSchema = z.object({
  critical: z.number().default(0),
  high: z.number().default(0),
  medium: z.number().default(0),
  low: z.number().default(0),
  info: z.number().default(0)
});
export type SeverityMetrics = z.infer<typeof SeverityMetricsSchema>;

// Schéma des métriques par catégorie
export const CategoryMetricsSchema = z.record(z.string(), z.number());
export type CategoryMetrics = z.infer<typeof CategoryMetricsSchema>;

// Schéma des métriques globales
export const ReportMetricsSchema = z.object({
  total: z.number(),
  bySeverity: SeverityMetricsSchema,
  byCategory: CategoryMetricsSchema,
  securityScore: z.number().min(0).max(100),
  topAffectedFiles: z.array(z.object({
    file: z.string(),
    count: z.number()
  })).default([])
});
export type ReportMetrics = z.infer<typeof ReportMetricsSchema>;

// Schéma des métadonnées du scan
export const ScanMetadataSchema = z.object({
  startTime: z.string().datetime(),
  endTime: z.string().datetime().optional(),
  duration: z.number().optional(), // en secondes
  tools: z.array(z.string()),
  targetBranch: z.string().optional(),
  commitHash: z.string().optional(),
  pipelineId: z.string().optional()
});
export type ScanMetadata = z.infer<typeof ScanMetadataSchema>;

// Schéma du rapport complet
export const ReportSchema = z.object({
  reportId: z.string().uuid(),
  projectName: z.string(),
  vulnerabilities: z.array(VulnerabilitySchema),
  metrics: ReportMetricsSchema,
  scanMetadata: ScanMetadataSchema,
  generatedAt: z.string().datetime(),
  format: ReportFormatEnum,
  status: ReportStatusEnum,
  filePath: z.string().optional(),
  error: z.string().optional()
});
export type Report = z.infer<typeof ReportSchema>;

// Options de génération de rapport
export const ReportOptionsSchema = z.object({
  includeSummary: z.boolean().default(true),
  includeRecommendations: z.boolean().default(true),
  includeRawFindings: z.boolean().default(false),
  template: z.string().default('softwareX'),
  logoUrl: z.string().url().optional(),
  companyName: z.string().optional(),
  customCss: z.string().optional()
});
export type ReportOptions = z.infer<typeof ReportOptionsSchema>;

// Schéma des résultats de scan (entrée)
export const ScanResultsSchema = z.object({
  sast: z.array(z.object({
    tool: z.string(),
    findings: z.array(z.any())
  })).optional(),
  sca: z.array(z.object({
    tool: z.string(),
    vulnerabilities: z.array(z.any())
  })).optional(),
  secrets: z.array(z.object({
    tool: z.string(),
    findings: z.array(z.any())
  })).optional(),
  dast: z.array(z.object({
    tool: z.string(),
    findings: z.array(z.any())
  })).optional()
});
export type ScanResults = z.infer<typeof ScanResultsSchema>;

// Schéma de la requête de génération
export const GenerateReportRequestSchema = z.object({
  projectName: z.string().min(1).max(255),
  scanId: z.string().optional(), // Lien vers le scan_id dans MongoDB
  scanResults: ScanResultsSchema,
  format: ReportFormatEnum,
  options: ReportOptionsSchema.optional()
});
export type GenerateReportRequest = z.infer<typeof GenerateReportRequestSchema>;

// Schéma de la réponse de génération
export const GenerateReportResponseSchema = z.object({
  reportId: z.string().uuid(),
  status: ReportStatusEnum,
  message: z.string().optional()
});
export type GenerateReportResponse = z.infer<typeof GenerateReportResponseSchema>;

// Schéma de la réponse d'info de rapport
export const ReportInfoResponseSchema = z.object({
  reportId: z.string().uuid(),
  projectName: z.string(),
  status: ReportStatusEnum,
  format: ReportFormatEnum,
  metrics: ReportMetricsSchema.optional(),
  scanMetadata: ScanMetadataSchema.optional(),
  generatedAt: z.string().datetime().optional(),
  error: z.string().optional()
});
export type ReportInfoResponse = z.infer<typeof ReportInfoResponseSchema>;
