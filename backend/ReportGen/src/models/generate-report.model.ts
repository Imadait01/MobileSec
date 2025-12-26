import { z } from 'zod';

export const VulnerabilitySchema = z.object({
  id: z.string().optional(),
  title: z.string(),
  description: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  impact: z.string().optional(),
  proof: z.any().optional(),
  recommendation: z.string().optional(),
  file: z.string().optional(),
  line: z.number().optional()
});

export const ResultsSchema = z.object({
  secretHunter: z.array(VulnerabilitySchema).optional(),
  cryptoCheck: z.array(VulnerabilitySchema).optional(),
  networkInspector: z.array(VulnerabilitySchema).optional()
});

export const GenerateReportSchema = z.object({
  format: z.enum(['pdf', 'json', 'sarif']).default('pdf'),
  template: z.string().default('security_report'),
  metadata: z.record(z.any()).optional(),
  results: ResultsSchema.optional(),
  scanResults: z.record(z.any()).optional(),
  projectName: z.string().optional(),
  scanId: z.string().optional(),
  options: z.object({
    maxVulnerabilities: z.number().optional(),
    templateVars: z.record(z.any()).optional()
  }).optional()
});

export type GenerateReportRequest = z.infer<typeof GenerateReportSchema>;
export type Vulnerability = z.infer<typeof VulnerabilitySchema>;