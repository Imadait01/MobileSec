import { GenerateReportSchema } from './generate-report.model';

export const GenerateReportRequestSchema = GenerateReportSchema;
export type GenerateReportRequest = ReturnType<typeof GenerateReportSchema['parse']> & any;

export type ReportStatus = 'pending' | 'processing' | 'completed' | 'failed';

export type ScanMetadata = {
  startTime?: string;
  endTime?: string;
  duration?: number;
  tools?: string[];
  targetBranch?: string;
  commitHash?: string;
  pipelineId?: string;
};


export type ReportOptions = {
  includeSummary?: boolean;
  includeRecommendations?: boolean;
  includeRawFindings?: boolean;
  includePerServiceDetails?: boolean;
  maxFindingsPerService?: number;
  includeRawServiceOutput?: boolean;
  template?: string;
};

export const ReportOptionsSchema = { parse: (v: any) => v } as any;

export type Report = {
  reportId: string;
  projectName: string;
  vulnerabilities: any[];
  metrics: any;
  generatedAt?: string;
  format?: string;
  status?: ReportStatus;
  filePath?: string;
  services?: any;
  priorityRecommendations?: any;
  scanMetadata?: ScanMetadata;
  error?: any;
};

export { GenerateReportSchema };
