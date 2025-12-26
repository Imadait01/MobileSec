export function mapSeverity(s: any): string {
  if (!s) return 'info';
  const sv = String(s).toLowerCase();
  if (sv === 'critical' || sv === 'crit') return 'critical';
  if (sv === 'high' || sv === 'h') return 'high';
  if (sv === 'medium' || sv === 'moderate' || sv === 'med') return 'medium';
  if (sv === 'low' || sv === 'l') return 'low';
  return 'info';
}

export function normalizeFinding(raw: any, serviceName?: string) {
  if (!raw || typeof raw !== 'object') {
    const title = String(raw || 'Finding');
    return {
      title,
      description: '',
      severity: 'info',
      file: '',
      line: 1,
      impact: undefined,
      proof: undefined,
      recommendation: undefined,
      raw: raw,
      rawString: typeof raw === 'string' ? raw : JSON.stringify(raw)
    } as any;
  }

  // Helper to pick first existing key from a list
  const pick = (obj: any, keys: string[]) => {
    for (const k of keys) {
      const v = obj[k];
      if (v !== undefined && v !== null && v !== '') return v;
    }
    return undefined;
  };

  const title = pick(raw, ['title', 'ruleId', 'rule_id', 'id', 'name', 'vulnerability', 'type', 'issue', 'rule', 'ruleName', 'rule_name', 'signature', 'message']) ||
    // if there is a nested object with identifier-like fields, stringify a small sample
    (raw && raw.match ? (typeof raw.match === 'string' ? raw.match : JSON.stringify(raw.match).slice(0, 120)) : undefined) ||
    (serviceName ? `${serviceName} finding` : 'Finding');

  const description = pick(raw, ['description', 'message', 'detail', 'summary', 'explanation', 'reason']) || '';

  const severity = mapSeverity(pick(raw, ['severity', 'sev', 'severity_level', 'level', 'confidence']));

  const file = pick(raw, ['file', 'file_path', 'filePath', 'path', 'location', 'filename', 'fileName']) ||
    (raw && raw.location && (raw.location.path || raw.location.file || raw.location.filename)) || '';

  const line = Number(pick(raw, ['line', 'lineNumber', 'line_number'])) || 1;

  const recommendation = pick(raw, ['recommendation', 'fix', 'suggestion', 'remediation']) || undefined;
  const proof = pick(raw, ['proof', 'evidence', 'match']) || undefined;
  const impact = pick(raw, ['impact']) || undefined;

  // Create a concise JSON snippet for fallback details
  let rawString = '';
  try {
    rawString = JSON.stringify(raw, null, 2);
  } catch (e) {
    rawString = String(raw);
  }

  // Compose a helpful description if empty
  const finalDescription = description || (rawString && rawString.length < 400 ? rawString : (description || ''));

  return {
    title: String(title),
    description: String(finalDescription),
    severity,
    file: String(file || ''),
    line: Number(line || 1),
    recommendation,
    proof,
    impact,
    raw,
    rawString
  } as any;
}
