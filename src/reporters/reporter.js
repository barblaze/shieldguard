export function generateReport(results, options = {}) {
  const {
    format = 'json',
    includeMetadata = true,
    severityLevels = ['CRÍTICO', 'ALTO', 'MEDIO', 'BAJO'],
  } = options;

  const metadata = includeMetadata ? {
    generatedAt: new Date().toISOString(),
    version: '2.0.0',
    tool: 'ShieldGuard SAST',
    totalFindings: results.length,
    summary: {
      CRÍTICO: results.filter(r => r.severity === 'CRÍTICO').length,
      ALTO: results.filter(r => r.severity === 'ALTO').length,
      MEDIO: results.filter(r => r.severity === 'MEDIO').length,
      BAJO: results.filter(r => r.severity === 'BAJO').length,
    }
  } : null;

  const filtered = results.filter(r => severityLevels.includes(r.severity));

  switch (format) {
    case 'json':
      return JSON.stringify({
        ...(metadata || {}),
        findings: filtered,
      }, null, 2);

    case 'sarif':
      return generateSARIF(filtered, metadata);

    case 'csv':
      return generateCSV(filtered);

    default:
      return JSON.stringify({ error: 'Unknown format' }, null, 2);
  }
}

function generateSARIF(results, metadata) {
  const runs = results.map(r => ({
    tool: {
      driver: {
        name: 'ShieldGuard SAST',
        version: metadata?.version || '2.0.0',
        rules: [...new Set(results.map(f => f.id))].map(id => ({
          id,
          name: results.find(f => f.id === id)?.name || id,
        }))
      }
    },
    results: results.map(f => ({
      ruleId: f.id,
      level: f.severity === 'CRÍTICO' ? 'error' : f.severity === 'ALTO' ? 'warning' : 'note',
      message: { text: f.message || f.name },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.path },
          region: { startLine: f.line }
        }
      }]
    }))
  }));

  return JSON.stringify({
    version: '2.1.0',
    schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs,
  }, null, 2);
}

function generateCSV(results) {
  const header = 'ID,Name,Type,Severity,Path,Line,Message\n';
  const rows = results.map(f => [
    f.id,
    f.name,
    f.type,
    f.severity,
    f.path,
    f.line || '',
    (f.message || '').replace(/"/g, '""'),
  ].join(',')).join('\n');

  return header + rows;
}

export function downloadReport(content, filename = 'sast-report.json') {
  const blob = new Blob([content], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function getSeverityColor(severity) {
  const colors = {
    CRÍTICO: '#ef4444',
    ALTO: '#f97316',
    MEDIO: '#eab308',
    BAJO: '#22c55e',
  };
  return colors[severity] || '#6b7280';
}

export function getSeverityIcon(severity) {
  const icons = {
    CRÍTICO: '🔴',
    ALTO: '🟠',
    MEDIO: '🟡',
    BAJO: '🟢',
  };
  return icons[severity] || '⚪';
}