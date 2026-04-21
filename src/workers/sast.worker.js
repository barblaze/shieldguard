import { RULES, LANGUAGE_EXTENSIONS, SKIP_DIRS, MAX_FILE_SIZE } from '../rules/rules.js';

let acorn = null;

async function getAcorn() {
  if (!acorn) {
    try {
      acorn = await import('acorn');
    } catch (e) {
      acorn = { parse: () => null };
    }
  }
  return acorn;
}

self.onmessage = async function(e) {
  const { files, options } = e.data;
  const results = [];
  const processed = { files: 0, secrets: 0, vulns: 0, filesFound: 0 };

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const path = file.webkitRelativePath || file.name;
    const name = file.name.toLowerCase();

    self.postMessage({ type: 'progress', processed: i + 1, total: files.length, current: path });

    if (SKIP_DIRS.has(path.split('/')[0])) continue;
    if (file.size > MAX_FILE_SIZE) continue;

    for (const f of RULES.files) {
      const pattern = f.name.replace('*', '');
      if (name.includes(pattern)) {
        results.push({
          id: `F-${f.label.toUpperCase().replace(/\s/g, '-')}`,
          type: 'SENSITIVE_FILE',
          name: f.label,
          severity: f.severity || 'CRÍTICO',
          path,
          line: 0,
          message: `Sensitive file ${f.label} detected`,
          confidence: 'high'
        });
        processed.filesFound++;
      }
    }

    const ext = '.' + name.split('.').pop();
    const isCode = Object.values(LANGUAGE_EXTENSIONS).some(rx => rx.test(ext));

    if (isCode && file.size < 512 * 1024) {
      try {
        const text = await file.text();
        const findings = await analyzeContent(text, path);
        results.push(...findings);

        processed.secrets += findings.filter(f => f.type === 'SECRET').length;
        processed.vulns += findings.filter(f => /V-/.test(f.id)).length;
      } catch (e) {
        results.push({
          id: 'E-READ-001',
          type: 'ERROR',
          name: 'Unable to read file',
          severity: 'BAJO',
          path,
          line: 0,
          message: `Error reading file: ${e.message}`,
          confidence: 'medium'
        });
      }
    }

    processed.files++;
  }

  self.postMessage({ type: 'complete', results, processed });
};

async function analyzeContent(code, filename) {
  const findings = [];
  const lines = code.split('\n');

  for (const rule of RULES.secrets) {
    let match;
    const rx = new RegExp(rule.pattern.source, rule.pattern.flags);
    
    while ((match = rx.exec(code)) !== null) {
      const lineNum = code.substring(0, match.index).split('\n').length;
      findings.push({
        id: rule.id,
        type: 'SECRET',
        name: rule.name,
        severity: rule.severity || 'CRÍTICO',
        path: filename,
        line: lineNum,
        message: `Hardcoded ${rule.name} detected`,
        matched: match[0].substring(0, 12) + '...',
        confidence: 'high'
      });
    }
  }

  for (const rule of RULES.vulnerabilities) {
    for (const pattern of rule.patterns) {
      let match;
      const rx = new RegExp(pattern.source, pattern.flags);
      
      while ((match = rx.exec(code)) !== null) {
        const lineNum = code.substring(0, match.index).split('\n').length;
        
        findings.push({
          id: rule.id,
          type: rule.category,
          name: rule.name,
          severity: rule.severity,
          path: filename,
          line: lineNum,
          message: `${rule.name} detected at line ${lineNum}`,
          confidence: 'high'
        });
      }
    }
  }

  return findings;
}