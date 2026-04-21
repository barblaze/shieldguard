import { parseJavaScript, findNodes, getCallees, getMemberObject } from '../parsers/parser.js';

export class TaintAnalyzer {
  constructor() {
    this.findings = [];
    this.tainted = new Set();
    this.sanitizers = new Set([
      'escape', 'sanitize', 'encode', 'encodeURIComponent', 'decodeURIComponent',
      'escapeHtml', 'unescapeHtml', 'htmlspecialchars', 'stripTags', 'trim',
      'parseInt', 'parseFloat', 'Number', 'String', 'Boolean',
      'query', 'prepare', 'execute', 'param', 'bind', 'quote',
      'exec', 'spawn', 'spawnSync', 'execFile', 'execFileSync'
    ]);
    this.sinks = {
      'query': ['execute', 'query', 'all', 'run', 'raw', 'any'],
      'exec': ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync'],
      'xss': ['innerHTML', 'outerHTML', 'write', 'insertAdjacentHTML', 'dangerouslySetInnerHTML'],
      'redirect': ['location', 'href', 'replace', 'assign', 'redirect', 'forward'],
      'crypto': ['createCipher', 'createDecipher', 'createHash', 'createSign', 'randomBytes'],
      'deserialize': ['unserialize', 'decode', 'parse', 'load', 'YAML.load', 'yaml.load']
    };
  }

  async analyze(code, filename, language = 'javascript') {
    this.findings = [];
    this.tainted.clear();
    this.filename = filename;
    this.code = code;

    if (language === 'javascript' || language === 'typescript') {
      return this.analyzeJS(code);
    }
    
    return this.findings;
  }

  analyzeJS(code) {
    const ast = { code, ...parseJavaScript(code, this.filename) };
    if (ast.error) return this.findings;

    this.checkTaint(ast);
    this.checkVulnerabilities(ast);
    this.checkHardcodedSecrets(ast);
    this.checkWeakCrypto(ast);

    return this.findings;
  }

  checkTaint(ast) {
    const dangerousCalls = [
      { method: 'query', fn: 'execute|query|all|run', severity: 'CRÍTICO', category: 'SQL_INJECTION' },
      { method: 'exec', fn: 'exec|execSync|execFile|spawn', severity: 'CRÍTICO', category: 'CMD_INJECTION' },
      { method: 'xss', fn: 'innerHTML|insertAdjacentHTML', severity: 'ALTO', category: 'XSS' },
      { method: 'redirect', fn: 'location|redirect', severity: 'ALTO', category: 'OPEN_REDIRECT' },
    ];

    const callSites = findNodes(ast, 'CallExpression');
    
    for (const call of callSites) {
      const calleeName = getCallees(call)[0] || '';
      const objName = getMemberObject(call.callee);

      for (const danger of dangerousCalls) {
        const methodName = danger.method;
        
        if (this.sinks[methodName]?.some(s => 
          calleeName.includes(s) || objName?.includes(s)
        )) {
          const args = call.arguments || [];
          let isTainted = false;
          let taintSource = '';

          for (const arg of args) {
            if (this.isTaintedArg(arg, ast)) {
              isTainted = true;
              taintSource = this.getTaintSource(arg, ast);
              break;
            }
          }

          if (isTainted) {
            this.findings.push({
              id: `T-${methodName.toUpperCase()}-001`,
              type: danger.category,
              name: `${danger.category.replace('_', ' ')} via ${calleeName}`,
              severity: danger.severity,
              path: this.filename,
              line: call.loc?.start?.line || 0,
              message: `Tainted input from ${taintSource} reaches sink ${calleeName}`,
              taintSource,
              sink: calleeName,
              confidence: 'high'
            });
          }
        }
      }
    }
  }

  isTaintedArg(arg, ast) {
    if (!arg) return false;
    
    if (arg.type === 'Identifier') {
      const name = arg.name;
      if (name.startsWith('req') || name.startsWith('body') || 
          name.startsWith('params') || name.startsWith('query') ||
          name.startsWith('input') || name.startsWith('user') ||
          name.startsWith('argv') || name.startsWith('process.argv')) {
        return true;
      }
    }

    if (arg.type === 'MemberExpression') {
      const obj = getMemberObject(arg);
      if (obj && (obj.startsWith('req') || obj.startsWith('body') || obj.startsWith('params'))) {
        return true;
      }
    }

    if (arg.type === 'BinaryExpression' || arg.type === 'TemplateLiteral') {
      return true;
    }

    return false;
  }

  getTaintSource(arg, ast) {
    if (arg.type === 'Identifier') return `parameter '${arg.name}'`;
    if (arg.type === 'MemberExpression') return `member access`;
    if (arg.type === 'BinaryExpression') return 'concatenated expression';
    if (arg.type === 'TemplateLiteral') return 'template literal';
    return 'unknown';
  }

  checkVulnerabilities(ast) {
    const dangerousPatterns = [
      { 
        check: (node) => node.type === 'CallExpression' && getCallees(node)[0] === 'eval',
        id: 'V-EVAL-001',
        name: 'Dangerous use of eval()',
        severity: 'CRÍTICO',
        type: 'CODE_INJECTION'
      },
      {
        check: (node) => {
          const callees = getCallees(node);
          return callees.some(c => c === 'document' && node.callee?.property?.name === 'write');
        },
        id: 'V-DOCWRITE-001',
        name: 'Use of document.write()',
        severity: 'MEDIO',
        type: 'XSS'
      },
      {
        check: (node) => {
          const callee = getCallees(node)[0];
          return callee === 'setTimeout' || callee === 'setInterval';
        },
        id: 'V-DYNCODE-001',
        name: 'Dynamic code execution',
        severity: 'ALTO',
        type: 'CODE_INJECTION'
      },
    ];

    for (const pattern of dangerousPatterns) {
      const nodes = findNodes(ast, 'CallExpression');
      for (const node of nodes) {
        if (pattern.check(node)) {
          const exists = this.findings.find(f => 
            f.id === pattern.id && f.path === this.filename && f.line === node.loc?.start?.line
          );
          if (!exists) {
            this.findings.push({
              id: pattern.id,
              type: pattern.type,
              name: pattern.name,
              severity: pattern.severity,
              path: this.filename,
              line: node.loc?.start?.line || 0,
              message: `${pattern.name} detected at line ${node.loc?.start?.line}`,
              confidence: 'high'
            });
          }
        }
      }
    }
  }

  checkHardcodedSecrets(ast) {
    const secretPatterns = [
      { id: 'S-AWS-001', name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/ },
      { id: 'S-AWS-SEC-001', name: 'AWS Secret Key', pattern: /[A-Za-z0-9/+=]{40}/, context: 'aws', severity: 'CRÍTICO' },
      { id: 'S-GH-001', name: 'GitHub Token', pattern: /ghp_[0-9a-zA-Z]{36}/ },
      { id: 'S-GH-ORG-001', name: 'GitHub Organization Token', pattern: /gho_[0-9a-zA-Z]{36}/ },
      { id: 'S-NPM-001', name: 'NPM Token', pattern: /npm_[A-Za-z0-9]{36}/ },
      { id: 'S-SK-STRIPE-001', name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24}/ },
      { id: 'S-SK-STRIPE-TEST-001', name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24}/ },
      { id: 'S-FB-001', name: 'Firebase API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/ },
      { id: 'S-GCLOUD-001', name: 'Google Cloud Key', pattern: /AIza[0-9A-Za-z\-_]{35}/ },
      { id: 'S-SENDGRID-001', name: 'SendGrid API Key', pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/ },
      { id: 'S-MAILGUN-001', name: 'Mailgun API Key', pattern: /key-[0-9A-Za-z]{32}/ },
      { id: 'S-TWILIO-001', name: 'Twilio API Key', pattern: /SK[a-f0-9]{32}/ },
      { id: 'S-JWT-001', name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
      { id: 'S-PK-PEM-001', name: 'Private Key PEM', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
      { id: 'S-CERT-001', name: 'Certificate PEM', pattern: /-----BEGIN CERTIFICATE-----/ },
      { id: 'S-PSQL-001', name: 'PostgreSQL Connection', pattern: /postgres:\/\/[^\s"']+/ },
      { id: 'S-MYSQL-001', name: 'MySQL Connection', pattern: /mysql:\/\/[^\s"']+/ },
      { id: 'S-MONGODB-001', name: 'MongoDB Connection', pattern: /mongodb(\+srv)?:\/\/[^\s"']+/ },
      { id: 'S-REDIS-001', name: 'Redis Connection', pattern: /redis:\/\/[^\s"']+/ },
    ];

    for (const secret of secretPatterns) {
      let match;
      const regex = new RegExp(secret.pattern.source, secret.pattern.flags);
      
      while ((match = regex.exec(this.code)) !== null) {
        const lines = this.code.substring(0, match.index).split('\n');
        const line = lines.length;

        this.findings.push({
          id: secret.id,
          type: 'SECRET',
          name: secret.name,
          severity: secret.severity || 'CRÍTICO',
          path: this.filename,
          line,
          message: `Hardcoded ${secret.name} detected`,
          matched: match[0].substring(0, 8) + '...',
          confidence: 'high'
        });
      }
    }
  }

  checkWeakCrypto(ast) {
    const weakAlgorithms = [
      { id: 'C-MD5-001', name: 'Weak hash: MD5', pattern: /md5\s*\(|createHash\s*\(\s*['"]md5['"]\)/gi, severity: 'MEDIO' },
      { id: 'C-SHA1-001', name: 'Weak hash: SHA1', pattern: /sha1\s*\(|createHash\s*\(\s*['"]sha1['"]\)/gi, severity: 'MEDIO' },
      { id: 'C-DES-001', name: 'Weak cipher: DES', pattern: /createCipher\s*\(\s*['"]des['"]\)/gi, severity: 'ALTO' },
      { id: 'C-RC4-001', name: 'Weak cipher: RC4', pattern: /createCipheriv\s*\(\s*['"]rc4['"]\)/gi, severity: 'ALTO' },
      { id: 'C-ECB-001', name: 'Insecure mode: ECB', pattern: /createCipheriv\s*\(.*['"]ecb['"]/gi, severity: 'ALTO' },
      { id: 'C-ECB-DEC-001', name: 'Insecure mode: ECB (decrypt)', pattern: /createDecipheriv\s*\(.*['"]ecb['"]/gi, severity: 'ALTO' },
      { id: 'C-RAND-001', name: 'Insecure random', pattern: /Math\.random\s*\(\s*\)/g, severity: 'MEDIO' },
    ];

    for (const algo of weakAlgorithms) {
      let match;
      while ((match = algo.pattern.exec(this.code)) !== null) {
        const lines = this.code.substring(0, match.index).split('\n');
        
        this.findings.push({
          id: algo.id,
          type: 'WEAK_CRYPTO',
          name: algo.name,
          severity: algo.severity,
          path: this.filename,
          line: lines.length,
          message: `${algo.name} is cryptographically weak`,
          confidence: 'high'
        });
      }
    }
  }
}