export interface StaticFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  line: number | string;
  desc: string;
  snippet: string;
  confidence: number;
}

export interface MultiScores {
  security: number;
  privacy: number;
  maintainability: number;
  readiness: number;
}

function parsePackageJson(code: string): Record<string, string> | null {
  if (!code.trim().startsWith('{')) return null;
  try {
    const parsed = JSON.parse(code);
    if (parsed.dependencies || parsed.devDependencies) {
      return { ...parsed.dependencies, ...parsed.devDependencies };
    }
    return null;
  } catch (e) {
    return null;
  }
}

function semverCompare(v1: string, v2: string): number {
  const parts1 = v1.replace(/[^0-9.]/g, '').split('.').map(Number);
  const parts2 = v2.replace(/[^0-9.]/g, '').split('.').map(Number);
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const num1 = parts1[i] || 0;
    const num2 = parts2[i] || 0;
    if (num1 > num2) return 1;
    if (num1 < num2) return -1;
  }
  return 0;
}

// Client-side Rule-based Static Heuristics Scanner
export function runStaticScanner(code: string): StaticFinding[] {
  const findings: StaticFinding[] = [];
  if (!code) return findings;

  // Try to parse as package.json first
  const parsedDeps = parsePackageJson(code);
  if (parsedDeps) {
    const vulnPacks: Record<string, { msg: string; safeVersion: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' }> = {
      'lodash': { msg: 'Prototype Pollution (CVE-2020-8203) - upgrade to >= 4.17.21', safeVersion: '4.17.21', severity: 'HIGH' },
      'axios': { msg: 'Server-Side Request Forgery (SSRF) (CVE-2020-28168) - upgrade to >= 0.21.1', safeVersion: '0.21.1', severity: 'HIGH' },
      'express': { msg: 'Open Redirect & Parameter Pollution - upgrade to >= 4.16.0', safeVersion: '4.16.0', severity: 'MEDIUM' },
      'moment': { msg: 'ReDoS Vulnerability (CVE-2022-31129) - upgrade to >= 2.29.4', safeVersion: '2.29.4', severity: 'MEDIUM' },
      'minimist': { msg: 'Prototype Pollution (CVE-2021-3545) - upgrade to >= 1.2.6', safeVersion: '1.2.6', severity: 'HIGH' }
    };

    Object.keys(parsedDeps).forEach((depName) => {
      if (vulnPacks[depName]) {
        const rawVersion = parsedDeps[depName];
        const cleanVer = rawVersion.replace(/[^0-9.]/g, '');
        if (cleanVer && semverCompare(cleanVer, vulnPacks[depName].safeVersion) < 0) {
          findings.push({
            id: `static-pkg-${depName}`,
            severity: vulnPacks[depName].severity,
            title: `Vulnerable Dependency: ${depName}@${cleanVer}`,
            line: 'package.json',
            desc: `${vulnPacks[depName].msg} (Declared version ${rawVersion} is verified vulnerable).`,
            snippet: `"${depName}": "${rawVersion}"`,
            confidence: 95 // Highly confident because we checked the actual manifest version
          });
        }
      }
    });

    return findings;
  }

  const lines = code.split('\n');

  const rules = [
    {
      id: 'static-sqli',
      severity: 'CRITICAL' as const,
      title: 'SQL Injection Vulnerability',
      regex: /(select\s+.*\s+from|insert\s+into|update\s+.*set)\s+.*\s*\+\s*[a-zA-Z0-9_$]+/i,
      desc: 'Direct string concatenation detected in a query. Exposed to parameter spoofing. Parameters should be parameterized.',
      confidence: 75
    },
    {
      id: 'static-eval',
      severity: 'CRITICAL' as const,
      title: 'Dangerous eval() Execution',
      regex: /\beval\s*\(/i,
      desc: 'The eval() call executes string parameters as code, introducing severe Remote Code Execution (RCE) exposure.',
      confidence: 85
    },
    {
      id: 'static-secret',
      severity: 'HIGH' as const,
      title: 'Hardcoded Cryptographic Secret',
      regex: /(password|api_key|apikey|secret|token|client_secret|private_key)\s*=\s*['"][a-zA-Z0-9_\-]{6,}['"]/i,
      desc: 'Plain text keys inside files are vulnerable to leaks. Transition secrets to server variables.',
      confidence: 80
    },
    {
      id: 'static-log-pii',
      severity: 'HIGH' as const,
      title: 'PII Log Exposure',
      regex: /console\.(log|warn|error)\(.*\+.*\b(email|card|cvv|ssn|phone|password|secret|token)\b/i,
      desc: 'Raw personal parameters exported to terminal logs. Encrypt or mask credentials before logging.',
      confidence: 80
    },
    {
      id: 'static-unsecure-http',
      severity: 'MEDIUM' as const,
      title: 'Unencrypted Transmission',
      regex: /fetch\(\s*['"]http:\/\/[a-zA-Z0-9_\-\.]+/i,
      desc: 'Transmitting sensitive variables via unencrypted HTTP protocols. Enforce HTTPS.',
      confidence: 75
    },
    {
      id: 'static-redos',
      severity: 'MEDIUM' as const,
      title: 'ReDoS Vulnerability (Dangerous RegExp)',
      regex: /([a-zA-Z0-9_\-|]+[\*+])+[\*+]/i,
      desc: 'Detected potential nested repeating groups in regex. Vulnerable to Regular Expression Denial of Service (ReDoS) from backtracking.',
      confidence: 65
    },
    {
      id: 'static-sync-block',
      severity: 'HIGH' as const,
      title: 'Blocking Sync Operation',
      regex: /\b(readFileSync|writeFileSync|execSync|spawnSync)\b/i,
      desc: 'Blocking synchronous call halts thread execution in Node.js event loops. Transition to non-blocking async functions.',
      confidence: 85
    }
  ];

  lines.forEach((lineText, idx) => {
    rules.forEach(rule => {
      if (rule.regex.test(lineText)) {
        findings.push({
          id: `${rule.id}-${idx}`,
          severity: rule.severity,
          title: rule.title,
          line: idx + 1,
          desc: rule.desc,
          snippet: lineText.trim(),
          confidence: rule.confidence
        });
      }
    });
  });

  // Dynamic Dependency Scan
  const importRegex = /(?:import\s+.*\s+from\s+['"]|require\(\s*['"])([@a-zA-Z0-9_\-\/]+)/g;
  let match;
  const vulnPacks: Record<string, { msg: string; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' }> = {
    'lodash': { msg: 'Prototype Pollution (CVE-2020-8203) - upgrade to >= 4.17.21', severity: 'HIGH' },
    'axios': { msg: 'Server-Side Request Forgery (SSRF) (CVE-2020-28168) - upgrade to >= 0.21.1', severity: 'HIGH' },
    'express': { msg: 'Open Redirect & Parameter Pollution - upgrade to >= 4.16.0', severity: 'MEDIUM' },
    'moment': { msg: 'ReDoS Vulnerability (CVE-2022-31129) - upgrade to >= 2.29.4', severity: 'MEDIUM' },
    'minimist': { msg: 'Prototype Pollution (CVE-2021-3545) - upgrade to >= 1.2.6', severity: 'HIGH' }
  };

  while ((match = importRegex.exec(code)) !== null) {
    const packName = match[1];
    if (vulnPacks[packName]) {
      findings.push({
        id: `static-dep-${packName}`,
        severity: vulnPacks[packName].severity,
        title: `Outdated Dependency (Heuristic): ${packName}`,
        line: 'Imports',
        desc: `${vulnPacks[packName].msg} (Imported without verified version).`,
        snippet: `Imported library: ${packName}`,
        confidence: 70 // Lower confidence because version is not verified from imports alone
      });
    }
  }

  return findings;
}

export function calculateMultiScoring(code: string, panels: Record<string, string>, staticFindings: StaticFinding[]): MultiScores {
  let security = 100;
  let privacy = 100;
  let maintainability = 100;

  staticFindings.forEach(f => {
    if (f.severity === 'CRITICAL') {
      security -= 22;
      privacy -= 8;
    } else if (f.severity === 'HIGH') {
      security -= 14;
      privacy -= 12;
    } else if (f.severity === 'MEDIUM') {
      security -= 6;
      maintainability -= 10;
    }
  });

  const secText = panels.security || "";
  const perfText = panels.performance || "";
  const styleText = panels.style || "";
  const compText = panels.compliance || "";

  const secVulnerabilities = (secText.match(/CRITICAL|\[VULN\]|🔴/g) || []).length;
  const secWarnings = (secText.match(/HIGH|\[WARN\]|🟡/g) || []).length;
  security -= (secVulnerabilities * 12 + secWarnings * 6);

  const complianceLeaks = (compText.match(/CRITICAL|\[LEAK\]|\[GDPR\]|🔴/g) || []).length;
  const complianceWarnings = (compText.match(/HIGH|\[PII\]|🟡/g) || []).length;
  privacy -= (complianceLeaks * 14 + complianceWarnings * 7);

  const styleSmells = (styleText.match(/HIGH|\[SMELL\]|\[DEBT\]|🔴/g) || []).length;
  const latencyBottlenecks = (perfText.match(/SEVERE|\[SLOW\]|\[LEAK\]/g) || []).length;
  maintainability -= (styleSmells * 8 + latencyBottlenecks * 6);

  security = Math.max(10, Math.min(100, security));
  privacy = Math.max(10, Math.min(100, privacy));
  maintainability = Math.max(10, Math.min(100, maintainability));

  const readiness = Math.round(security * 0.45 + privacy * 0.35 + maintainability * 0.20);

  return { security, privacy, maintainability, readiness };
}
