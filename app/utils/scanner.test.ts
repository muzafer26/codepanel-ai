import { describe, it, expect } from 'vitest';
import { runStaticScanner, calculateMultiScoring } from './scanner';

describe('Heuristic Static Scanner Tests', () => {
  it('should detect SQL injection vulnerabilities when string concatenation is used', () => {
    const vulnerableCode = `
      const query = "SELECT * FROM users WHERE id = " + req.query.id;
      db.execute(query);
    `;
    const findings = runStaticScanner(vulnerableCode);
    expect(findings.length).toBeGreaterThan(0);
    const sqli = findings.find(f => f.title === 'SQL Injection Vulnerability');
    expect(sqli).toBeDefined();
    expect(sqli?.severity).toBe('CRITICAL');
    expect(sqli?.confidence).toBe(75);
  });

  it('should detect PII log exposures when sensitive variables are logged', () => {
    const vulnerableCode = `
      const email = "user@example.com";
      console.log("Registered email: " + email);
    `;
    const findings = runStaticScanner(vulnerableCode);
    expect(findings.length).toBeGreaterThan(0);
    const piiLog = findings.find(f => f.title === 'PII Log Exposure');
    expect(piiLog).toBeDefined();
    expect(piiLog?.severity).toBe('HIGH');
    expect(piiLog?.confidence).toBe(80);
  });

  it('should not flag clean, simple code as having vulnerabilities (No Force Findings)', () => {
    const cleanCode = `
      let name = "Adarsh";
      console.log(name);
    `;
    const findings = runStaticScanner(cleanCode);
    expect(findings.length).toBe(0);
  });

  it('should parse package.json and flag vulnerable dependency versions with high confidence', () => {
    const packageJson = JSON.stringify({
      dependencies: {
        "lodash": "^4.17.15",
        "axios": "^0.20.0",
        "express": "^4.18.2" // safe version (safeVersion: 4.16.0)
      }
    });

    const findings = runStaticScanner(packageJson);
    expect(findings.length).toBe(2); // lodash and axios are vulnerable; express is safe!
    
    const lodashFinding = findings.find(f => f.title.includes("lodash"));
    expect(lodashFinding).toBeDefined();
    expect(lodashFinding?.severity).toBe("HIGH");
    expect(lodashFinding?.confidence).toBe(95);

    const expressFinding = findings.find(f => f.title.includes("express"));
    expect(expressFinding).toBeUndefined(); // Express version 4.18.2 is safe
  });

  it('should compute scores correctly based on findings', () => {
    const panels = {
      security: 'Done checking.',
      performance: 'Done checking.',
      style: 'Done checking.',
      compliance: 'Done checking.'
    };
    
    // No findings: expect perfect scores
    const perfectScores = calculateMultiScoring('', panels, []);
    expect(perfectScores.security).toBe(100);
    expect(perfectScores.privacy).toBe(100);
    expect(perfectScores.readiness).toBe(100);

    // SQL Injection finding (CRITICAL)
    const sqlFinding = [{
      id: 'static-sqli-0',
      severity: 'CRITICAL' as const,
      title: 'SQL Injection Vulnerability',
      line: 2,
      desc: 'concatenation',
      snippet: 'concatenation',
      confidence: 75
    }];
    
    const compromisedScores = calculateMultiScoring('', panels, sqlFinding);
    expect(compromisedScores.security).toBeLessThan(100);
    expect(compromisedScores.readiness).toBeLessThan(100);
  });
});
