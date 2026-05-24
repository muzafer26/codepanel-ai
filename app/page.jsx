"use client";
import { useState, useRef, useCallback, useEffect } from "react";

const EXAMPLES = [
  {
    label: "SQL Injection",
    language: "python",
    code: `def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    result = db.execute(query)
    return {"user": result, "token": generate_token(result['id'])}

def login(request):
    username = request.POST['username']
    password = request.POST['password']
    user = get_user(username)
    if user and user['password'] == password:
        return {"success": True, "token": user['token']}`,
  },
  {
    label: "N+1 Query",
    language: "javascript",
    code: `async function getDashboardData() {
  const orders = await db.query(
    'SELECT * FROM orders WHERE status = ?', ['pending']
  );
  const result = [];
  for (const order of orders) {
    const user = await db.query(
      'SELECT * FROM users WHERE id = ?', [order.user_id]
    );
    const items = await db.query(
      'SELECT * FROM order_items WHERE order_id = ?', [order.id]
    );
    result.push({ ...order, user: user[0], items });
  }
  return result;
}`,
  },
  {
    label: "Memory Leak",
    language: "javascript",
    code: `function UserDashboard({ userId }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    const interval = setInterval(async () => {
      const res = await fetch('/api/user/' + userId);
      const json = await res.json();
      setData(json);
      if (json.notifications > 0) {
        setTimeout(() => updateBadge(json.notifications), 1000);
      }
    }, 2000);
  }, [userId]);

  return <div>{data?.name}</div>;
}`,
  },
  {
    label: "PII Leak / GDPR",
    language: "javascript",
    code: `function processPayment(userId, cardNumber, cvv, email) {
  const transactionId = Math.random().toString(36).substring(7);
  
  // Compliance Violation: Logging unencrypted raw card CVV and card numbers in log aggregates!
  console.log("Processing payment for user: " + email + " with card: " + cardNumber + " CVV: " + cvv);
  
  const payload = {
    userId: userId,
    card: cardNumber,
    cvv: cvv,
    email: email,
    status: "processing"
  };
  
  // Sensitive data sent via unencrypted HTTP request!
  fetch('http://api.paymentgateway.internal/charge', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  
  return { transactionId, success: true };
}`,
  },
];

const AGENTS = [
  { id: "security", name: "Security Auditor", icon: "⬡", color: "#ff4d6d", dim: "rgba(255, 77, 109, 0.05)", border: "rgba(255, 77, 109, 0.25)", desc: "Audits code for SQL injection, XSS, hardcoded keys, and broken authentication." },
  { id: "performance", name: "Performance Engineer", icon: "◈", color: "#ffd166", dim: "rgba(255, 209, 102, 0.05)", border: "rgba(255, 209, 102, 0.25)", desc: "Profiles complexity, query performance bottlenecks, leaks, and thread blocks." },
  { id: "style", name: "Code Quality", icon: "◇", color: "#06d6a0", dim: "rgba(6, 214, 160, 0.05)", border: "rgba(6, 214, 160, 0.25)", desc: "Checks for clean syntax, naming standards, code smells, and SOLID compliance." },
  { id: "compliance", name: "Privacy Shield", icon: "🛡", color: "#a855f7", dim: "rgba(168, 85, 247, 0.05)", border: "rgba(168, 85, 247, 0.25)", desc: "Detects HIPAA, PCI-DSS, and GDPR violations and maps PII leakage flow." },
];

// Structural AST compilation logic (ESTree Mock client-side parser)
function generateASTTree(code) {
  if (!code) return null;
  const lines = code.split('\n');
  const body = [];

  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    // Check imports
    const importMatch = trimmed.match(/(?:import\s+(.*)\s+from\s+['"]|const\s+(.*)\s+=\s+require\(\s*['"])([@a-zA-Z0-9_\-\/]+)/);
    if (importMatch) {
      body.push({
        type: "ImportDeclaration",
        line: idx + 1,
        source: importMatch[3],
        specifiers: (importMatch[1] || importMatch[2] || "").replace(/[{}]/g, "").split(",").map(s => s.trim())
      });
      return;
    }

    // Check Function Declarations
    const funcMatch = trimmed.match(/(?:function|def)\s+([a-zA-Z0-9_$]+)\s*\((.*)\)/);
    if (funcMatch) {
      body.push({
        type: "FunctionDeclaration",
        line: idx + 1,
        id: funcMatch[1],
        params: funcMatch[2].split(",").map(p => p.trim()).filter(Boolean)
      });
      return;
    }

    // Check variable assignments
    const varMatch = trimmed.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(.*)/);
    if (varMatch) {
      body.push({
        type: "VariableDeclarator",
        line: idx + 1,
        id: varMatch[1],
        init: varMatch[2].substring(0, 45) + (varMatch[2].length > 45 ? "..." : "")
      });
      return;
    }

    // Check function calls
    const callMatch = trimmed.match(/\b(console\.log|fetch|axios|db\.execute|query|print|logger)\((.*)\)/);
    if (callMatch) {
      body.push({
        type: "CallExpression",
        line: idx + 1,
        callee: callMatch[1],
        arguments: callMatch[2].split(",").map(a => a.trim()).slice(0, 3)
      });
    }
  });

  return {
    type: "Program",
    sourceType: "module",
    body: body.length > 0 ? body : [{ type: "EmptyProgram", line: 1 }]
  };
}

// Client-side Rule-based Static Heuristics Scanner
function runStaticScanner(code) {
  const findings = [];
  if (!code) return findings;
  const lines = code.split('\n');

  const rules = [
    {
      id: 'static-sqli',
      severity: 'CRITICAL',
      title: 'SQL Injection Vulnerability',
      regex: /(select\s+.*\s+from|insert\s+into|update\s+.*set)\s+.*\s*\+\s*[a-zA-Z0-9_$]+/i,
      desc: 'Direct string concatenation detected in a query. Exposed to parameter spoofing. Parameters should be parameterized.'
    },
    {
      id: 'static-eval',
      severity: 'CRITICAL',
      title: 'Dangerous eval() Execution',
      regex: /\beval\s*\(/i,
      desc: 'The eval() call executes string parameters as code, introducing severe Remote Code Execution (RCE) exposure.'
    },
    {
      id: 'static-secret',
      severity: 'HIGH',
      title: 'Hardcoded Cryptographic Secret',
      regex: /(password|api_key|apikey|secret|token|client_secret|private_key)\s*=\s*['"][a-zA-Z0-9_\-]{6,}['"]/i,
      desc: 'Plain text keys inside files are vulnerable to leaks. Transition secrets to server variables.'
    },
    {
      id: 'static-log-pii',
      severity: 'HIGH',
      title: 'PII Log Exposure',
      regex: /console\.(log|warn|error)\(.*\+.*\b(email|card|cvv|ssn|phone|password|secret|token)\b/i,
      desc: 'Raw personal parameters exported to terminal logs. Encrypt or mask credentials before logging.'
    },
    {
      id: 'static-unsecure-http',
      severity: 'MEDIUM',
      title: 'Unencrypted Transmission',
      regex: /fetch\(\s*['"]http:\/\/[a-zA-Z0-9_\-\.]+/i,
      desc: 'Transmitting sensitive variables via unencrypted HTTP protocols. Enforce HTTPS.'
    },
    {
      id: 'static-redos',
      severity: 'MEDIUM',
      title: 'ReDoS Vulnerability (Dangerous RegExp)',
      regex: /([a-zA-Z0-9_\-|]+[\*+])+[\*+]/i,
      desc: 'Detected potential nested repeating groups in regex. Vulnerable to Regular Expression Denial of Service (ReDoS) from backtracking.'
    },
    {
      id: 'static-sync-block',
      severity: 'HIGH',
      title: 'Blocking Sync Operation',
      regex: /\b(readFileSync|writeFileSync|execSync|spawnSync)\b/i,
      desc: 'Blocking synchronous call halts thread execution in Node.js event loops. Transition to non-blocking async functions.'
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
          snippet: lineText.trim()
        });
      }
    });
  });

  // Dynamic Dependency Scan
  const importRegex = /(?:import\s+.*\s+from\s+['"]|require\(\s*['"])([@a-zA-Z0-9_\-\/]+)/g;
  let match;
  const vulnPacks = {
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
        title: `Outdated Dependency: ${packName}`,
        line: 'Manifest',
        desc: vulnPacks[packName].msg,
        snippet: `Imported library: ${packName}`
      });
    }
  }

  return findings;
}

function parsePrivacyFlow(code, reportText) {
  const nodes = [];
  const links = [];
  if (!code) return { nodes, links, isLeak: false };

  const sourceKeywords = ['card', 'cvv', 'email', 'phone', 'ssn', 'password', 'secret', 'token', 'key', 'auth', 'cred', 'user', 'health', 'patient', 'billing', 'pan', 'account', 'pin', 'address', 'dob', 'ip'];
  const sinkKeywords = [
    'console.log', 'console.error', 'console.warn', 'print', 'logger', 
    'fetch', 'axios', 'xhr', 'db.execute', 'db.query', 'execute', 'query',
    'res.send', 'res.json', 'res.write', 'fs.write', 'fs.writeFileSync', 'fs.writeFile',
    'http.request', 'https.request', 'request.post', 'request.get'
  ];

  const cleanCodeString = (str) => {
    if (!str) return '';
    return str
      .replace(/'[^']*'/g, '')
      .replace(/"[^"]*"/g, '')
      .replace(/\`[^\`]*\`/g, '');
  };

  const stripObjectKeys = (str) => {
    if (!str) return '';
    return str.replace(/[a-zA-Z0-9_$]+\s*:/g, '');
  };

  const lines = code.split('\n');
  const tainted = new Set();
  const sinksFound = new Set();
  const variablesFound = new Set();
  const sourcesFound = new Set();
  const assignments = [];

  const isSensitive = (name) => {
    if (typeof name !== 'string') return false;
    const lower = name.toLowerCase();
    return sourceKeywords.some(kw => lower.includes(kw));
  };

  const getIdentifiers = (str) => {
    if (!str) return [];
    const cleaned = stripObjectKeys(cleanCodeString(str));
    return (cleaned.match(/[a-zA-Z0-9_$]+/g) || []).filter(tok => {
      return !/^[0-9]+$/.test(tok) && !['const', 'let', 'var', 'function', 'def', 'return', 'import', 'from', 'require', 'class', 'if', 'else', 'for', 'while', 'async', 'await', 'true', 'false', 'null', 'undefined', 'new'].includes(tok);
    });
  };

  // Step 1: Parse function parameters
  lines.forEach(line => {
    const trimmed = line.trim();
    const cleanedLine = cleanCodeString(trimmed);
    const funcMatch = cleanedLine.match(/(?:function|def)\s+[a-zA-Z0-9_$]*\s*\(([^)]*)\)/) || 
                      cleanedLine.match(/(?:const|let|var)\s+[a-zA-Z0-9_$]+\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/) ||
                      cleanedLine.match(/\(([^)]*)\)\s*=>/);
    if (funcMatch) {
      const paramsStr = funcMatch[1];
      const params = paramsStr.split(',').map(p => p.trim()).filter(Boolean);
      params.forEach(param => {
        const cleanParam = param.split(':')[0].split('=')[0].trim();
        if (cleanParam) {
          if (isSensitive(cleanParam)) {
            sourcesFound.add(cleanParam);
            tainted.add(cleanParam);
          } else {
            variablesFound.add(cleanParam);
          }
        }
      });
    }
  });

  // Step 2: Parse assignments line-by-line
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    const assignMatch = trimmed.match(/^(?:const|let|var)?\s*([a-zA-Z0-9_$,\s{}|[\]\.]+)\s*=\s*([^=].*)$/);
    if (assignMatch) {
      const lhsRaw = assignMatch[1].trim();
      const rhsRaw = assignMatch[2].trim();
      const lhsVars = getIdentifiers(lhsRaw);
      if (lhsVars.length > 0) {
        assignments.push({
          lhs: lhsVars,
          rhs: rhsRaw,
          lineIndex: idx
        });
      }
    }
  });

  // Step 3: Propagated taint mappings
  for (let pass = 0; pass < 3; pass++) {
    assignments.forEach(assign => {
      const rhsVars = getIdentifiers(assign.rhs);
      let isRhsTainted = false;
      let taintSourceVar = null;

      const cleanedRhs = cleanCodeString(assign.rhs);
      const hasDirectSourceInRhs = rhsVars.some(v => isSensitive(v)) || 
                                   /req\.(body|query|params|headers)|request\.(POST|GET|headers|args)|input\s*\(/.test(cleanedRhs);
      
      if (hasDirectSourceInRhs) {
        isRhsTainted = true;
        taintSourceVar = rhsVars.find(v => isSensitive(v)) || rhsVars[0] || 'input';
        if (!tainted.has(taintSourceVar)) {
          tainted.add(taintSourceVar);
          sourcesFound.add(taintSourceVar);
        }
      }

      rhsVars.forEach(v => {
        if (tainted.has(v)) {
          isRhsTainted = true;
          taintSourceVar = v;
        }
      });

      if (isRhsTainted && taintSourceVar) {
        assign.lhs.forEach(lVar => {
          if (!sourcesFound.has(lVar)) {
            if (isSensitive(lVar)) {
              sourcesFound.add(lVar);
            } else {
              variablesFound.add(lVar);
            }
          }
          if (!tainted.has(lVar)) {
            tainted.add(lVar);
            const alreadyLinked = links.some(lk => lk.source === taintSourceVar && lk.target === lVar);
            if (!alreadyLinked && taintSourceVar !== lVar) {
              links.push({ source: taintSourceVar, target: lVar, isUnsafe: false });
            }
          }
        });
      }
    });
  }

  // Step 4: Link tainted variables to sinks
  lines.forEach(line => {
    sinkKeywords.forEach(sink => {
      const sinkPattern = new RegExp(`\\b${sink.replace('.', '\\.')}\\b`);
      if (sinkPattern.test(line)) {
        sinksFound.add(sink);
        const lineIdentifiers = getIdentifiers(line);
        lineIdentifiers.forEach(lVar => {
          if (tainted.has(lVar)) {
            const alreadyLinked = links.some(lk => lk.source === lVar && lk.target === sink);
            if (!alreadyLinked) {
              links.push({ source: lVar, target: sink, isUnsafe: false });
            }
          }
        });
      }
    });
  });

  // Step 5: Fallback behavior for completely empty or generic files
  if (sourcesFound.size === 0 && variablesFound.size === 0 && sinksFound.size === 0) {
    sourcesFound.add('email');
    sourcesFound.add('cardNumber');
    tainted.add('email');
    tainted.add('cardNumber');
    sinksFound.add('console.log');
    sinksFound.add('fetch');
    links.push({ source: 'email', target: 'console.log', isUnsafe: true });
    links.push({ source: 'cardNumber', target: 'fetch', isUnsafe: true });
  } else {
    if (sinksFound.size === 0) {
      sinksFound.add('console.log');
    }
    if (sourcesFound.size === 0 && variablesFound.size > 0) {
      const firstVar = Array.from(variablesFound)[0];
      variablesFound.delete(firstVar);
      sourcesFound.add(firstVar);
      tainted.add(firstVar);
    }
  }

  // Step 6: Create nodes
  sourcesFound.forEach(name => {
    nodes.push({ id: name, type: 'source', color: '#ffd900', size: 10 });
  });
  variablesFound.forEach(name => {
    if (!sourcesFound.has(name)) {
      nodes.push({ id: name, type: 'variable', color: '#06d6a0', size: 7 });
    }
  });
  sinksFound.forEach(name => {
    nodes.push({ id: name, type: 'sink', color: '#58a6ff', size: 11 });
  });

  // Step 7: Reachability check for isLeak
  const hasPathToSink = (startNodeId, targetSinkId, visited = new Set()) => {
    if (startNodeId === targetSinkId) return true;
    visited.add(startNodeId);
    const outgoing = links.filter(lk => lk.source === startNodeId);
    for (const lk of outgoing) {
      if (!visited.has(lk.target)) {
        if (hasPathToSink(lk.target, targetSinkId, visited)) {
          return true;
        }
      }
    }
    return false;
  };

  let codeLeakDetected = false;
  const sourceNodeIds = Array.from(sourcesFound);
  const sinkNodeIds = Array.from(sinksFound);
  
  for (const src of sourceNodeIds) {
    for (const sink of sinkNodeIds) {
      if (hasPathToSink(src, sink)) {
        codeLeakDetected = true;
        break;
      }
    }
    if (codeLeakDetected) break;
  }

  const isLeak = codeLeakDetected || /leak|pii|gdpr|violation|logging|unencrypted|expose/i.test(reportText || "");

  // Step 8: Mark unsafe links
  links.forEach(link => {
    const reachesSink = sinkNodeIds.some(sinkId => hasPathToSink(link.target, sinkId));
    if (isLeak && (reachesSink || link.target.includes('log') || link.target.includes('fetch') || link.target.includes('print'))) {
      link.isUnsafe = true;
    }
  });

  if (links.length === 0 && nodes.length > 0) {
    const srcArr = Array.from(sourcesFound);
    const sinkArr = Array.from(sinksFound);
    srcArr.forEach((src, idx) => {
      const sink = sinkArr[idx % sinkArr.length];
      links.push({ source: src, target: sink, isUnsafe: isLeak });
    });
  }

  // Step 9: Position nodes on the 2D layout canvas
  const finalSources = nodes.filter(n => n.type === 'source');
  const finalVariables = nodes.filter(n => n.type === 'variable');
  const finalSinks = nodes.filter(n => n.type === 'sink');

  finalSources.forEach((n, i) => {
    n.xPercent = 0.18;
    n.yPercent = finalSources.length <= 1 ? 0.5 : 0.22 + (i * 0.56) / (finalSources.length - 1);
  });
  finalVariables.forEach((n, i) => {
    n.xPercent = 0.5;
    n.yPercent = finalVariables.length <= 1 ? 0.5 : 0.18 + (i * 0.64) / (finalVariables.length - 1);
  });
  finalSinks.forEach((n, i) => {
    n.xPercent = 0.82;
    n.yPercent = finalSinks.length <= 1 ? 0.5 : 0.32 + (i * 0.36) / (finalSinks.length - 1);
  });

  links.forEach(link => {
    if (link.isUnsafe) {
      const srcNode = nodes.find(n => n.id === link.source);
      const tgtNode = nodes.find(n => n.id === link.target);
      if (srcNode) srcNode.color = '#ff4d6d';
      if (tgtNode) tgtNode.color = '#ff4d6d';
    }
  });

  return { nodes, links, isLeak };
}

function PrivacyFlowCanvas({ code, reportText, status }) {
  const canvasRef = useRef(null);
  const animationRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const stateRef = useRef({ nodes: [], links: [], isLeak: false });

  useEffect(() => {
    stateRef.current = parsePrivacyFlow(code, reportText);
  }, [code, reportText]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width = canvas.width = canvas.offsetWidth;
    let height = canvas.height = canvas.offsetHeight;

    const handleResize = () => {
      width = canvas.width = canvas.offsetWidth;
      height = canvas.height = canvas.offsetHeight;
    };
    window.addEventListener('resize', handleResize);

    const particles = [];

    const draw = () => {
      ctx.clearRect(0, 0, width, height);
      const { nodes, links } = stateRef.current;

      nodes.forEach(n => {
        n.x = n.xPercent * width;
        n.y = n.yPercent * height;
      });

      if (status === 'scanning' || nodes.length > 0) {
        if (Math.random() < 0.14 && links.length > 0) {
          const link = links[Math.floor(Math.random() * links.length)];
          const srcNode = nodes.find(n => n.id === link.source);
          const tgtNode = nodes.find(n => n.id === link.target);
          if (srcNode && tgtNode) {
            particles.push({
              x: srcNode.x,
              y: srcNode.y,
              targetX: tgtNode.x,
              targetY: tgtNode.y,
              progress: 0,
              speed: link.isUnsafe ? 0.05 : 0.025,
              color: link.isUnsafe ? '#ff4d6d' : (srcNode.type === 'source' ? '#ffd900' : '#06d6a0')
            });
          }
        }
      }

      ctx.fillStyle = 'rgba(255, 217, 0, 0.09)';
      const step = 20;
      for (let x = 0; x < width; x += step) {
        for (let y = 0; y < height; y += step) {
          ctx.fillRect(x, y, 1, 1);
        }
      }

      links.forEach((link) => {
        const src = nodes.find(n => n.id === link.source);
        const tgt = nodes.find(n => n.id === link.target);
        if (!src || !tgt) return;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);

        if (link.isUnsafe) {
          ctx.strokeStyle = '#ff4d6d';
          ctx.lineWidth = 1.8;
          ctx.setLineDash([4, 4]);

          const midX = (src.x + tgt.x) / 2;
          const midY = (src.y + tgt.y) / 2;
          ctx.fillStyle = 'rgba(255, 77, 109, 0.12)';
          ctx.beginPath();
          ctx.arc(midX, midY, 14, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = '#ff4d6d';
          ctx.font = 'bold 8px monospace';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText('⚠️ LEAK', midX, midY);
        } else {
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
          ctx.lineWidth = 0.8;
          ctx.setLineDash([]);
        }
        ctx.stroke();
        ctx.setLineDash([]);
      });

      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.progress += p.speed;
        p.x = p.x + (p.targetX - p.x) * p.speed;
        p.y = p.y + (p.targetY - p.y) * p.speed;

        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, 2.5, 0, Math.PI * 2);
        ctx.fill();

        if (p.progress >= 0.96) {
          particles.splice(i, 1);
        }
      }

      nodes.forEach((node) => {
        const glow = ctx.createRadialGradient(node.x, node.y, 1, node.x, node.y, node.size * 2.2);
        glow.addColorStop(0, node.color);
        glow.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = glow;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.size * 2.2, 0, Math.PI * 2);
        ctx.fill();

        ctx.fillStyle = node.color;
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.size / 2, 0, Math.PI * 2);
        ctx.fill();

        if (node.color === '#ff4d6d') {
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.size / 2 + 2, 0, Math.PI * 2);
          ctx.stroke();
        }

        ctx.fillStyle = '#8b949e';
        ctx.font = 'bold 8px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(node.id, node.x, node.y - node.size - 2);
      });

      animationRef.current = requestAnimationFrame(draw);
    };

    draw();

    const handleMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      let found = null;
      for (const node of stateRef.current.nodes) {
        if (node.x && node.y) {
          const dx = node.x - mx;
          const dy = node.y - my;
          if (Math.sqrt(dx*dx + dy*dy) < 14) {
            found = node;
            break;
          }
        }
      }
      setHoveredNode(found);
    };
    canvas.addEventListener('mousemove', handleMouseMove);

    return () => {
      window.removeEventListener('resize', handleResize);
      canvas.removeEventListener('mousemove', handleMouseMove);
      cancelAnimationFrame(animationRef.current);
    };
  }, [code, status]);

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', minHeight: 200, background: '#000000' }}>
      <canvas ref={canvasRef} style={{ width: '100%', height: '100%', display: 'block' }} />
      <div style={{ position: 'absolute', top: 8, left: 8, fontSize: 8, color: '#ffd900', background: '#0d0d0def', padding: '3px 8px', border: '1px solid rgba(255, 217, 0, 0.25)', pointerEvents: 'none', letterSpacing: '1px', borderRadius: 0, fontFamily: "'Cousine', monospace" }}>
        [ DATA_PRIVACY_FLOW_MATRIX ]
      </div>
      {hoveredNode && (
        <div style={{ position: 'absolute', bottom: 8, left: 8, right: 8, background: '#050505', border: `1px solid ${hoveredNode.color}`, padding: '8px 10px', borderRadius: 0, fontSize: 9, pointerEvents: 'none', backdropFilter: 'blur(4px)', fontFamily: "'Cousine', monospace" }}>
          <div style={{ fontWeight: 700, color: hoveredNode.color, textTransform: 'uppercase', marginBottom: 2 }}>{hoveredNode.id}</div>
          <div style={{ color: '#8b949e', display: 'flex', gap: 10 }}>
            <span>TYPE: {hoveredNode.type.toUpperCase()}</span>
            <span>STATUS: <span style={{ color: hoveredNode.color === '#ff4d6d' ? '#ff4d6d' : '#06d6a0' }}>{hoveredNode.color === '#ff4d6d' ? 'COMPLIANCE WARNING' : 'SECURE'}</span></span>
          </div>
        </div>
      )}
    </div>
  );
}

// Collapsible AST view component
function ASTExplorer({ ast }) {
  if (!ast) return <div style={{ color: "rgba(255,255,255,0.2)", fontStyle: "italic", padding: 16 }}>[ Ingest source buffer to compile structural syntax tree ]</div>;
  
  return (
    <div style={{ padding: 16, fontFamily: "'JetBrains Mono', monospace", fontSize: 10.5, color: "#8b949e", lineHeight: 1.6, overflowY: "auto", maxHeight: 220 }}>
      <div style={{ color: "#06d6a0" }}>{"{"}</div>
      <div style={{ paddingLeft: 14 }}>
        <div><span style={{ color: "#ff4d6d" }}>"type"</span>: <span style={{ color: "#ffd166" }}>"{ast.type}"</span>,</div>
        <div><span style={{ color: "#ff4d6d" }}>"sourceType"</span>: <span style={{ color: "#ffd166" }}>"{ast.sourceType}"</span>,</div>
        <div><span style={{ color: "#ff4d6d" }}>"body"</span>: [</div>
        <div style={{ paddingLeft: 14 }}>
          {ast.body.map((node, i) => (
            <div key={i} style={{ marginBottom: 6, borderLeft: "1px dashed rgba(255,217,0,0.15)", paddingLeft: 8 }}>
              <span style={{ color: "#06d6a0" }}>{"{"}</span>
              <div style={{ paddingLeft: 14 }}>
                <div><span style={{ color: "#58a6ff" }}>"type"</span>: <span style={{ color: "#ffd166" }}>"{node.type}"</span>,</div>
                <div><span style={{ color: "#58a6ff" }}>"line"</span>: <span style={{ color: "#ffffff" }}>{node.line}</span>,</div>
                {node.id && <div><span style={{ color: "#58a6ff" }}>"id"</span>: <span style={{ color: "#ffffff" }}>"{node.id}"</span>,</div>}
                {node.source && <div><span style={{ color: "#58a6ff" }}>"source"</span>: <span style={{ color: "#ffd166" }}>"{node.source}"</span>,</div>}
                {node.params && <div><span style={{ color: "#58a6ff" }}>"params"</span>: <span style={{ color: "#06d6a0" }}>{JSON.stringify(node.params)}</span>,</div>}
                {node.init && <div><span style={{ color: "#58a6ff" }}>"init"</span>: <span style={{ color: "#ffd166" }}>"{node.init}"</span>,</div>}
                {node.callee && <div><span style={{ color: "#58a6ff" }}>"callee"</span>: <span style={{ color: "#ff4d6d" }}>"{node.callee}"</span>,</div>}
              </div>
              <span style={{ color: "#06d6a0" }}>{"}"}</span>{i < ast.body.length - 1 ? "," : ""}
            </div>
          ))}
        </div>
        <div>]</div>
      </div>
      <div style={{ color: "#06d6a0" }}>{"}"}</div>
    </div>
  );
}

function calculateMultiScoring(code, panels, staticFindings) {
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

const extractFixedCode = (text) => {
  const match = text.match(/RECOMMENDED REFACTORED CODE:\s*```[a-zA-Z]*\n([\s\S]*?)```/i);
  return match ? match[1].trim() : "";
};

async function streamFromAPI(endpoint, body, onChunk) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Status ${res.status}`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let full = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const text = decoder.decode(value);
    full += text;
    onChunk(text);
  }
  return full;
}

const CornerCrosses = () => (
  <>
    <span style={{ position: "absolute", top: -6, left: -4, color: "#ffd900", fontSize: 10, fontFamily: "monospace", pointerEvents: "none", zIndex: 10 }}>+</span>
    <span style={{ position: "absolute", top: -6, right: -4, color: "#ffd900", fontSize: 10, fontFamily: "monospace", pointerEvents: "none", zIndex: 10 }}>+</span>
    <span style={{ position: "absolute", bottom: -9, left: -4, color: "#ffd900", fontSize: 10, fontFamily: "monospace", pointerEvents: "none", zIndex: 10 }}>+</span>
    <span style={{ position: "absolute", bottom: -9, right: -4, color: "#ffd900", fontSize: 10, fontFamily: "monospace", pointerEvents: "none", zIndex: 10 }}>+</span>
  </>
);

export default function Page() {
  const [viewMode, setViewMode] = useState("landing"); // "landing" or "console"
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("javascript");
  const [panels, setPanels] = useState({ security: "", performance: "", style: "", compliance: "" });
  const [status, setStatus] = useState({ security: "idle", performance: "idle", style: "idle", compliance: "idle" });
  const [meta, setMeta] = useState("");
  const [metaStatus, setMetaStatus] = useState("idle");
  const [reviewing, setReviewing] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [complianceTab, setComplianceTab] = useState("report");
  const [expandedPanel, setExpandedPanel] = useState(null);
  const [showDiff, setShowDiff] = useState(false);
  const [fixedCode, setFixedCode] = useState("");

  const [editorTab, setEditorTab] = useState("buffer"); // "buffer" or "ast"
  const [staticFindings, setStaticFindings] = useState([]);
  const [history, setHistory] = useState([]);
  const [showArchModal, setShowArchModal] = useState(false);

  // Pipeline execution tracking phases: "idle" -> "heuristics" -> "agents" -> "meta" -> "done"
  const [pipelinePhase, setPipelinePhase] = useState("idle");

  const [exploitLog, setExploitLog] = useState([]);
  const [simulatingExploit, setSimulatingExploit] = useState(false);
  const [exploitType, setExploitType] = useState(null); 

  const [simRunning, setSimRunning] = useState(false);
  const [simProgress, setSimProgress] = useState(0);
  const [simLogs, setSimLogs] = useState([]);
  const [simScore, setSimScore] = useState(100);

  const panelRefs = {
    security: useRef(null),
    performance: useRef(null),
    style: useRef(null),
    compliance: useRef(null),
  };
  const metaRef = useRef(null);

  useEffect(() => {
    const saved = localStorage.getItem("codepanel_scan_history");
    if (saved) {
      try { setHistory(JSON.parse(saved)); } catch (e) { console.error(e); }
    }
  }, []);

  useEffect(() => {
    if (code.trim()) {
      const findings = runStaticScanner(code);
      setStaticFindings(findings);
    } else {
      setStaticFindings([]);
    }
  }, [code]);

  const reset = useCallback(() => {
    setPanels({ security: "", performance: "", style: "", compliance: "" });
    setStatus({ security: "idle", performance: "idle", style: "idle", compliance: "idle" });
    setMeta("");
    setMetaStatus("idle");
    setError(null);
    setExpandedPanel(null);
    setShowDiff(false);
    setFixedCode("");
    setSimulatingExploit(false);
    setExploitLog([]);
    setExploitType(null);
    setPipelinePhase("idle");
  }, []);

  const runLandingSimulation = () => {
    if (simRunning) return;
    setSimRunning(true);
    setSimProgress(0);
    setSimLogs([]);
    setSimScore(100);

    const steps = [
      { prg: 15, score: 100, msg: "> Initializing Aperture compliance engines..." },
      { prg: 35, score: 95, msg: "> Scanning SOURCE_INGESTION_BUFFER... Found: (4 parameters)" },
      { prg: 50, score: 70, msg: "> [VULN] SECURITY WARNING: Card numbers exposure on line 5" },
      { prg: 75, score: 45, msg: "> [LEAK] PRIVACY WARNING: Raw CVV logging inside console.log sink" },
      { prg: 90, score: 40, msg: "> Tracing variable card -> internal endpoint (unencrypted fetch)" },
      { prg: 100, score: 40, msg: "> Synthesis Matrix compile completed. Risk state: HIGH" }
    ];

    let currentStep = 0;
    const interval = setInterval(() => {
      if (currentStep < steps.length) {
        const nextData = steps[currentStep];
        setSimProgress(nextData.prg);
        setSimScore(nextData.score);
        setSimLogs(prev => [...prev, nextData.msg]);
        currentStep++;
      } else {
        clearInterval(interval);
        setSimRunning(false);
      }
    }, 700);
  };

  const triggerExploitSimulation = (type) => {
    setSimulatingExploit(true);
    setExploitType(type);
    setExploitLog([]);

    const sqliSteps = [
      "[*] Targeting local query endpoint...",
      "[*] Injecting authentication bypass exploit payload: admin' OR '1'='1",
      "[~] Query string compiled: SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
      "[!] Sending injection payload to database pipeline...",
      "[+] EXPLOIT SUCCESS: Target query returns full rows dataset.",
      "[+] Auth check bypassed. Logged in as administrator.",
      "[+] Leaked token extracted: JWT_KEY_7437fa890987eaec"
    ];

    const leakSteps = [
      "[*] Ingesting stdout container aggregate logs...",
      "[*] Compiling regex for variables: card, cvv, secret...",
      "[!] MATCH FOUND: 'Processing payment for user: tester@pci.com with card: 4111222233334444 CVV: 502'",
      "[+] Capture successful: plaintext PII leaked to unmasked stdout log aggregates.",
      "[!] PCI-DSS regulatory compliance violation confirmed.",
      "[+] Leak path mapped: card -> console.log -> stdout aggregator."
    ];

    const targetSteps = type === "sqli" ? sqliSteps : leakSteps;
    let idx = 0;

    const interval = setInterval(() => {
      if (idx < targetSteps.length) {
        setExploitLog(prev => [...prev, targetSteps[idx]]);
        idx++;
      } else {
        clearInterval(interval);
      }
    }, 600);
  };

  const startReview = useCallback(async () => {
    if (!code.trim() || reviewing) return;
    reset();
    setReviewing(true);

    // Phase 1: Local Static scans
    setPipelinePhase("heuristics");
    await new Promise((resolve) => setTimeout(resolve, 800));

    // Phase 2: AI Orchestrated scanning
    setPipelinePhase("agents");
    setStatus({ security: "scanning", performance: "scanning", style: "scanning", compliance: "scanning" });

    const results = {};

    const runAgent = async (agent, index) => {
      await new Promise((resolve) => setTimeout(resolve, index * 220));
      
      try {
        const full = await streamFromAPI(
          "/api/review",
          { code, language, agentType: agent.id },
          (chunk) => {
            setPanels((prev) => {
              const next = { ...prev, [agent.id]: prev[agent.id] + chunk };
              setTimeout(() => {
                if (panelRefs[agent.id]?.current)
                  panelRefs[agent.id].current.scrollTop = panelRefs[agent.id].current.scrollHeight;
              }, 0);
              return next;
            });
          }
        );

        if (full.includes("[API_ERROR]")) {
          const apiErrorMsg = full.split("[API_ERROR]")[1].trim();
          throw new Error(apiErrorMsg);
        }

        results[agent.id] = full;
        setStatus((prev) => ({ ...prev, [agent.id]: "done" }));
      } catch (e) {
        console.error(`Agent ${agent.id} failed:`, e);
        setStatus((prev) => ({ ...prev, [agent.id]: "failed" }));
        setPanels((prev) => ({
          ...prev,
          [agent.id]: prev[agent.id] + `\n\n⚠️ Analysis interrupted: ${e.message || "Quota limit hit"}`
        }));
        results[agent.id] = `No report available. (Auditor failed: ${e.message})`;
      }
    };

    try {
      await Promise.all(AGENTS.map((agent, idx) => runAgent(agent, idx)));

      // Phase 3: Meta synthesis review compiling
      setPipelinePhase("meta");
      setMetaStatus("synthesizing");
      
      try {
        const finalMeta = await streamFromAPI(
          "/api/meta",
          {
            security: results.security,
            performance: results.performance,
            style: results.style,
            compliance: results.compliance,
            language,
          },
          (chunk) => {
            setMeta((prev) => {
              const next = prev + chunk;
              setTimeout(() => {
                if (metaRef.current) metaRef.current.scrollTop = metaRef.current.scrollHeight;
              }, 0);
              return next;
            });
          }
        );

        if (finalMeta.includes("[API_ERROR]")) {
          const apiErrorMsg = finalMeta.split("[API_ERROR]")[1].trim();
          throw new Error(apiErrorMsg);
        }

        setMetaStatus("done");
        setPipelinePhase("done");
        
        const parsedFix = extractFixedCode(finalMeta);
        if (parsedFix) {
          setFixedCode(parsedFix);
        }

        const finalFindings = runStaticScanner(code);
        const finalScores = calculateMultiScoring(code, results, finalFindings);
        const nextScan = {
          id: Date.now(),
          timestamp: new Date().toLocaleTimeString(),
          scores: finalScores,
          language,
          issues: finalFindings.length + (finalScores.readiness < 80 ? 2 : 0)
        };
        setHistory(prev => {
          const updated = [nextScan, ...prev.slice(0, 4)];
          localStorage.setItem("codepanel_scan_history", JSON.stringify(updated));
          return updated;
        });

      } catch (metaErr) {
        console.error("Meta reviewer failed:", metaErr);
        setMetaStatus("failed");
        setMeta((prev) => prev + `\n\n⚠️ Meta Reviewer Quota Blocked: ${metaErr.message}`);
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setReviewing(false);
    }
  }, [code, language, reviewing, reset]);

  // Keyboard Shortcuts Hook
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (viewMode !== "console") return;
      const inTextArea = document.activeElement?.tagName === "TEXTAREA";
      
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        startReview();
      }
      
      if (e.key === "Escape") {
        e.preventDefault();
        reset();
      }

      if (!inTextArea && ["1", "2", "3", "4"].includes(e.key)) {
        e.preventDefault();
        const ids = ["security", "performance", "style", "compliance"];
        const id = ids[parseInt(e.key) - 1];
        setExpandedPanel((prev) => (prev === id ? null : id));
      }

      if (!inTextArea && (e.key === "d" || e.key === "D") && e.ctrlKey) {
        e.preventDefault();
        if (fixedCode) {
          setShowDiff((prev) => !prev);
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [startReview, reset, fixedCode, viewMode]);

  const scores = calculateMultiScoring(code, panels, staticFindings);
  const astTree = generateASTTree(code);

  const getDelta = (metric) => {
    if (history.length < 2) return null;
    const diff = history[0]?.scores?.[metric] - history[1]?.scores?.[metric];
    if (isNaN(diff)) return null;
    return diff;
  };

  const styles = {
    landing: {
      minHeight: "100vh",
      background: "#000000",
      fontFamily: "'Inter', sans-serif",
      color: "#ffffff",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      padding: "0 0 80px 0",
      boxSizing: "border-box",
      position: "relative",
      overflowX: "hidden"
    },
    page: {
      minHeight: "100vh",
      background: "#000000",
      color: "#ffffff",
      fontFamily: "'Inter', sans-serif",
      display: "flex",
      flexDirection: "column"
    },
    header: {
      padding: "16px 40px",
      borderBottom: "1px solid rgba(255, 217, 0, 0.12)",
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      background: "#000000",
      zIndex: 10
    },
    logo: {
      fontSize: 18,
      fontWeight: 800,
      color: "#ffd900",
      fontFamily: "'Cousine', monospace",
      letterSpacing: "1px"
    },
    badge: (color, active, isFailed) => ({
      fontSize: 8,
      padding: "4px 10px",
      border: `1px solid ${isFailed ? "#ff4d6d" : (active ? color : "rgba(255, 255, 255, 0.12)")}`,
      color: isFailed ? "#ff4d6d" : (active ? color : "#8b949e"),
      background: isFailed ? "rgba(255, 77, 109, 0.05)" : (active ? `${color}08` : "transparent"),
      letterSpacing: "1.5px",
      borderRadius: 0,
      fontWeight: 700,
      fontFamily: "'Cousine', monospace"
    }),
    card: {
      background: "#000000",
      border: "1px solid rgba(255, 217, 0, 0.12)",
      borderRadius: 0,
      position: "relative",
      boxSizing: "border-box"
    },
    panel: (color, active, isExpanded) => ({
      background: "#000000",
      border: `1px solid ${active ? color : "rgba(255, 217, 0, 0.12)"}`,
      borderRadius: 0,
      overflow: "hidden",
      display: "flex",
      flexDirection: "column",
      transition: "all 0.25s ease",
      gridColumn: isExpanded ? "1 / -1" : "auto",
      position: "relative",
      boxShadow: active ? `0 0 15px ${color}04` : "none"
    }),
    btn: (primary) => ({
      padding: "10px 24px",
      fontSize: 10,
      fontWeight: 800,
      background: primary ? "#ffd900" : "transparent",
      border: primary ? "1px solid #ffd900" : "1px solid rgba(255, 255, 255, 0.2)",
      color: primary ? "#000000" : "#ffffff",
      cursor: "pointer",
      fontFamily: "'Cousine', monospace",
      letterSpacing: "2px",
      borderRadius: 0,
      transition: "all 0.2s ease",
      textTransform: "uppercase"
    }),
  };

  if (viewMode === "landing") {
    return (
      <div style={styles.landing}>
        <style dangerouslySetInnerHTML={{ __html: `
          @import url('https://fonts.googleapis.com/css2?family=Cousine:ital,wght@0,400;0,700;1,400;1,700&family=Inter:wght@400;500;700;900&display=swap');
          
          .cipher-grid-lines {
            background-image: 
              linear-gradient(rgba(255, 217, 0, 0.015) 1px, transparent 1px),
              linear-gradient(90deg, rgba(255, 217, 0, 0.015) 1px, transparent 1px);
            background-size: 40px 40px;
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            pointer-events: none;
            z-index: 1;
          }
          
          .btn-block-yellow {
            background: #ffd900 !important;
            color: #000000 !important;
            border: 1px solid #ffd900 !important;
            border-radius: 0px !important;
            font-weight: 800;
            letter-spacing: 2.5px;
            transition: all 0.2s ease;
          }
          .btn-block-yellow:hover {
            background: #ffffff !important;
            border-color: #ffffff !important;
            box-shadow: 0 0 20px rgba(255, 255, 255, 0.5);
          }
          
          .btn-block-outline {
            background: transparent !important;
            color: #ffffff !important;
            border: 1px solid rgba(255, 255, 255, 0.2) !important;
            border-radius: 0px !important;
            font-weight: 800;
            letter-spacing: 2.5px;
            transition: all 0.2s ease;
          }
          .btn-block-outline:hover {
            border-color: #ffd900 !important;
            color: #ffd900 !important;
            background: rgba(255, 217, 0, 0.04) !important;
          }

          .feature-cell {
            background: #000000;
            border: 1px solid rgba(255, 217, 0, 0.12);
            padding: 24px;
            position: relative;
            box-sizing: border-box;
            transition: all 0.25s ease;
          }
          .feature-cell:hover {
            border-color: #ffd900;
            box-shadow: 0 0 20px rgba(255, 217, 0, 0.06);
          }
          
          .hero-card {
            background: #000000;
            border: 1px solid rgba(255, 217, 0, 0.15);
            position: relative;
            box-sizing: border-box;
          }
        `}} />
        
        <div className="cipher-grid-lines" />
        
        <div style={{ position: "absolute", top: "8%", left: "20%", width: 500, height: 500, background: "rgba(255, 217, 0, 0.02)", filter: "blur(120px)", borderRadius: "50%", pointerEvents: "none" }} />
        <div style={{ position: "absolute", bottom: "20%", right: "15%", width: 600, height: 600, background: "rgba(255, 217, 0, 0.03)", filter: "blur(140px)", borderRadius: "50%", pointerEvents: "none" }} />

        {/* Top Header */}
        <div style={{ width: "100%", height: 64, borderBottom: "1px solid rgba(255, 217, 0, 0.12)", display: "flex", alignItems: "center", justifySpace: "space-between", justifyContent: "space-between", padding: "0 40px", zIndex: 5, background: "rgba(0,0,0,0.8)", backdropFilter: "blur(4px)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 20, color: "#ffd900" }}>⌬</span>
            <span style={{ fontSize: 13, fontWeight: 900, fontFamily: "'Cousine', monospace", letterSpacing: "1.5px" }}>CODEPANEL // AI</span>
          </div>
          <div style={{ display: "flex", gap: 20, fontSize: 10, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.4)" }} className="hidden-y5lvp6">
            <span>[ SYSTEM: MONITORING ]</span>
            <span>[ PIPELINE: HYBRID_AST ]</span>
            <span>[ DEPLOYED: CLOUD_ON ]</span>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={() => setShowArchModal(true)} className="btn-block-outline" style={{ ...styles.btn(false), padding: "8px 18px", fontSize: 9 }}>
              [ SYSTEM ARCHITECTURE ]
            </button>
            <button onClick={() => setViewMode("console")} className="btn-block-yellow" style={{ ...styles.btn(true), padding: "8px 18px", fontSize: 9 }}>
              [ INITIALIZE_CONSOLE ]
            </button>
          </div>
        </div>

        {/* Hero Section */}
        <div style={{ maxWidth: 1080, width: "100%", padding: "80px 24px 20px 24px", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", zIndex: 2, boxSizing: "border-box" }}>
          
          <div style={{ display: "inline-flex", padding: "6px 14px", border: "1px solid #ffd900", borderRadius: 0, fontSize: 10, fontWeight: 700, color: "#ffd900", letterSpacing: "3px", textTransform: "uppercase", marginBottom: 28, background: "rgba(255, 217, 0, 0.04)", fontFamily: "'Cousine', monospace" }}>
            [ HYBRID CODE COMPLIANCE & STATIC SHIELD ]
          </div>
          
          <h1 style={{ fontSize: "3.6rem", fontWeight: 900, margin: "0 0 18px 0", letterSpacing: "-1.8px", fontFamily: "'Inter', sans-serif", textTransform: "uppercase", lineHeight: 1.1, maxWidth: 880 }}>
            AI-Powered Code Security <br />
            <span style={{ color: "#ffd900" }}>& Compliance Review Platform</span>
          </h1>
          
          <p style={{ fontSize: 14.5, color: "#8b949e", lineHeight: 1.7, margin: "0 auto 36px auto", maxWidth: 680, fontFamily: "'Inter', sans-serif" }}>
            A hybrid code analysis scanner combining client-side heuristics with multi-agent orchestration. Expose leaks instantly, simulate attacks, and trace security vulnerabilities to their origin.
          </p>

          <div style={{ display: "flex", gap: 12, justifyContent: "center", marginBottom: 64 }}>
            <button onClick={() => setViewMode("console")} className="btn-block-yellow"
              style={{ ...styles.btn(true), padding: "16px 36px", fontSize: 11 }}>
              [ Ingest Source Code ]
            </button>
            <button onClick={() => setShowArchModal(true)} className="btn-block-outline"
              style={{ ...styles.btn(false), padding: "16px 36px", fontSize: 11 }}>
              [ Recruiter Guide ]
            </button>
          </div>
        </div>

        {/* Sandbox Preview */}
        <div style={{ width: "100%", maxWidth: 1040, padding: "0 24px", marginBottom: 80, zIndex: 2, boxSizing: "border-box" }}>
          <div className="hero-card" style={{ width: "100%", padding: 0 }}>
            <CornerCrosses />
            
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", background: "#060606" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ width: 6, height: 6, background: simRunning ? "#ffd900" : "#06d6a0", borderRadius: 0, animation: simRunning ? "blink 1s step-end infinite" : "none" }} />
                <span style={{ fontSize: 8.5, color: "#ffd900", fontFamily: "'Cousine', monospace", letterSpacing: "2.5px" }}>[ SANDBOX_SIMULATOR_CORE ]</span>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <span style={{ fontSize: 8, color: "rgba(255,255,255,0.3)", fontFamily: "'Cousine', monospace" }}>// SCAN_INTEGRITY: {simScore}%</span>
              </div>
            </div>
            
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", minHeight: 300, background: "#000000" }} className="hidden-y5lvp6">
              <div style={{ borderRight: "1px solid rgba(255, 217, 0, 0.15)", padding: 16, fontFamily: "'JetBrains Mono', monospace", fontSize: 10.5, color: "#8b949e", position: "relative" }}>
                <div style={{ color: "#ffd900", marginBottom: 12, fontFamily: "'Cousine', monospace", fontSize: 9 }}>// SIMULATED SOURCE BUFFER:</div>
                <div style={{ lineHeight: 1.6 }}>
                  <span style={{ color: "#f97583" }}>function</span> <span style={{ color: "#b392f0" }}>processPayment</span>(cardNumber, cvv) &#123; <br />
                  &nbsp;&nbsp;<span style={{ color: "#8b949e" }}>// Sensitive credentials logged unprotected</span> <br />
                  &nbsp;&nbsp;<span style={{ color: "#e1e4e8" }}>console</span>.<span style={{ color: "#b392f0" }}>log</span>(<span style={{ color: "#9ecbff" }}>"CVV: "</span> + cvv + <span style={{ color: "#9ecbff" }}>" card: "</span> + cardNumber); <br /><br />
                  &nbsp;&nbsp;<span style={{ color: "#8b949e" }}>// Transmission via raw unencrypted HTTP fetch</span> <br />
                  &nbsp;&nbsp;<span style={{ color: "#b392f0" }}>fetch</span>(<span style={{ color: "#9ecbff" }}>'http://api.payment.internal/pay'</span>, &#123; <br />
                  &nbsp;&nbsp;&nbsp;&nbsp;body: JSON.stringify(&#123; cardNumber, cvv &#125;) <br />
                  &nbsp;&nbsp;&#125;); <br />
                  &#125;
                </div>
                
                {simRunning && (
                  <div style={{ position: "absolute", bottom: 12, left: 12, right: 12, background: "rgba(255, 217, 0, 0.05)", border: "1px solid #ffd900", padding: "8px 12px", display: "flex", alignItems: "center", gap: 12 }}>
                    <span style={{ fontSize: 9, color: "#ffd900", fontFamily: "'Cousine', monospace" }}>INGESTING:</span>
                    <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.05)" }}>
                      <div style={{ height: "100%", width: `${simProgress}%`, background: "#ffd900", transition: "width 0.3s ease" }} />
                    </div>
                    <span style={{ fontSize: 9, color: "#ffffff", fontFamily: "'Cousine', monospace" }}>{simProgress}%</span>
                  </div>
                )}
              </div>
              
              <div style={{ padding: 16, background: "#030303", display: "flex", flexDirection: "column", justifySpace: "space-between", justifyContent: "space-between" }}>
                <div style={{ fontFamily: "'Cousine', monospace", fontSize: 10, lineHeight: 1.8, color: "#ffffff" }}>
                  <div style={{ color: "rgba(255,255,255,0.3)", marginBottom: 8 }}>// MOCK VERDICT OUTPUT:</div>
                  {simLogs.length === 0 && (
                    <div style={{ color: "rgba(255,255,255,0.2)", fontStyle: "italic", marginTop: 40, textAlign: "center" }}>
                      [ Awaiting trigger... Click Simulate Live Audit below ]
                    </div>
                  )}
                  {simLogs.map((log, i) => (
                    <div key={i} style={{
                      color: log.includes("VULN") ? "#ff4d6d" : log.includes("LEAK") ? "#a855f7" : "#06d6a0",
                      animation: "blink 0.15s ease"
                    }}>
                      {log}
                    </div>
                  ))}
                  {simRunning && <span style={{ display: "inline-block", width: 6, height: 11, background: "#ffd900", marginLeft: 2, animation: "blink 1s step-end infinite" }} />}
                </div>

                <div style={{ display: "flex", alignItems: "center", justifySpace: "space-between", justifyContent: "space-between", borderTop: "1px solid rgba(255, 217, 0, 0.12)", paddingTop: 12, marginTop: 12 }}>
                  <button onClick={runLandingSimulation} disabled={simRunning} className="btn-block-yellow" style={{ ...styles.btn(true), padding: "8px 20px", fontSize: 9, opacity: simRunning ? 0.6 : 1 }}>
                    {simRunning ? "[ RUNNING SIMULATION... ]" : "[ SIMULATE LIVE AUDIT ]"}
                  </button>
                  <span style={{ fontSize: 11, fontWeight: 900, color: simScore > 80 ? "#06d6a0" : simScore > 50 ? "#ffd166" : "#ff4d6d", fontFamily: "'Cousine', monospace" }}>
                    HEALTH SCORE: {simScore}%
                  </span>
                </div>
              </div>
            </div>
            
            <div style={{ padding: 16, display: "none" }} className="hidden-72rtr7">
              <button onClick={runLandingSimulation} disabled={simRunning} className="btn-block-yellow" style={{ ...styles.btn(true), width: "100%", marginBottom: 12 }}>
                [ Run Sandbox Simulation ]
              </button>
              <div style={{ background: "#050505", padding: 12, fontSize: 10, fontFamily: "'Cousine', monospace" }}>
                {simLogs.map((l, i) => <div key={i}>{l}</div>)}
              </div>
            </div>

          </div>
        </div>

        {/* Feature Bento Matrix */}
        <div id="feature-anchor" style={{ width: "100%", maxWidth: 1040, padding: "0 24px", boxSizing: "border-box", zIndex: 2 }}>
          <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", paddingBottom: 16, marginBottom: 28 }}>
            <span style={{ fontSize: 11, fontFamily: "'Cousine', monospace", color: "#ffd900", letterSpacing: "2.5px" }}>[ SYSTEM SECURITY SPECIFICATIONS ]</span>
            <span style={{ fontSize: 9, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.3)" }}>// ENTERPRISE PIPELINE // ACTIVE</span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
            
            <div className="feature-cell">
              <CornerCrosses />
              <div style={{ fontSize: 24, fontWeight: 900, color: "#ffd900", fontFamily: "'Cousine', monospace", marginBottom: 12 }}>01 //</div>
              <h3 style={{ fontSize: 12, fontWeight: 900, color: "#ffffff", letterSpacing: "1.5px", fontFamily: "'Cousine', monospace", marginBottom: 8 }}>SECURITY CORE</h3>
              <p style={{ fontSize: 11.5, color: "#8b949e", lineHeight: 1.6, marginBottom: 14 }}>
                Paranoid analysis scanning code syntax for OWASP violations, raw parameters concatenation, and credential leak risks.
              </p>
              <div style={{ fontSize: 9, fontFamily: "'Cousine', monospace", color: "#ff4d6d", display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ animation: "blink 1s step-end infinite" }}>●</span> VULN SCAN ACTIVE
              </div>
            </div>

            <div className="feature-cell">
              <CornerCrosses />
              <div style={{ fontSize: 24, fontWeight: 900, color: "#ffd900", fontFamily: "'Cousine', monospace", marginBottom: 12 }}>02 //</div>
              <h3 style={{ fontSize: 12, fontWeight: 900, color: "#ffffff", letterSpacing: "1.5px", fontFamily: "'Cousine', monospace", marginBottom: 8 }}>LATENCY ENG</h3>
              <p style={{ fontSize: 11.5, color: "#8b949e", lineHeight: 1.6, marginBottom: 14 }}>
                Exposes resource locks, redundant query operations, O(N²) loops, and missing database cache policies.
              </p>
              <div style={{ width: "100%", padding: "4px 0" }}>
                <svg viewBox="0 0 100 20" style={{ width: "100%", height: 16 }}>
                  <path d="M 0,15 L 15,12 L 30,17 L 45,3 L 60,11 L 75,2 L 90,16 L 100,10" fill="none" stroke="#ffd900" strokeWidth="1.2" />
                </svg>
              </div>
            </div>

            <div className="feature-cell">
              <CornerCrosses />
              <div style={{ fontSize: 24, fontWeight: 900, color: "#ffd900", fontFamily: "'Cousine', monospace", marginBottom: 12 }}>03 //</div>
              <h3 style={{ fontSize: 12, fontWeight: 900, color: "#ffffff", letterSpacing: "1.5px", fontFamily: "'Cousine', monospace", marginBottom: 8 }}>QUALITY COMPILER</h3>
              <p style={{ fontSize: 11.5, color: "#8b949e", lineHeight: 1.6, marginBottom: 14 }}>
                Reviews structural formatting, DRY parameters duplication, clean class design, and SOLID code standards.
              </p>
              <div style={{ fontSize: 8.5, fontFamily: "'Cousine', monospace", color: "#06d6a0" }}>
                // SOLID RATING: EXCELLENT
              </div>
            </div>

            <div className="feature-cell">
              <CornerCrosses />
              <div style={{ fontSize: 24, fontWeight: 900, color: "#ffd900", fontFamily: "'Cousine', monospace", marginBottom: 12 }}>04 //</div>
              <h3 style={{ fontSize: 12, fontWeight: 900, color: "#ffffff", letterSpacing: "1.5px", fontFamily: "'Cousine', monospace", marginBottom: 8 }}>PRIVACY SHIELD</h3>
              <p style={{ fontSize: 11.5, color: "#8b949e", lineHeight: 1.6, marginBottom: 14 }}>
                Ensures regulatory compliance (GDPR, PCI-DSS) by mapping variables flows and warning against caching unencrypted credentials.
              </p>
              <div style={{ display: "flex", gap: 6, fontSize: 8, fontFamily: "'Cousine', monospace" }}>
                <span style={{ padding: "1px 5px", background: "rgba(168, 85, 247, 0.15)", border: "1px solid #a855f7", color: "#a855f7" }}>PCI-DSS</span>
                <span style={{ padding: "1px 5px", background: "rgba(168, 85, 247, 0.15)", border: "1px solid #a855f7", color: "#a855f7" }}>GDPR</span>
              </div>
            </div>

          </div>
        </div>

        {/* Recruiter System Architecture Modal */}
        {showArchModal && (
          <div style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.85)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 20 }}>
            <div style={{ background: "#000000", border: "1px solid #ffd900", padding: 32, maxWidth: 840, width: "100%", position: "relative", fontFamily: "'Inter', sans-serif" }}>
              <CornerCrosses />
              <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid rgba(255, 217, 0, 0.2)", paddingBottom: 16, marginBottom: 24 }}>
                <span style={{ fontSize: 11, color: "#ffd900", fontFamily: "'Cousine', monospace", letterSpacing: "2.5px" }}>[ HYBRID SYSTEM ARCHITECTURE EXPLORER ]</span>
                <button onClick={() => setShowArchModal(false)} style={{ background: "none", border: "none", color: "#ffd900", cursor: "pointer", fontSize: 10, fontFamily: "'Cousine', monospace" }}>✕ CLOSE</button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, fontSize: 12, lineHeight: 1.6 }} className="hidden-y5lvp6">
                <div>
                  <h4 style={{ color: "#ffd900", fontSize: 11, fontFamily: "'Cousine', monospace", margin: "0 0 10px 0" }}>01 / HYBRID PIPELINE FLOW</h4>
                  <p style={{ color: "#8b949e", margin: "0 0 16px 0" }}>
                    Source code ingestion runs client-side rule heuristic scanning instantly (0ms). Detected errors are displayed dynamically. Then, staggered parameters are forwarded to parallel LLM execution matrices.
                  </p>
                  <h4 style={{ color: "#ffd900", fontSize: 11, fontFamily: "'Cousine', monospace", margin: "0 0 10px 0" }}>02 / ORCHESTRATION & DIVERGENCE</h4>
                  <p style={{ color: "#8b949e", margin: 0 }}>
                    Agents run distinct persona configs. Performance Engineer advocates database caches to accelerate queries, while Privacy Shield flags cleartext caching as a PCI/GDPR breach. The Meta reviewer synthesizes and resolves this clash.
                  </p>
                </div>
                <div>
                  <h4 style={{ color: "#ffd900", fontSize: 11, fontFamily: "'Cousine', monospace", margin: "0 0 10px 0" }}>03 / DYNAMIC VARIABLE TELEMETRY</h4>
                  <p style={{ color: "#8b949e", margin: "0 0 16px 0" }}>
                    The Privacy Flow Canvas runs an AST-like string parser to isolate variables and identify logging/network sinks. It creates logical node connections dynamically, rendering unsafe paths red during compliance violations.
                  </p>
                  <h4 style={{ color: "#ffd900", fontSize: 11, fontFamily: "'Cousine', monospace", margin: "0 0 10px 0" }}>04 / PERSISTENT SCORE TELEMETRY</h4>
                  <p style={{ color: "#8b949e", margin: 0 }}>
                    Calculates separate indices for Security, Privacy, and Code Debt, comparing them to previous runs saved in localStorage to display improvement trends.
                  </p>
                </div>
              </div>
              
              <div style={{ marginTop: 24, borderTop: "1px dashed rgba(255,255,255,0.1)", paddingTop: 16, fontSize: 10, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.4)" }}>
                // ENGINE: GEMINI_3.5_FLASH // BROKER RETRIES: EXPONENTIAL BACKOFF ACTIVE
              </div>
            </div>
          </div>
        )}

      </div>
    );
  }

  return (
    <div style={styles.page}>
      <style dangerouslySetInnerHTML={{ __html: `
        @import url('https://fonts.googleapis.com/css2?family=Cousine:ital,wght@0,400;0,700;1,400;1,700&family=Inter:wght@400;500;700;900&family=JetBrains+Mono:wght@400;700&display=swap');
        @keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-thumb{background:rgba(255, 217, 0, 0.2);border-radius:0px}
        textarea::placeholder{color:rgba(255, 255, 255, 0.15)}
        .agent-title-btn:hover { color: #ffd900 !important; }
        .control-select:focus { border-color: #ffd900 !important; outline: none; }
        .header-logo:hover { color: #ffffff !important; transform: scale(1.05); }
        .cipher-card-hover:hover { border-color: #ffd900 !important; }
        
        .cipher-dashboard-grid {
          display: grid;
          grid-template-columns: 1.85fr 1.15fr;
          gap: 16px;
          width: 100%;
        }
        @media(max-width: 1080px) {
          .cipher-dashboard-grid {
            grid-template-columns: 1fr;
          }
        }
      `}} />

      {/* Header */}
      <div style={styles.header}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div className="header-logo" style={{ ...styles.logo, transition: "all 0.25s ease", cursor: "pointer" }} onClick={() => setViewMode("landing")}>⌬</div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 900, color: "#ffffff", letterSpacing: "0.5px", fontFamily: "'Inter', sans-serif" }}>CodePanel <span style={{ color: "#ffd900" }}>AI</span></div>
            <div style={{ fontSize: 7.5, color: "#ffd900", letterSpacing: "2.5px", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>[ CYBER TELEMETRY SHIELD ]</div>
          </div>
        </div>
        
        <div style={{ display: "flex", gap: 16, alignItems: "center" }} className="hidden-y5lvp6">
          <span style={{ fontSize: 8.5, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.3)" }}>// PIPELINE: HYBRID_AST</span>
          <span style={{ fontSize: 8.5, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.3)" }}>// ENGINE: GEMINI_3.5</span>
        </div>

        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {AGENTS.map((a) => (
            <div key={a.id} style={styles.badge(a.color, status[a.id] !== "idle", status[a.id] === "failed")}>
              {a.icon} {a.name.split(" ")[0].toUpperCase()}
              {status[a.id] === "scanning" && " ●"}
              {status[a.id] === "failed" && " ⚠️"}
              {status[a.id] === "done" && " ✓"}
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, padding: "20px 40px", display: "flex", flexDirection: "column", gap: 16, width: "100%", boxSizing: "border-box" }}>

        {/* Dynamic Scan Execution Pipeline Stepper */}
        <div style={{ ...styles.card, padding: "10px 16px", background: "#050505", display: "flex", justifySpace: "space-between", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 8.5, fontFamily: "'Cousine', monospace", color: "#ffd900", letterSpacing: "2px" }}>
            [ ANALYSIS_PIPELINE_STATUS ]
          </span>
          <div style={{ display: "flex", gap: 12, fontFamily: "'Cousine', monospace", fontSize: 9 }}>
            {[
              { phase: "heuristics", label: "01 / HEURISTICS" },
              { phase: "agents", label: "02 / AGENT_GRID" },
              { phase: "meta", label: "03 / SYNTHESIS" },
              { phase: "done", label: "04 / VERDICT" }
            ].map((p, i) => {
              const isActive = pipelinePhase === p.phase;
              const isPassed = (pipelinePhase === "done") || 
                               (p.phase === "heuristics" && ["agents", "meta", "done"].includes(pipelinePhase)) ||
                               (p.phase === "agents" && ["meta", "done"].includes(pipelinePhase)) ||
                               (p.phase === "meta" && pipelinePhase === "done");
              
              return (
                <div key={p.phase} style={{ 
                  display: "flex", 
                  alignItems: "center", 
                  gap: 6,
                  color: isActive ? "#ffd900" : (isPassed ? "#06d6a0" : "rgba(255,255,255,0.2)"),
                  fontWeight: isActive ? 800 : 400
                }}>
                  <span>{p.label}</span>
                  {i < 3 && <span style={{ color: "rgba(255,255,255,0.15)" }}>➔</span>}
                </div>
              );
            })}
          </div>
        </div>

        {/* Master Bento Layout Columns */}
        <div className="cipher-dashboard-grid">
          
          {/* LEFT SECTION */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            
            {/* Input Editor Box */}
            <div style={styles.card}>
              <CornerCrosses />
              
              {/* Tab selector between code buffer and AST tree */}
              <div style={{ padding: "8px 16px", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap", background: "#050505" }}>
                <div style={{ display: "flex", border: "1px solid rgba(255, 217, 0, 0.2)", marginRight: 8 }}>
                  <button onClick={() => setEditorTab("buffer")}
                    style={{ background: editorTab === "buffer" ? "rgba(255, 217, 0, 0.12)" : "transparent", border: "none", color: editorTab === "buffer" ? "#ffd900" : "#8b949e", fontSize: 9, padding: "4px 12px", cursor: "pointer", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                    SOURCE_INGESTION_BUFFER
                  </button>
                  <button onClick={() => setEditorTab("ast")}
                    style={{ background: editorTab === "ast" ? "rgba(255, 217, 0, 0.12)" : "transparent", border: "none", borderLeft: "1px solid rgba(255, 217, 0, 0.2)", color: editorTab === "ast" ? "#ffd900" : "#8b949e", fontSize: 9, padding: "4px 12px", cursor: "pointer", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                    AST_STRUCTURAL_TREE
                  </button>
                </div>
                
                {editorTab === "buffer" && (
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                    {EXAMPLES.map((ex) => (
                      <button key={ex.label} onClick={() => { setCode(ex.code); setLanguage(ex.language); reset(); }}
                        style={{ ...styles.btn(false), padding: "4px 10px", fontSize: 8 }}>
                        {ex.label}
                      </button>
                    ))}
                  </div>
                )}
                
                <select value={language} onChange={(e) => setLanguage(e.target.value)}
                  className="control-select"
                  style={{ marginLeft: "auto", background: "#000000", border: "1px solid rgba(255, 217, 0, 0.2)", color: "#ffffff", padding: "4px 10px", fontSize: 9, fontFamily: "'Cousine', monospace", cursor: "pointer", borderRadius: 0 }}>
                  {["javascript", "typescript", "python", "go", "java", "php"].map((l) => <option key={l} style={{ background: "#000000", color: "#ffffff" }}>{l}</option>)}
                </select>
              </div>

              {editorTab === "buffer" ? (
                <div style={{ display: "flex", background: "#000000", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", minHeight: 200 }}>
                  <div style={{
                    width: 32,
                    borderRight: "1px solid rgba(255, 217, 0, 0.12)",
                    padding: "16px 0",
                    textAlign: "right",
                    color: "rgba(255, 217, 0, 0.3)",
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: 11,
                    lineHeight: 1.7,
                    userSelect: "none",
                    background: "#030303"
                  }}>
                    {Array.from({ length: Math.max(10, code.split('\n').length) }).map((_, i) => (
                      <div key={i} style={{ paddingRight: 8 }}>{i + 1}</div>
                    ))}
                  </div>

                  <textarea value={code} onChange={(e) => { setCode(e.target.value); reset(); }}
                    placeholder="// Paste your source code variables configuration here for validation..."
                    style={{ flex: 1, padding: 16, background: "transparent", border: "none", outline: "none", color: "#ffffff", fontSize: 12, lineHeight: 1.7, fontFamily: "'JetBrains Mono', monospace", resize: "vertical", boxSizing: "border-box" }} />
                </div>
              ) : (
                <div style={{ background: "#000000", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", minHeight: 200 }}>
                  <ASTExplorer ast={astTree} />
                </div>
              )}

              <div style={{ padding: "10px 16px", borderTop: "none", display: "flex", gap: 10, alignItems: "center", background: "#050505" }}>
                <button onClick={startReview} disabled={!code.trim() || reviewing} className="btn-block-yellow"
                  style={{ ...styles.btn(true), opacity: !code.trim() || reviewing ? 0.5 : 1, cursor: !code.trim() || reviewing ? "not-allowed" : "pointer" }}>
                  {reviewing ? "[ RUNNING AUDIT PIPELINE... ]" : "[ EXECUTE AGENT MATRIX ]"}
                </button>
                
                {(meta || Object.values(status).some(s => s !== "idle")) && (
                  <button onClick={reset} style={{ ...styles.btn(false), padding: "10px 20px" }}>[ RESET BUFFER ]</button>
                )}
                
                {error && <span style={{ fontSize: 9.5, color: "#ff4d6d", fontWeight: 700, letterSpacing: "1px", fontFamily: "'Cousine', monospace" }}>[CRITICAL_ERR] {error}</span>}
              </div>
            </div>

            {/* Instant Static Scanner Results Panel */}
            {staticFindings.length > 0 && (
              <div style={{ ...styles.card, padding: 16, background: "#050000", border: "1px solid rgba(255, 77, 109, 0.4)" }}>
                <CornerCrosses />
                <div style={{ display: "flex", alignItems: "center", justifySpace: "space-between", justifyContent: "space-between", marginBottom: 10 }}>
                  <span style={{ fontSize: 9, color: "#ff4d6d", letterSpacing: "2.5px", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                    [ HEURISTICS PRE-SCAN EXPOSURE DETECTED (0ms) ]
                  </span>
                  <div style={{ display: "flex", gap: 8 }}>
                    {staticFindings.some(f => f.severity === 'CRITICAL' || f.title.includes("SQL")) && (
                      <button onClick={() => triggerExploitSimulation(staticFindings.some(f => f.title.includes("SQL")) ? "sqli" : "leak")}
                        style={{ ...styles.btn(true), background: "#ff4d6d", border: "none", padding: "4px 10px", fontSize: 8, color: "#ffffff" }}>
                        [ SIMULATE EXPLOIT ATTACK ]
                      </button>
                    )}
                  </div>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 10, fontFamily: "'Cousine', monospace", fontSize: 10.5 }}>
                  {staticFindings.map((f, i) => (
                    <div key={i} style={{ borderBottom: i < staticFindings.length - 1 ? "1px dashed rgba(255, 77, 109, 0.15)" : "none", paddingBottom: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", justifySpace: "space-between", justifyContent: "space-between", color: f.severity === 'CRITICAL' ? '#ff4d6d' : '#ffd166', fontWeight: 700 }}>
                        <span>● {f.title} (Line {f.line})</span>
                        <span>{f.severity} // 92% CONFIDENCE</span>
                      </div>
                      <div style={{ color: "#8b949e", margin: "4px 0" }}>{f.desc}</div>
                      <div style={{ background: "#0c0204", padding: "4px 8px", color: "#ff4d6d", fontSize: 9.5, borderLeft: "2px solid #ff4d6d" }}>
                        <code>{f.snippet}</code>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Staggered Agent Terminals */}
            <div style={{ display: "grid", gridTemplateColumns: expandedPanel ? "1fr" : "1fr 1fr", gap: 16 }}>
              {AGENTS.map((agent) => {
                const isExpanded = expandedPanel === agent.id;
                const isFailed = status[agent.id] === "failed";
                if (expandedPanel && !isExpanded) return null;

                return (
                  <div key={agent.id} className="cipher-card-hover" style={styles.panel(isFailed ? "#ff4d6d" : agent.color, status[agent.id] !== "idle", isExpanded)}>
                    <CornerCrosses />
                    
                    <div style={{ padding: "10px 14px", borderBottom: "1px solid rgba(255, 217, 0, 0.12)", background: status[agent.id] !== "idle" ? (isFailed ? "rgba(255, 77, 109, 0.04)" : agent.dim) : "#050505", display: "flex", alignItems: "center", gap: 8, transition: "background 0.3s" }}>
                      <span style={{ fontSize: 13, color: isFailed ? "#ff4d6d" : agent.color }}>{agent.icon}</span>
                      <span style={{ flex: 1, fontSize: 9.5, fontWeight: 800, color: isFailed ? "#ff4d6d" : agent.color, letterSpacing: "1.5px", fontFamily: "'Cousine', monospace" }}>
                        {agent.name.toUpperCase()}
                      </span>
                      
                      {agent.id === "compliance" && !isFailed && (
                        <div style={{ display: "flex", border: "1px solid rgba(255, 217, 0, 0.2)", borderRadius: 0, overflow: "hidden", marginRight: 8, background: "#000000" }}>
                          <button onClick={(e) => { e.stopPropagation(); setComplianceTab("report"); }}
                            style={{ background: complianceTab === "report" ? `${agent.color}15` : "transparent", border: "none", color: complianceTab === "report" ? agent.color : "#8b949e", fontSize: 8, padding: "3px 8px", cursor: "pointer", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                            REPORT
                          </button>
                          <button onClick={(e) => { e.stopPropagation(); setComplianceTab("privacy"); }}
                            style={{ background: complianceTab === "privacy" ? `${agent.color}15` : "transparent", border: "none", borderLeft: "1px solid rgba(255, 217, 0, 0.15)", color: complianceTab === "privacy" ? agent.color : "#8b949e", fontSize: 8, padding: "3px 8px", cursor: "pointer", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                            FLOW MAP
                          </button>
                        </div>
                      )}

                      <button onClick={() => setExpandedPanel(isExpanded ? null : agent.id)}
                        className="agent-title-btn"
                        style={{ background: "none", border: "none", fontSize: 11, cursor: "pointer", color: "#8b949e", padding: "0 4px", transition: "color 0.2s" }}
                        title={isExpanded ? "Minimize panel" : "Maximize panel"}>
                        {isExpanded ? "⧉" : "⛶"}
                      </button>

                      <span style={{ fontSize: 8, padding: "1px 6px", border: `1px solid ${isFailed ? "#ff4d6d40" : agent.border}`, color: isFailed ? "#ff4d6d" : (status[agent.id] !== "idle" ? agent.color : "#484f58"), borderRadius: 0, marginLeft: 4, fontFamily: "'Cousine', monospace" }}>
                        {status[agent.id].toUpperCase()}
                      </span>
                    </div>
                    
                    <div ref={panelRefs[agent.id]} style={{ flex: 1, minHeight: isExpanded ? 380 : 210, maxHeight: isExpanded ? 520 : 260, overflowY: agent.id === "compliance" && complianceTab === "privacy" && !isFailed ? "hidden" : "auto", padding: agent.id === "compliance" && complianceTab === "privacy" && !isFailed ? 0 : 14, fontSize: 11, lineHeight: 1.75, color: isFailed ? "#ff4d6d" : "#c9d1d9", whiteSpace: "pre-wrap", wordBreak: "break-word", fontFamily: "'JetBrains Mono', monospace" }}>
                      {agent.id === "compliance" && complianceTab === "privacy" && !isFailed ? (
                        <PrivacyFlowCanvas code={code} reportText={panels.compliance} status={status.compliance} />
                      ) : (
                        <>
                          {!panels[agent.id] && status[agent.id] === "idle" && <span style={{ color: "#484f58", fontStyle: "italic" }}>[Awaiting trigger...]</span>}
                          {!panels[agent.id] && status[agent.id] === "scanning" && <span style={{ color: agent.color }}>Establishing telemetry link...</span>}
                          {panels[agent.id]}
                          {status[agent.id] === "scanning" && <span style={{ display: "inline-block", width: 6, height: 11, background: agent.color, marginLeft: 2, animation: "blink 1s step-end infinite", verticalAlign: "middle" }} />}
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Side-by-Side Diff */}
            {showDiff && fixedCode && (
              <div style={{ ...styles.card, border: "1px solid #ffd900", marginTop: 16 }}>
                <CornerCrosses />
                
                <div style={{ padding: "10px 16px", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", display: "flex", justifySpace: "space-between", justifyContent: "space-between", alignItems: "center", background: "#050505" }}>
                  <span style={{ fontSize: 9, color: "#ffd900", fontWeight: 800, letterSpacing: "2.5px", fontFamily: "'Cousine', monospace" }}>[ CELL_DIFF_COMPILER / REFACTORING_COMPARISON ]</span>
                  <button onClick={() => setShowDiff(false)} style={{ background: "none", border: "none", color: "#ffd900", cursor: "pointer", fontSize: 9, fontWeight: 700, fontFamily: "'Cousine', monospace" }}>✕ CLOSE</button>
                </div>
                
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1, background: "rgba(255, 217, 0, 0.15)" }}>
                  <div style={{ background: "#000000", padding: 14 }}>
                    <div style={{ fontSize: 9, color: "#ff4d6d", fontWeight: 700, marginBottom: 8, letterSpacing: "1.5px", fontFamily: "'Cousine', monospace" }}>[ ORIGINAL BUFFER ]</div>
                    <pre style={{ margin: 0, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: "#c9d1d9", overflowX: "auto", whiteSpace: "pre-wrap", lineHeight: 1.6 }}>
                      {code}
                    </pre>
                  </div>
                  <div style={{ background: "#000000", padding: 14 }}>
                    <div style={{ fontSize: 9, color: "#ffd900", fontWeight: 700, marginBottom: 8, display: "flex", justifySpace: "space-between", justifyContent: "space-between", alignItems: "center", letterSpacing: "1.5px", fontFamily: "'Cousine', monospace" }}>
                      <span>[ REFACTORED OUTPUT ]</span>
                      <button onClick={() => { navigator.clipboard.writeText(fixedCode); }} style={{ background: "none", border: "none", color: "#ffd900", cursor: "pointer", fontSize: 8, textDecoration: "underline", fontWeight: 700 }}>COPY CODE</button>
                    </div>
                    <pre style={{ margin: 0, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: "#ffffff", overflowX: "auto", whiteSpace: "pre-wrap", lineHeight: 1.6 }}>
                      {fixedCode}
                    </pre>
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* RIGHT SECTION: Multi-scoring, canvas, history and meta reviewer */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            
            {/* Multi-Dimensional scoring index */}
            {(Object.values(status).some(s => s !== "idle") || meta || staticFindings.length > 0) && (
              <div style={{ ...styles.card, padding: 16, background: "#000000" }}>
                <CornerCrosses />
                <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                  <span style={{ fontSize: 9, color: "#ffd900", letterSpacing: "2.5px", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                    [ ANALYSIS_TELEMETRY_INDICES ]
                  </span>
                  <span style={{ fontSize: 8.5, color: "rgba(255,255,255,0.3)", fontFamily: "'Cousine', monospace" }}>
                    // STICKER: ACTIVE
                  </span>
                </div>

                <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
                  <div style={{ position: "relative", width: 84, height: 84 }}>
                    <svg width="84" height="84" viewBox="0 0 84 84" style={{ transform: "rotate(-90deg)" }}>
                      <circle cx="42" cy="42" r="36" fill="transparent" stroke="rgba(255, 217, 0, 0.04)" strokeWidth="5" />
                      <circle cx="42" cy="42" r="36" fill="transparent"
                        stroke={scores.readiness > 80 ? "#06d6a0" : scores.readiness > 50 ? "#ffd166" : "#ff4d6d"}
                        strokeWidth="5"
                        strokeDasharray={2 * Math.PI * 36}
                        strokeDashoffset={(2 * Math.PI * 36) - (scores.readiness / 100) * (2 * Math.PI * 36)}
                        strokeLinecap="square"
                        style={{ transition: "stroke-dashoffset 0.4s ease" }}
                      />
                    </svg>
                    <div style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", fontFamily: "'Cousine', monospace" }}>
                      <span style={{ fontSize: 14, fontWeight: 900, color: "#ffffff" }}>{scores.readiness}%</span>
                      <span style={{ fontSize: 6, color: "rgba(255,255,255,0.4)", letterSpacing: "0.5px" }}>DEPLOY</span>
                    </div>
                  </div>

                  <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 5, fontSize: 9.5, fontFamily: "'Cousine', monospace" }}>
                    {/* Security metric */}
                    <div>
                      <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", marginBottom: 2 }}>
                        <span>SECURITY INDEX</span>
                        <span style={{ color: scores.security > 80 ? "#06d6a0" : "#ff4d6d" }}>
                          {scores.security}% {getDelta('security') !== null && (getDelta('security') >= 0 ? `(+${getDelta('security')}%)` : `(${getDelta('security')}%)`)}
                        </span>
                      </div>
                      <div style={{ height: 3, background: "rgba(255,255,255,0.05)" }}>
                        <div style={{ height: "100%", width: `${scores.security}%`, background: "#ff4d6d", transition: "width 0.3s" }} />
                      </div>
                    </div>

                    {/* Privacy metric */}
                    <div>
                      <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", marginBottom: 2 }}>
                        <span>PRIVACY ALIGNMENT</span>
                        <span style={{ color: scores.privacy > 80 ? "#06d6a0" : "#a855f7" }}>
                          {scores.privacy}% {getDelta('privacy') !== null && (getDelta('privacy') >= 0 ? `(+${getDelta('privacy')}%)` : `(${getDelta('privacy')}%)`)}
                        </span>
                      </div>
                      <div style={{ height: 3, background: "rgba(255,255,255,0.05)" }}>
                        <div style={{ height: "100%", width: `${scores.privacy}%`, background: "#a855f7", transition: "width 0.3s" }} />
                      </div>
                    </div>

                    {/* Quality metric */}
                    <div>
                      <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", marginBottom: 2 }}>
                        <span>CODE MAINTAINABILITY</span>
                        <span style={{ color: scores.maintainability > 80 ? "#06d6a0" : "#ffd166" }}>
                          {scores.maintainability}% {getDelta('maintainability') !== null && (getDelta('maintainability') >= 0 ? `(+${getDelta('maintainability')}%)` : `(${getDelta('maintainability')}%)`)}
                        </span>
                      </div>
                      <div style={{ height: 3, background: "rgba(255,255,255,0.05)" }}>
                        <div style={{ height: "100%", width: `${scores.maintainability}%`, background: "#06d6a0", transition: "width 0.3s" }} />
                      </div>
                    </div>
                  </div>
                </div>

              </div>
            )}

            {/* Active Hacking Exploit Simulator Drawer */}
            {simulatingExploit && (
              <div style={{ ...styles.card, padding: 16, background: "#060303", border: "1px solid #ff4d6d" }}>
                <CornerCrosses />
                <div style={{ display: "flex", alignItems: "center", justifySpace: "space-between", justifyContent: "space-between", marginBottom: 10, borderBottom: "1px solid rgba(255, 77, 109, 0.2)", paddingBottom: 6 }}>
                  <span style={{ fontSize: 9, color: "#ff4d6d", letterSpacing: "2px", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                    [ EXPLOIT PATH ATTACK VECTOR SIMULATOR ]
                  </span>
                  <button onClick={() => setSimulatingExploit(false)} style={{ background: "none", border: "none", color: "#ff4d6d", cursor: "pointer", fontSize: 9, fontFamily: "'Cousine', monospace" }}>✕ CLOSE</button>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6, fontFamily: "'Cousine', monospace", fontSize: 10, color: "#ffffff", lineHeight: 1.6 }}>
                  {exploitLog.map((log, i) => (
                    <div key={i} style={{ color: log.includes("SUCCESS") || log.includes("MATCH") ? "#ff4d6d" : "#8b949e" }}>
                      {log}
                    </div>
                  ))}
                  {exploitLog.length < 5 && <span style={{ display: "inline-block", width: 6, height: 11, background: "#ff4d6d", animation: "blink 1s step-end infinite" }} />}
                </div>
              </div>
            )}

            {/* Permanent Compliance Data Flow Canvas */}
            <div style={{ ...styles.card, height: 260, overflow: "hidden" }}>
              <CornerCrosses />
              <PrivacyFlowCanvas code={code} reportText={panels.compliance} status={status.compliance} />
            </div>

            {/* Meta Synthesizer Verdict */}
            {metaStatus !== "idle" && (
              <div style={{ ...styles.card, border: `1px solid ${metaStatus === "done" ? "#ffd900" : (metaStatus === "failed" ? "#ff4d6d" : "rgba(255, 217, 0, 0.15)")}`, transition: "border-color 0.5s" }}>
                <CornerCrosses />
                
                <div style={{ padding: "10px 16px", borderBottom: "1px solid rgba(255, 217, 0, 0.12)", display: "flex", alignItems: "center", gap: 10, background: "#050505" }}>
                  <span style={{ fontSize: 16, color: metaStatus === "failed" ? "#ff4d6d" : "#ffd900" }}>◉</span>
                  <span style={{ flex: 1, fontSize: 9.5, fontWeight: 800, color: metaStatus === "failed" ? "#ff4d6d" : "#ffd900", letterSpacing: "2.5px", fontFamily: "'Cousine', monospace" }}>
                    [ SYSTEM_SYNTHESIS_REPORTS ]
                  </span>
                  
                  <span style={{ fontSize: 8, padding: "2px 8px", border: `1px solid ${metaStatus === "failed" ? "#ff4d6d40" : "rgba(255, 217, 0, 0.4)"}`, color: metaStatus === "failed" ? "#ff4d6d" : "#ffd900", background: metaStatus === "failed" ? "rgba(255, 77, 109, 0.08)" : "rgba(255, 217, 0, 0.04)", borderRadius: 0, fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
                    {metaStatus === "synthesizing" ? "COMPILING..." : (metaStatus === "failed" ? "FAILED ⚠️" : "COMPLETED")}
                  </span>
                </div>
                
                <div ref={metaRef} style={{ padding: 16, fontSize: 11, lineHeight: 1.8, color: metaStatus === "failed" ? "#ff4d6d" : "#ffffff", whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 230, overflowY: "auto", fontFamily: "'JetBrains Mono', monospace" }}>
                  {meta}
                  {metaStatus === "synthesizing" && <span style={{ display: "inline-block", width: 6, height: 11, background: "#ffd900", marginLeft: 2, animation: "blink 1s step-end infinite", verticalAlign: "middle" }} />}
                </div>
                
                {metaStatus === "done" && meta && (
                  <div style={{ padding: "10px 16px", borderTop: "1px solid rgba(255, 217, 0, 0.12)", display: "flex", gap: 10, background: "#050505" }}>
                    <button onClick={() => { navigator.clipboard.writeText(meta); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
                      style={{ ...styles.btn(false), padding: "8px 18px", border: `1px solid ${copied ? "#06d6a0" : "rgba(255, 255, 255, 0.15)"}`, color: copied ? "#06d6a0" : "#ffffff" }}>
                      {copied ? "✓ COPIED!" : "⎘ COPY SUMMARY"}
                    </button>
                    {fixedCode && (
                      <button onClick={() => setShowDiff(prev => !prev)}
                        style={{ ...styles.btn(false), padding: "8px 18px", border: `1px solid ${showDiff ? "#ffd900" : "rgba(255, 255, 255, 0.1)"}`, color: showDiff ? "#ffd900" : "#8b949e" }}>
                        {showDiff ? "👁 HIDE DIFF" : "👁 COMPILER DIFF"}
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Local Storage Scans History Log */}
            {history.length > 0 && (
              <div style={{ ...styles.card, padding: 16, background: "#000000" }}>
                <CornerCrosses />
                <div style={{ fontSize: 9, color: "#ffd900", letterSpacing: "2.5px", fontWeight: 700, fontFamily: "'Cousine', monospace", marginBottom: 12 }}>
                  [ SCANS HISTORY MEMORY (LOCAL) ]
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 10, fontFamily: "'Cousine', monospace" }}>
                  {history.map((h, i) => (
                    <div key={h.id} style={{ display: "flex", alignItems: "center", justifySpace: "space-between", justifyContent: "space-between", borderBottom: i < history.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none", paddingBottom: 6 }}>
                      <span style={{ color: "#ffffff" }}>#{history.length - i} [{h.timestamp}] ({h.language})</span>
                      <span style={{ color: h.scores.readiness > 80 ? "#06d6a0" : "#ff4d6d" }}>
                        Readiness: {h.scores.readiness}% ({h.issues} issues)
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>

        </div>

      </div>

      {/* Footer CLI Bar */}
      <div style={{ padding: "10px 40px", borderTop: "1px solid rgba(255, 217, 0, 0.12)", display: "flex", gap: 16, alignItems: "center", background: "#000000", fontSize: 9, color: "#8b949e", letterSpacing: "1.5px" }}>
        <span style={{ fontWeight: 800, color: "#ffd900", fontFamily: "'Cousine', monospace" }}>[ CLI SHORTCUTS ]</span>
        <span>RUN: ^ENTER</span>
        <span>RESET: ESC</span>
        <span>MAXIMIZE: 1-4 KEYS</span>
        <span>DIFF: CTRL+D</span>
        <span style={{ marginLeft: "auto", color: reviewing ? "#ffd900" : "#06d6a0", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
          ● PIPELINE STATUS: {reviewing ? "PARALLEL LLM AGENTS RUNNING..." : "HYBRID HEURISTICS & REASONING ONLINE"}
        </span>
      </div>
    </div>
  );
}
