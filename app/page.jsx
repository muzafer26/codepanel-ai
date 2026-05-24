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

function parsePrivacyFlow(code, reportText) {
  const nodes = [];
  const links = [];
  if (!code) return { nodes, links, isLeak: false };

  const sourceKeywords = ['card', 'cvv', 'email', 'phone', 'ssn', 'password', 'secret', 'token', 'userid', 'user', 'health', 'patient', 'billing'];
  const sinkKeywords = ['console.log', 'console.error', 'console.warn', 'print', 'logger', 'fetch', 'axios', 'request', 'xhr', 'send', 'execute', 'query', 'db.'];

  const lines = code.split('\n');
  const detectedSources = new Set();
  const detectedSinks = new Set();
  const detectedVariables = new Set();

  // Extract identifiers and classify sources/sinks
  lines.forEach(line => {
    const words = line.match(/[a-zA-Z0-9_$]+/g) || [];
    words.forEach(word => {
      if (word.length <= 2) return;
      const lower = word.toLowerCase();
      
      const isSource = sourceKeywords.some(kw => lower.includes(kw));
      const isSink = sinkKeywords.some(kw => lower.includes(kw));
      
      if (isSource) {
        detectedSources.add(word);
      } else if (isSink) {
        detectedSinks.add(word);
      } else if (word !== 'function' && word !== 'const' && word !== 'let' && word !== 'var' && word !== 'return') {
        detectedVariables.add(word);
      }
    });

    // Capture compound expressions like console.log
    sinkKeywords.forEach(sinkKw => {
      if (line.includes(sinkKw)) {
        detectedSinks.add(sinkKw);
      }
    });
  });

  // Defaults if empty
  if (detectedSources.size === 0) {
    detectedSources.add('email');
    detectedSources.add('cardNumber');
  }
  if (detectedSinks.size === 0) {
    detectedSinks.add('console.log');
    detectedSinks.add('fetch');
  }

  const sourceList = Array.from(detectedSources);
  const varList = Array.from(detectedVariables).filter(v => !detectedSources.has(v) && !detectedSinks.has(v)).slice(0, 5);
  const sinkList = Array.from(detectedSinks);

  sourceList.forEach(name => {
    nodes.push({ id: name, type: 'source', color: '#ffd900', size: 10 });
  });
  varList.forEach(name => {
    nodes.push({ id: name, type: 'variable', color: '#06d6a0', size: 7 });
  });
  sinkList.forEach(name => {
    nodes.push({ id: name, type: 'sink', color: '#58a6ff', size: 11 });
  });

  const isLeak = /leak|pii|gdpr|violation|logging|unencrypted|expose/i.test(reportText || "");

  // Link variables co-occurring on same line
  sourceList.forEach(src => {
    let linked = false;
    lines.forEach(line => {
      varList.forEach(v => {
        if (line.includes(src) && line.includes(v)) {
          links.push({ source: src, target: v, isUnsafe: false });
          linked = true;
        }
      });
    });

    if (!linked) {
      lines.forEach(line => {
        sinkList.forEach(sink => {
          if (line.includes(src) && line.includes(sink)) {
            const isUnsafe = isLeak && (sink.includes('log') || sink.includes('fetch') || sink.includes('print'));
            links.push({ source: src, target: sink, isUnsafe });
            linked = true;
          }
        });
      });
    }
  });

  varList.forEach(v => {
    lines.forEach(line => {
      sinkList.forEach(sink => {
        if (line.includes(v) && line.includes(sink)) {
          const isUnsafe = isLeak && (sink.includes('log') || sink.includes('fetch') || sink.includes('print'));
          links.push({ source: v, target: sink, isUnsafe });
        }
      });
    });
  });

  if (links.length === 0) {
    sourceList.forEach((src, idx) => {
      if (varList.length > 0) {
        const v = varList[idx % varList.length];
        links.push({ source: src, target: v, isUnsafe: false });
        if (sinkList.length > 0) {
          const sink = sinkList[idx % sinkList.length];
          const isUnsafe = isLeak && (sink.includes('log') || sink.includes('fetch'));
          links.push({ source: v, target: sink, isUnsafe });
        }
      } else if (sinkList.length > 0) {
        const sink = sinkList[idx % sinkList.length];
        links.push({ source: src, target: sink, isUnsafe: isLeak });
      }
    });
  }

  const sources = nodes.filter(n => n.type === 'source');
  const variables = nodes.filter(n => n.type === 'variable');
  const sinks = nodes.filter(n => n.type === 'sink');

  sources.forEach((n, i) => {
    n.xPercent = 0.18;
    n.yPercent = sources.length <= 1 ? 0.5 : 0.22 + (i * 0.56) / (sources.length - 1);
  });
  variables.forEach((n, i) => {
    n.xPercent = 0.5;
    n.yPercent = variables.length <= 1 ? 0.5 : 0.18 + (i * 0.64) / (variables.length - 1);
  });
  sinks.forEach((n, i) => {
    n.xPercent = 0.82;
    n.yPercent = sinks.length <= 1 ? 0.5 : 0.32 + (i * 0.36) / (sinks.length - 1);
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

function calculateRisk(panels) {
  const text = Object.values(panels).join("\n");
  const criticals = (text.match(/\[VULN\]|\[LEAK\]|CRITICAL|🔴|severe|leak|compliance violation|gdpr/gi) || []).length;
  const warnings = (text.match(/\[WARN\]|\[SLOW\]|\[SMELL\]|HIGH|🟡|warning|pii|exposure/gi) || []).length;
  const lows = (text.match(/\[PASS\]|\[OK\]|\[GOOD\]|\[DEBT\]|\[SAFE\]|LOW|🟢|info|compliance|style/gi) || []).length;
  
  const score = Math.max(10, 100 - (criticals * 15 + warnings * 5 + lows * 2));
  return { criticals, warnings, lows, score };
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

  const reset = useCallback(() => {
    setPanels({ security: "", performance: "", style: "", compliance: "" });
    setStatus({ security: "idle", performance: "idle", style: "idle", compliance: "idle" });
    setMeta("");
    setMetaStatus("idle");
    setError(null);
    setExpandedPanel(null);
    setShowDiff(false);
    setFixedCode("");
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

  const startReview = useCallback(async () => {
    if (!code.trim() || reviewing) return;
    reset();
    setReviewing(true);
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
        const parsedFix = extractFixedCode(finalMeta);
        if (parsedFix) {
          setFixedCode(parsedFix);
        }
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

  const risk = calculateRisk(panels);

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
          @import url('https://fonts.googleapis.com/css2?family=Cousine:ital,wght=0,400;0,700;1,400;1,700&family=Inter:wght@400;500;700;900&display=swap');
          
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
            <span>[ COMPLIANCE: GDPR ]</span>
            <span>[ STACK: GEMINI_3.5 ]</span>
          </div>
          <div>
            <button onClick={() => setViewMode("console")} className="btn-block-outline" style={{ ...styles.btn(false), padding: "8px 18px", fontSize: 9 }}>
              [ INITIALIZE_CONSOLE ]
            </button>
          </div>
        </div>

        {/* Hero Section */}
        <div style={{ maxWidth: 1080, width: "100%", padding: "80px 24px 20px 24px", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", zIndex: 2, boxSizing: "border-box" }}>
          
          <div style={{ display: "inline-flex", padding: "6px 14px", border: "1px solid #ffd900", borderRadius: 0, fontSize: 10, fontWeight: 700, color: "#ffd900", letterSpacing: "3px", textTransform: "uppercase", marginBottom: 28, background: "rgba(255, 217, 0, 0.04)", fontFamily: "'Cousine', monospace" }}>
            [ APERTURE AGENTIC SHIELDING PIPELINE ]
          </div>
          
          <h1 style={{ fontSize: "3.6rem", fontWeight: 900, margin: "0 0 18px 0", letterSpacing: "-1.8px", fontFamily: "'Inter', sans-serif", textTransform: "uppercase", lineHeight: 1.1, maxWidth: 880 }}>
            Automated Audit Telemetry. <br />
            <span style={{ color: "#ffd900" }}>Shielding Code Assets.</span>
          </h1>
          
          <p style={{ fontSize: 14.5, color: "#8b949e", lineHeight: 1.7, margin: "0 auto 36px auto", maxWidth: 680, fontFamily: "'Inter', sans-serif" }}>
            An autonomous multi-agent analysis matrix that parses code structures, traces sensitive variables to leakage endpoints, and generates instant PCI-DSS/GDPR compliance telemetry logs.
          </p>

          <div style={{ display: "flex", gap: 12, justifyContent: "center", marginBottom: 64 }}>
            <button onClick={() => setViewMode("console")} className="btn-block-yellow"
              style={{ ...styles.btn(true), padding: "16px 36px", fontSize: 11 }}>
              [ Launch Console Workspace ]
            </button>
            <button onClick={() => {
              const el = document.getElementById("feature-anchor");
              if (el) el.scrollIntoView({ behavior: "smooth" });
            }} className="btn-block-outline"
              style={{ ...styles.btn(false), padding: "16px 36px", fontSize: 11 }}>
              [ Explanatory Matrix ]
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
              
              <div style={{ padding: 16, background: "#030303", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
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

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderTop: "1px solid rgba(255, 217, 0, 0.12)", paddingTop: 12, marginTop: 12 }}>
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
          <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", paddingBottom: 16, marginBottom: 28 }}>
            <span style={{ fontSize: 11, fontFamily: "'Cousine', monospace", color: "#ffd900", letterSpacing: "2.5px" }}>[ APERTURE AUTOMATED ENGINE SPECIFICATIONS ]</span>
            <span style={{ fontSize: 9, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.3)" }}>// VERSION 1.4 // CLOUD SYNC</span>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
            
            <div className="feature-cell">
              <CornerCrosses />
              <div style={{ fontSize: 24, fontWeight: 900, color: "#ffd900", fontFamily: "'Cousine', monospace", marginBottom: 12 }}>01 //</div>
              <h3 style={{ fontSize: 12, fontWeight: 900, color: "#ffffff", letterSpacing: "1.5px", fontFamily: "'Cousine', monospace", marginBottom: 8 }}>SECURITY AUDITOR</h3>
              <p style={{ fontSize: 11.5, color: "#8b949e", lineHeight: 1.6, marginBottom: 14 }}>
                Scans structural representations to pinpoint OWASP Top 10 breaches, unencrypted variables, and hardcoded system access credentials.
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
                Exposes query bottleneck patterns, unclosed memory buffers, complex loops, and execution-blocking asynchronous nodes.
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
                Ingests files for structural code smells, DRY validation compliance, and alignment to functional SOLID design patterns.
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
                Audits variables handling PII against GDPR, HIPAA, and PCI rules. Generates telemetry nodes mapped to insecure logging sinks.
              </p>
              <div style={{ display: "flex", gap: 6, fontSize: 8, fontFamily: "'Cousine', monospace" }}>
                <span style={{ padding: "1px 5px", background: "rgba(168, 85, 247, 0.15)", border: "1px solid #a855f7", color: "#a855f7" }}>PCI-DSS</span>
                <span style={{ padding: "1px 5px", background: "rgba(168, 85, 247, 0.15)", border: "1px solid #a855f7", color: "#a855f7" }}>GDPR</span>
              </div>
            </div>

          </div>
        </div>

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
          <span style={{ fontSize: 8.5, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.3)" }}>// NODE: APERTURE-US-01</span>
          <span style={{ fontSize: 8.5, fontFamily: "'Cousine', monospace", color: "rgba(255,255,255,0.3)" }}>// PORT: 3002 // OK</span>
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

        {/* Master Bento Layout Columns */}
        <div className="cipher-dashboard-grid">
          
          {/* LEFT SECTION */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            
            {/* Input Editor Box */}
            <div style={styles.card}>
              <CornerCrosses />
              <div style={{ padding: "10px 16px", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", background: "#050505" }}>
                <span style={{ fontSize: 9, color: "#ffd900", letterSpacing: "2.5px", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>[ CELL_01 / SOURCE_INGESTION_BUFFER ]</span>
                
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginLeft: 16 }}>
                  {EXAMPLES.map((ex) => (
                    <button key={ex.label} onClick={() => { setCode(ex.code); setLanguage(ex.language); reset(); }}
                      style={{ ...styles.btn(false), padding: "4px 10px", fontSize: 8 }}>
                      {ex.label}
                    </button>
                  ))}
                </div>
                
                <select value={language} onChange={(e) => setLanguage(e.target.value)}
                  className="control-select"
                  style={{ marginLeft: "auto", background: "#000000", border: "1px solid rgba(255, 217, 0, 0.2)", color: "#ffffff", padding: "4px 10px", fontSize: 9, fontFamily: "'Cousine', monospace", cursor: "pointer", borderRadius: 0 }}>
                  {["javascript", "typescript", "python", "go", "java", "php"].map((l) => <option key={l} style={{ background: "#000000", color: "#ffffff" }}>{l}</option>)}
                </select>
              </div>

              <div style={{ display: "flex", background: "#000000", borderBottom: "1px solid rgba(255, 217, 0, 0.15)", minHeight: 200 }}>
                {/* Gutter Line Numbers */}
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

          {/* RIGHT SECTION */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            
            {/* Live Triage Diagnostics */}
            {(Object.values(status).some(s => s !== "idle") || meta) && (
              <div style={{ ...styles.card, padding: 16, background: "#000000" }}>
                <CornerCrosses />
                <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                  <span style={{ fontSize: 9, color: "#ffd900", letterSpacing: "2.5px", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>[ APERTURE_HEALTH_DIAGNOSTICS ]</span>
                  <span style={{ fontSize: 8.5, color: "rgba(255,255,255,0.3)", fontFamily: "'Cousine', monospace" }}>// LIVE_METRIC</span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
                  <div style={{ position: "relative", width: 96, height: 96 }}>
                    <svg width="96" height="96" viewBox="0 0 96 96" style={{ transform: "rotate(-90deg)" }}>
                      <circle cx="48" cy="48" r="40" fill="transparent" stroke="rgba(255, 217, 0, 0.05)" strokeWidth="6" />
                      <circle cx="48" cy="48" r="40" fill="transparent"
                        stroke={risk.score > 80 ? "#06d6a0" : risk.score > 50 ? "#ffd166" : "#ff4d6d"}
                        strokeWidth="6"
                        strokeDasharray={2 * Math.PI * 40}
                        strokeDashoffset={(2 * Math.PI * 40) - (risk.score / 100) * (2 * Math.PI * 40)}
                        strokeLinecap="square"
                        style={{ transition: "stroke-dashoffset 0.4s ease, stroke 0.4s" }}
                      />
                    </svg>
                    <div style={{ position: "absolute", top: 0, left: 0, right: 0, bottom: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyItems: "center", justifyContent: "center", fontFamily: "'Cousine', monospace" }}>
                      <span style={{ fontSize: 16, fontWeight: 900, color: "#ffffff" }}>{risk.score}%</span>
                      <span style={{ fontSize: 6.5, color: "rgba(255,255,255,0.4)", letterSpacing: "1px" }}>SCORE</span>
                    </div>
                  </div>

                  <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 6, fontSize: 9, fontFamily: "'Cousine', monospace" }}>
                    <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", borderBottom: "1px dashed rgba(255,255,255,0.06)", paddingBottom: 4 }}>
                      <span style={{ color: "#ff4d6d" }}>● CRITICAL VULNS</span>
                      <span style={{ color: "#ffffff", fontWeight: 700 }}>{risk.criticals}</span>
                    </div>
                    <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", borderBottom: "1px dashed rgba(255,255,255,0.06)", paddingBottom: 4 }}>
                      <span style={{ color: "#ffd166" }}>● COMPLIANCE RISKS</span>
                      <span style={{ color: "#ffffff", fontWeight: 700 }}>{risk.warnings}</span>
                    </div>
                    <div style={{ display: "flex", justifySpace: "space-between", justifyContent: "space-between", borderBottom: "1px dashed rgba(255,255,255,0.06)", paddingBottom: 4 }}>
                      <span style={{ color: "#06d6a0" }}>● CODE SMELL SMELLS</span>
                      <span style={{ color: "#ffffff", fontWeight: 700 }}>{risk.lows}</span>
                    </div>
                  </div>
                </div>

              </div>
            )}

            {/* Permanent Compliance Data Flow Canvas */}
            <div style={{ ...styles.card, height: 260, overflow: "hidden" }}>
              <CornerCrosses />
              <PrivacyFlowCanvas code={code} reportText={panels.compliance} status={status.compliance} />
            </div>

            {/* Meta Synthesizer */}
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
                
                <div ref={metaRef} style={{ padding: 16, fontSize: 11, lineHeight: 1.8, color: metaStatus === "failed" ? "#ff4d6d" : "#ffffff", whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 250, overflowY: "auto", fontFamily: "'JetBrains Mono', monospace" }}>
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

          </div>

        </div>

      </div>

      {/* Footer CLI Bar */}
      <div style={{ padding: "10px 40px", borderTop: "1px solid rgba(255, 217, 0, 0.12)", display: "flex", gap: 16, alignItems: "center", background: "#000000", fontSize: 9, color: "#8b949e", letterSpacing: "1.5px" }}>
        <span style={{ fontWeight: 800, color: "#ffd900", fontFamily: "'Cousine', monospace" }}>[ CLI SHORTCUTS ]</span>
        <span>RUN: ^ENTER</span>
        <span>RESET: ESC</span>
        <span>MAXIMIZE PANEL: 1-4 KEYS</span>
        <span>DIFF COMPARISON: CTRL+D</span>
        <span style={{ marginLeft: "auto", color: reviewing ? "#ffd900" : "#06d6a0", fontWeight: 700, fontFamily: "'Cousine', monospace" }}>
          ● STATUS: {reviewing ? "ACQUIRING REMOTE CLOUD DATA..." : "CONSOLE TELEMETRY PIPELINE ONLINE"}
        </span>
      </div>
    </div>
  );
}
