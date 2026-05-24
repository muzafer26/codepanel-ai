import { GoogleGenerativeAI } from "@google/generative-ai";
import * as acorn from "acorn";
import { rateLimit } from "../limiter";

interface ASTSummary {
  functions: Array<{ name: string; params: string[] }>;
  variables: string[];
  imports: string[];
  calls: string[];
  errors: string[];
}

function getASTSummary(code: string, language = "javascript"): ASTSummary {
  const summary: ASTSummary = {
    functions: [],
    variables: [],
    imports: [],
    calls: [],
    errors: []
  };

  const isJSOrTS = ["javascript", "typescript", "js", "ts", "jsx", "tsx"].includes(language.toLowerCase());

  if (!isJSOrTS) {
    // Basic regex-based parser for Python and other languages
    try {
      const funcRegex = /def\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)/g;
      let m;
      while ((m = funcRegex.exec(code)) !== null) {
        summary.functions.push({
          name: m[1],
          params: m[2].split(",").map(p => p.trim()).filter(Boolean)
        });
      }
      const importRegex = /(?:import\s+([a-zA-Z0-9_, ]+)|from\s+([a-zA-Z0-9_.]+)\s+import\s+([a-zA-Z0-9_*, ]+))/g;
      while ((m = importRegex.exec(code)) !== null) {
        summary.imports.push(m[1] || `${m[3]} from ${m[2]}`);
      }
      const varRegex = /\b([a-zA-Z0-9_]+)\s*=\s*/g;
      while ((m = varRegex.exec(code)) !== null) {
        if (!["if", "elif", "while", "for"].includes(m[1])) {
          summary.variables.push(m[1]);
        }
      }
    } catch (e: any) {
      summary.errors.push(e.message);
    }
    return summary;
  }

  try {
    // JavaScript/TypeScript Acorn parsing
    const parsed = acorn.parse(code, { ecmaVersion: 2022, sourceType: "module" });

    // Lightweight tree walker
    function walk(node: any) {
      if (!node) return;

      if (node.type === "FunctionDeclaration") {
        summary.functions.push({
          name: node.id?.name || "anonymous",
          params: node.params.map((p: any) => p.name || (p.type === "AssignmentPattern" ? p.left?.name : "param"))
        });
      } else if (node.type === "VariableDeclarator") {
        if (node.id.type === "Identifier") {
          summary.variables.push(node.id.name);
        }
      } else if (node.type === "ImportDeclaration") {
        summary.imports.push(node.source.value);
      } else if (node.type === "CallExpression") {
        let calleeName = "";
        if (node.callee.type === "Identifier") {
          calleeName = node.callee.name;
        } else if (node.callee.type === "MemberExpression") {
          const obj = node.callee.object?.name || "object";
          const prop = node.callee.property?.name || "property";
          calleeName = `${obj}.${prop}`;
        }
        if (calleeName) {
          summary.calls.push(calleeName);
        }
      }

      for (const key in node) {
        if (node[key] && typeof node[key] === "object") {
          if (Array.isArray(node[key])) {
            node[key].forEach(walk);
          } else {
            walk(node[key]);
          }
        }
      }
    }

    walk(parsed);
  } catch (e: any) {
    summary.errors.push(e.message);
  }

  return summary;
}

const PROMPTS: Record<string, (code: string, lang: string, astContext: string) => string> = {
  security: (code, lang, astContext) => `You are a professional security static analysis engine.
Analyze this ${lang} code. You must be realistic, precise, and avoid false positives.

CRITICAL RULES:
1. DO NOT FORCE FINDINGS. If the code is clean, simple, or trivial (e.g., console.log, basic variable assigns, simple loops), explicitly output:
   "[PASS] No significant security issues detected."
   "VERDICT: No major security vulnerabilities found."
2. ONLY REPORT TECHNICALLY JUSTIFIED FINDINGS. Every finding must have clear exploitability, real-world impact, and correct confidence.
3. MAP FINDINGS TO OWASP Top 10 and CWE. For example:
   - SQL Injection ➔ CWE-89 (OWASP A03:2021-Injection)
   - Hardcoded Secrets ➔ CWE-798 (OWASP A02:2021-Cryptographic Failures)
   - Dangerous eval() ➔ CWE-94 (OWASP A03:2021-Injection)
   - Unencrypted transmission ➔ CWE-319 (OWASP A02:2021-Cryptographic Failures)
4. USE REALISTIC SEVERITY levels:
   - CRITICAL: Remote exploits, SQL injection, hardcoded secrets, plain passwords, arbitrary eval execution, authentication bypass.
   - HIGH: Insecure HTTP (unencrypted fetch), unsafe RegExp (ReDoS), sensitive logging of PII.
   - MEDIUM: Blocking sync calls, inefficient loops.
   - LOW: Style, formatting, readability.
5. ASSIGN ACCURATE CONFIDENCE: 90-100% only for obvious direct exploits, 70-85% for strong heuristics, 40-60% for speculative issues.

${astContext}

Output format:
Use these prefixes:
[SCAN] when examining something
[WARN] when spotting a potential issue (always include CONFIDENCE: X% based on exploitability)
[VULN] when confirming a vulnerability (always include CONFIDENCE: X% based on exploitability)
[PASS] when something looks safe

End with VERDICT: listing all security issues with severity (CRITICAL/HIGH/MED/LOW) and CONFIDENCE (%).

Code:
\`\`\`${lang}
${code}
\`\`\``,

  performance: (code, lang, astContext) => `You are a professional static performance analyzer.
Analyze this ${lang} code. Focus on CPU/RAM bottlenecks, O(N^2) loops, database query optimizations, and resource leaks.

CRITICAL RULES:
1. DO NOT FORCE FINDINGS. If the code is trivial, small, or lacks resource-intensive operations, explicitly output:
   "[OK] No performance bottlenecks identified."
   "VERDICT: Performance is optimal for this scale."
2. DO NOT suggest caching, database index strategies, or parallel concurrency for simple snippets (like name = "xyz"; console.log(name)).
3. Report only high-impact issues: actual blocking sync operations in event loops, deeply nested loops, or resource leaks.

${astContext}

Output format:
Use these prefixes:
[PROFILE] when examining a section
[SLOW] when detecting a bottleneck (always include CONFIDENCE: X% based on execution path)
[LEAK] when detecting a memory/resource leak (always include CONFIDENCE: X%)
[OK] when something is efficient

End with VERDICT: listing all performance issues with impact (SEVERE/MODERATE/MINOR) and CONFIDENCE (%). Suggest caching user transaction/data tables if applicable.

Code:
\`\`\`${lang}
${code}
\`\`\``,

  style: (code, lang, astContext) => `You are a professional static code quality analyzer.
Analyze this ${lang} code for maintainability, structural smells, and design patterns.

CRITICAL RULES:
1. DO NOT FORCE FINDINGS. Avoid fake "technical debt" findings for tiny or standard snippets. If code is simple and readable, explicitly output:
   "[GOOD] No code quality issues found. Code is simple and maintainable."
   "VERDICT: Clean and readable."
2. Report only genuine issues: deeply nested conditional blocks, duplicated code blocks, or heavily polluted files.

${astContext}

Output format:
Use these prefixes:
[READ] when reading a section
[SMELL] when detecting a code smell (always include CONFIDENCE: X% based on guidelines)
[DEBT] when spotting tech debt (always include CONFIDENCE: X%)
[GOOD] when something is well-written

End with VERDICT: listing all quality issues with impact (HIGH/MED/LOW) and CONFIDENCE (%).

Code:
\`\`\`${lang}
${code}
\`\`\``,

  compliance: (code, lang, astContext) => `You are a regulatory compliance and data privacy auditing engine.
Analyze this ${lang} code for GDPR, PCI-DSS, and HIPAA violations.

CRITICAL RULES:
1. DO NOT FORCE FINDINGS. If the code is clean or doesn't handle sensitive PII, explicitly output:
   "[SAFE] No compliance/privacy violations detected."
   "VERDICT: Privacy standards compliant."
2. DOMAIN-AWARE REGULATORY RULES:
   - PCI-DSS: Only warn about PCI-DSS violations if credit card numbers, CVVs, or billing details are handled, stored, or logged insecurely.
   - HIPAA: Only warn about HIPAA violations if Protected Health Information (PHI) such as patient identifiers, medical history, clinical records, or healthcare details are detected. Do NOT flag standard contact variables like email or phone as HIPAA violations unless medical data is present.
   - GDPR: Flag GDPR compliance violations for generic contact identifiers (email, phone, address) logged or transmitted insecurely.
3. ONLY classify variables as sensitive if they strongly match: password, token, apiKey, secret, cardNumber, cvv, ssn, email, phone. Do NOT treat generic variables like name, count, temp, data, value as privacy leaks unless contextual evidence exists.

${astContext}

Output format:
Use these prefixes:
[PII] when spotting sensitive personal data handling
[LEAK] when detecting data leakage or insecure storage (always include CONFIDENCE: X% based on data exposure)
[GDPR] for compliance and privacy violations (always include CONFIDENCE: X%)
[SAFE] when personal info is handled securely

End with VERDICT: listing all compliance/privacy issues with severity (CRITICAL/HIGH/MED/LOW) and CONFIDENCE (%).

Code:
\`\`\`${lang}
${code}
\`\`\``,
};

async function generateWithRetry(model: any, prompt: string, retries = 3, delay = 1500) {
  for (let i = 0; i < retries; i++) {
    try {
      return await model.generateContentStream(prompt);
    } catch (error: any) {
      const isRateLimit = error.status === 429 || error.message?.includes("429") || error.message?.includes("quota") || error.message?.includes("limit");
      if (isRateLimit && i < retries - 1) {
        console.warn(`Rate limit hit in review endpoint. Retrying in ${delay}ms (attempt ${i + 1}/${retries})...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        delay *= 2.5; // exponential backoff
        continue;
      }
      throw error;
    }
  }
}

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "127.0.0.1";
  
  if (!rateLimit(ip, 30)) {
    return new Response(JSON.stringify({ error: "Rate limit exceeded. Maximum 30 requests per minute." }), {
      status: 429,
      headers: { "Content-Type": "application/json" }
    });
  }

  try {
    const { code, language, agentType } = await req.json();

    if (!code || !agentType) {
      return new Response("Missing code or agentType", { status: 400 });
    }

    const astSummary = getASTSummary(code, language || "javascript");
    let astContext = "AST STRUCTURE CONTEXT:\n";
    if (astSummary.errors.length > 0) {
      astContext += `- AST Parsing Status: Partial (error: ${astSummary.errors.join(", ")})\n`;
    } else {
      if (astSummary.functions.length > 0) {
        astContext += `- Functions: ${astSummary.functions.map(f => `${f.name}(${f.params.join(", ")})`).join(", ")}\n`;
      }
      if (astSummary.variables.length > 0) {
        astContext += `- Declared Variables: ${Array.from(new Set(astSummary.variables)).slice(0, 15).join(", ")}\n`;
      }
      if (astSummary.imports.length > 0) {
        astContext += `- Imported Modules: ${Array.from(new Set(astSummary.imports)).join(", ")}\n`;
      }
      if (astSummary.calls.length > 0) {
        astContext += `- Key Calls: ${Array.from(new Set(astSummary.calls)).slice(0, 15).join(", ")}\n`;
      }
    }

    const prompt = PROMPTS[agentType]?.(code, language || "javascript", astContext);
    if (!prompt) return new Response("Invalid agentType", { status: 400 });

    const apiKey = process.env.GROQ_API_KEY || process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return new Response(JSON.stringify({ error: "Missing API Key. Please configure GEMINI_API_KEY or GROQ_API_KEY in your environment." }), { status: 500 });
    }

    if (apiKey.startsWith("gsk_")) {
      const stream = new ReadableStream({
        async start(controller) {
          try {
            const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${apiKey}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                model: "llama-3.3-70b-versatile",
                messages: [{ role: "user", content: prompt }],
                stream: true
              })
            });

            if (!res.ok) {
              const errText = await res.text();
              throw new Error(`Groq API returned ${res.status}: ${errText}`);
            }

            const reader = res.body!.getReader();
            const decoder = new TextDecoder();
            let buffer = "";

            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              buffer += decoder.decode(value, { stream: true });
              const lines = buffer.split("\n");
              buffer = lines.pop() || "";

              for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed) continue;
                if (trimmed === "data: [DONE]") continue;
                if (trimmed.startsWith("data: ")) {
                  try {
                    const json = JSON.parse(trimmed.substring(6));
                    const content = json.choices?.[0]?.delta?.content;
                    if (content) {
                      controller.enqueue(new TextEncoder().encode(content));
                    }
                  } catch (e) {
                    // ignore JSON parse errors in SSE chunks
                  }
                }
              }
            }
          } catch (error: any) {
            controller.enqueue(new TextEncoder().encode(`\n\n[API_ERROR] ${error.message || "Unknown Groq review error"}`));
          } finally {
            controller.close();
          }
        }
      });

      return new Response(stream, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Transfer-Encoding": "chunked",
          "Cache-Control": "no-cache",
        },
      });
    } else {
      const genAI = new GoogleGenerativeAI(apiKey);
      const stream = new ReadableStream({
        async start(controller) {
          try {
            const model = genAI.getGenerativeModel({ model: "gemini-3.5-flash" });
            const result = await generateWithRetry(model, prompt);

            for await (const chunk of result.stream) {
              const text = chunk.text();
              if (text) {
                controller.enqueue(new TextEncoder().encode(text));
              }
            }
          } catch (error: any) {
            controller.enqueue(new TextEncoder().encode(`\n\n[API_ERROR] ${error.message || "Unknown review API error"}`));
          } finally {
            controller.close();
          }
        },
      });

      return new Response(stream, {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Transfer-Encoding": "chunked",
          "Cache-Control": "no-cache",
        },
      });
    }
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}
