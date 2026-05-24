import { GoogleGenerativeAI } from "@google/generative-ai";
import { rateLimit } from "../limiter";

async function generateWithRetry(model: any, prompt: string, retries = 3, delay = 1500) {
  for (let i = 0; i < retries; i++) {
    try {
      return await model.generateContentStream(prompt);
    } catch (error: any) {
      const isRateLimit = error.status === 429 || error.message?.includes("429") || error.message?.includes("quota") || error.message?.includes("limit");
      if (isRateLimit && i < retries - 1) {
        console.warn(`Rate limit hit in meta endpoint. Retrying in ${delay}ms (attempt ${i + 1}/${retries})...`);
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
    const { security, performance, style, compliance, language } = await req.json();

    const prompt = `You are a principal systems architect and professional static code analysis synthesis engine.
Synthesize the findings of the four specialist code analysis agents into a single, definitive review.

CRITICAL INSTRUCTIONS:
1. DO NOT FORCE FINDINGS. If the specialist reports show no significant issues, explicitly output:
   - OVERALL SCORE: 10/10 (or 9/10 for trivial suggestions)
   - EXECUTIVE SUMMARY: No significant security, performance, or privacy issues were detected in this snippet. The code is simple, readable, and functional.
   - TOP ISSUES: None detected.
   - ONE THING DONE WELL: The code is concise and clear.
   - VERDICT FOR DEVELOPER: The code is safe and optimal.
2. AVOID DRAMATIC OR SCI-FI CYBERSECURITY LANGUAGE (e.g. "Critical telemetry breach matrix exposure"). Use professional, realistic engineering terms.
3. PRIORITIZE MEANINGFUL FINDINGS ONLY. Focus on true-positive, exploitable vulnerabilities or critical bottlenecks.
4. RESOLVE CONFLICTS. If there are conflicting recommendations (e.g. Performance agent recommending caching data, while Compliance/Privacy agent warns that caching contains unencrypted PII), provide the secure compromise solution in the RECOMMENDED REFACTORED CODE (e.g., separate PII from cached metadata, hash cached values, or disable caching specifically for sensitive keys).
5. PRACTICAL PRODUCTION-SAFE REFACTORING:
   - In the RECOMMENDED REFACTORED CODE block, you must output code that is production-ready, clean, and directly deployable.
   - Do NOT use placeholder cryptography (e.g., do NOT write fake keys like 'secretkey' or fake IVs like 'initvector' hardcoded in the file).
   - If cryptography is needed, load keys/IVs from secure environment variables (e.g., 'process.env.ENCRYPTION_KEY') or config managers, and write realistic, standard Node.js crypto or Web Crypto API invocations.
   - Preserve the user's original logic and intent. Minimize unnecessary rewrites. Avoid massive, over-engineered "enterprise architecture theater" for simple scripts. Keep fixes minimal, clean, and highly secure.

SECURITY REPORT:
${security || "No security issues reported."}

PERFORMANCE REPORT:
${performance || "No performance issues reported."}

CODE QUALITY REPORT:
${style || "No code quality issues reported."}

COMPLIANCE & DATA PRIVACY REPORT:
${compliance || "No compliance/privacy issues reported."}

Write the final verdict in this exact format:

OVERALL SCORE: X/10

EXECUTIVE SUMMARY:
[2-3 sentences summarizing the overall state of this code and any major agent conflicts you resolved]

TOP ISSUES (deduplicated, ranked by severity):
1. [CRITICAL/HIGH/MED/LOW] (Confidence: X%) — Issue title — Brief explanation
2. [severity] (Confidence: X%) — Issue title — Brief explanation
3. [severity] (Confidence: X%) — Issue title — Brief explanation
(max 5 issues, no repetition)

ONE THING DONE WELL:
[Something genuinely positive]

VERDICT FOR DEVELOPER:
[One punchy sentence they'll remember]

RECOMMENDED REFACTORED CODE:
\`\`\`${language}
[Provide the complete corrected/improved code incorporating all fixes and resolving the agent conflicts. Do not use placeholders. Give the full code so it can be copied or shown in side-by-side diff view. Ensure this section is at the very end of your response, starting with RECOMMENDED REFACTORED CODE: followed by a code block.]
\`\`\``;

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
            controller.enqueue(new TextEncoder().encode(`\n\n[API_ERROR] ${error.message || "Unknown Groq meta error"}`));
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
            controller.enqueue(new TextEncoder().encode(`\n\n[API_ERROR] ${error.message || "Unknown meta synthesis error"}`));
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
