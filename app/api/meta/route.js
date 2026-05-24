import { GoogleGenerativeAI } from "@google/generative-ai";

async function generateWithRetry(model, prompt, retries = 3, delay = 1500) {
  for (let i = 0; i < retries; i++) {
    try {
      return await model.generateContentStream(prompt);
    } catch (error) {
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

export async function POST(req) {
  const { security, performance, style, compliance, language } = await req.json();

  const prompt = `You are a principal architect. Four specialist agents reviewed this ${language} code.
Analyze their logs and synthesize their findings into one definitive review.

IMPORTANT CONFLICT RESOLUTION:
Look for conflicting recommendations between agents (e.g. Performance Engineer recommending caching database objects to speed up latency, while Privacy Shield warns that caching objects containing PII is a severe compliance leak).
You MUST reconcile these conflicts in your summary and provide a secure, compromise solution in the RECOMMENDED REFACTORED CODE (e.g., show how to cache only hashes or encrypted data, or separate PII data from cached metrics).

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
              model: "llama-3.3-70b-specdec",
              messages: [{ role: "user", content: prompt }],
              stream: true
            })
          });

          if (!res.ok) {
            const errText = await res.text();
            throw new Error(`Groq API returned ${res.status}: ${errText}`);
          }

          const reader = res.body.getReader();
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
        } catch (error) {
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
        } catch (error) {
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
}
