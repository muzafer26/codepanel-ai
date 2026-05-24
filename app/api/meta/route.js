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

  const prompt = `You are a principal engineer. Four specialists reviewed this ${language} code. Synthesize their findings into one definitive review.

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
[2-3 sentences on the overall state of this code]

TOP ISSUES (deduplicated, ranked by severity):
1. [CRITICAL/HIGH/MED/LOW] — Issue title — Brief explanation
2. [severity] — Issue title — Brief explanation
3. [severity] — Issue title — Brief explanation
(max 5 issues, no repetition)

ONE THING DONE WELL:
[Something genuinely positive]

VERDICT FOR DEVELOPER:
[One punchy sentence they'll remember]

RECOMMENDED REFACTORED CODE:
\`\`\`${language}
[Provide the complete corrected/improved code incorporating all fixes. Do not use placeholders inside this code block. Give the full code so it can be copied or shown in side-by-side diff view. Ensure this section is at the very end of your response, starting with RECOMMENDED REFACTORED CODE: followed by a code block.]
\`\`\``;

  const apiKey = process.env.GEMINI_API_KEY || "AIzaSyAQs6XpdIcd_5SFtavS0uQT-Hx3sUfNdDI";
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
