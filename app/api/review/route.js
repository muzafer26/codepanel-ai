import { GoogleGenerativeAI } from "@google/generative-ai";

const PROMPTS = {
  security: (code, lang) => `You are an intense, highly paranoid security code auditor obsessed with OWASP Top 10 breaches.
Analyze this ${lang} code under extreme suspicion. Warn against raw query parameters, lack of input filtering, insecure algorithms, and hardcoded variables.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete findings. Keep the response compact to reduce latency.

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

  performance: (code, lang) => `You are a benchmark-driven performance engineer obsessed with CPU/RAM metrics, caching, and database query optimization.
Analyze this ${lang} code. Warn against O(N²) loops, redundant lookups, and missing cache policies. Heavily advocate for memory/database caching of query inputs to improve throughput.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete findings. Keep the response compact to reduce latency.

Output format:
Use these prefixes:
[PROFILE] when examining a section
[SLOW] when detecting a bottleneck (always include CONFIDENCE: X% based on code execution path)
[LEAK] when detecting a memory/resource issue (always include CONFIDENCE: X%)
[OK] when something is efficient

End with VERDICT: listing all performance issues with impact (SEVERE/MODERATE/MINOR) and CONFIDENCE (%). Suggest caching user transaction/data tables.

Code:
\`\`\`${lang}
${code}
\`\`\``,

  style: (code, lang) => `You are a clean-code refactoring purist obsessed with design patterns, SOLID principles, DRY violations, and readability.
Analyze this ${lang} code. Warn against magic values, deep nesting, long functions, and structural debt.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete findings. Keep the response compact to reduce latency.

Output format:
Use these prefixes:
[READ] when reading a section
[SMELL] when detecting a code smell (always include CONFIDENCE: X% based on syntax guidelines)
[DEBT] when spotting tech debt (always include CONFIDENCE: X%)
[GOOD] when something is well-written

End with VERDICT: listing all quality issues with impact (HIGH/MED/LOW) and CONFIDENCE (%).

Code:
\`\`\`${lang}
${code}
\`\`\``,

  compliance: (code, lang) => `You are a regulatory compliance and data privacy officer (GDPR, PCI-DSS, HIPAA).
Analyze this ${lang} code for exposure. Strongly warn against insecure transmission, plain logging of secrets, or caching sensitive customer data (PII like CVV, credit cards, passwords, emails). Flag database caching of plain PII as a severe compliance violation.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete findings. Keep the response compact to reduce latency.

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

async function generateWithRetry(model, prompt, retries = 3, delay = 1500) {
  for (let i = 0; i < retries; i++) {
    try {
      return await model.generateContentStream(prompt);
    } catch (error) {
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

export async function POST(req) {
  const { code, language, agentType } = await req.json();

  if (!code || !agentType) {
    return new Response("Missing code or agentType", { status: 400 });
  }

  const prompt = PROMPTS[agentType]?.(code, language || "javascript");
  if (!prompt) return new Response("Invalid agentType", { status: 400 });

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
