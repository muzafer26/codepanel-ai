import { GoogleGenerativeAI } from "@google/generative-ai";

const PROMPTS = {
  security: (code, lang) => `You are an elite security code reviewer. Analyze this ${lang} code for vulnerabilities: SQL injection, XSS, hardcoded secrets, broken auth, OWASP Top 10.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete findings. Keep the response compact to reduce latency.

Use these prefixes:
[SCAN] when examining something
[WARN] when spotting a potential issue
[VULN] when confirming a vulnerability
[PASS] when something looks safe

End with VERDICT: listing all issues with severity (CRITICAL/HIGH/MED/LOW).

Code:
\`\`\`${lang}
${code}
\`\`\``,

  performance: (code, lang) => `You are a performance engineer. Analyze this ${lang} code for: N+1 queries, O(n²) loops, memory leaks, blocking I/O, unnecessary re-renders.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete findings. Keep the response compact to reduce latency.

Use these prefixes:
[PROFILE] when examining a section
[SLOW] when detecting a bottleneck
[LEAK] when detecting a memory/resource issue
[OK] when something is efficient

End with VERDICT: listing all performance issues with impact (SEVERE/MODERATE/MINOR).

Code:
\`\`\`${lang}
${code}
\`\`\``,

  style: (code, lang) => `You are a senior engineer obsessed with clean code. Analyze this ${lang} code for: naming issues, SOLID violations, dead code, missing error handling, magic numbers.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete findings. Keep the response compact to reduce latency.

Use these prefixes:
[READ] when reading a section
[SMELL] when detecting a code smell
[DEBT] when spotting tech debt
[GOOD] when something is well-written

End with VERDICT: listing all quality issues with impact (HIGH/MED/LOW).

Code:
\`\`\`${lang}
${code}
\`\`\``,

  compliance: (code, lang) => `You are an elite compliance and data privacy auditor (GDPR, HIPAA, PCI-DSS). Analyze this ${lang} code for privacy violations, logging of sensitive data (PII like email, passwords, cards, phone numbers), transmitting unencrypted data, insecure storage, or compliance infractions.

IMPORTANT: Keep your analysis and scan logs extremely brief (max 1-2 sentences per prefix). Focus only on concrete data flows. Keep the response compact to reduce latency.

Use these prefixes:
[PII] when spotting sensitive personal data handling
[LEAK] when detecting data leakage (e.g. logging or sending unencrypted PII)
[GDPR] for compliance and privacy violations
[SAFE] when personal info is handled securely

End with VERDICT: listing all compliance/privacy issues with severity (CRITICAL/HIGH/MED/LOW).

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
