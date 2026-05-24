# CodePanel AI 🔐⚡◇

3-agent AI code review tool. Security + Performance + Code Quality agents review simultaneously, then a Meta-Reviewer gives the final verdict.

## Get Free API Key (60 seconds)
1. Go to https://aistudio.google.com
2. Click "Get API Key" → Create API Key
3. Copy the key

## Deploy to Vercel

### Step 1 — Push to GitHub
```bash
npm install
git init
git add .
git commit -m "CodePanel AI"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/codepanel-ai.git
git push -u origin main
```

### Step 2 — Deploy on Vercel
1. Go to vercel.com
2. New Project → Import from GitHub → select codepanel-ai
3. Under Environment Variables, add:
   - Name: `GEMINI_API_KEY`
   - Value: your key from aistudio.google.com
4. Click Deploy

Done. Live URL in 90 seconds.

## Local Dev
```bash
npm install
echo "GEMINI_API_KEY=your_key_here" > .env.local
npm run dev
```
Open http://localhost:3000
