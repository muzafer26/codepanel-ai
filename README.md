# CodePanel AI

AI-powered cybersecurity and code analysis platform with real-time multi-agent auditing, privacy-flow visualization, vulnerability detection, and developer telemetry.

---

## Overview

CodePanel AI is an interactive developer analysis console designed to simulate a modern AI-powered cybersecurity platform.

The system combines:

* Real-time AI code review
* Multi-agent security analysis
* AST-based structural inspection
* Privacy flow visualization
* Risk scoring
* Streaming telemetry dashboards
* Automated refactor generation

The platform analyzes pasted source code live and generates security, performance, privacy, and maintainability insights through specialized AI agents.

---

## Features

### Multi-Agent Analysis Engine

Specialized agents independently analyze code for:

* Security vulnerabilities
* Performance bottlenecks
* Privacy/GDPR risks
* Code quality issues

---

### Real-Time Streaming Analysis

Analysis responses stream live into the dashboard using Groq-powered LLM inference.

---

### Privacy Flow Visualization

Dynamic flow engine that:

* detects sensitive variables
* traces data movement
* identifies dangerous sinks
* visualizes exposure paths in real time

---

### AST Structural Analysis

Hybrid parsing pipeline using:

* AST traversal
* static rule detection
* lightweight heuristics
* AI reasoning synthesis

---

### Risk Scoring System

Generates:

* Security score
* Privacy score
* Maintainability score
* Deployment readiness score

---

### Refactored Code Generation

Automatically generates improved and safer versions of vulnerable code.

---

## Tech Stack

### Frontend

* Next.js
* React
* TailwindCSS

### Backend

* Next.js API Routes
* Groq API
* Multi-agent orchestration pipeline

### AI Models

* DeepSeek R1
* Llama 3.3
* Groq inference engine

---

## Installation

```bash
git clone https://github.com/muzafer26/codepanel-ai.git

cd codepanel-ai

npm install
```

---

## Environment Variables

Create a `.env.local` file:

```env
GROQ_API_KEY=your_api_key
GROQ_MODEL=deepseek-r1-distill-llama-70b
```

---

## Run Locally

```bash
npm run dev
```

Open:

```txt
http://localhost:3000
```

---

## Example Analysis Capabilities

The platform can detect:

* SQL Injection
* Hardcoded secrets
* Insecure HTTP requests
* Sensitive data exposure
* Plaintext password storage
* Dangerous eval usage
* ReDoS vulnerabilities
* Blocking synchronous operations
* PII leakage paths

---

## Architecture Pipeline

```txt
Code Input
   ↓
Static Analysis
   ↓
AST Traversal
   ↓
Specialist AI Agents
   ↓
Meta Synthesis Engine
   ↓
Risk Scoring
   ↓
Telemetry Visualization
   ↓
Refactored Output
```

---

## Project Status

Current Focus:

* Hybrid analysis pipeline
* Advanced privacy-flow engine
* Repository-level intelligence
* Dependency vulnerability scanning
* Agent conflict resolution
* Execution telemetry improvements

---

## Disclaimer

CodePanel AI is an experimental AI-assisted analysis platform intended for educational, research, and developer tooling purposes.

AI-generated findings and refactored code should always be manually reviewed before production use.

---

## Author

Muzafer Shaikh
