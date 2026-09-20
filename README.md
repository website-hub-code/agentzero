# AGENTZERO

> **Let agents act. Keep execution under control.**

AGENTZERO is a runtime security layer for autonomous AI agents.

Instead of allowing an AI agent to directly execute consequential tool calls, AGENTZERO sits between the agent and execution:

```text
USER
  ↓
AI AGENT
  ↓
PROPOSED TOOL CALL
  ↓
AGENTZERO
  ├── Semantic Analysis
  ├── Runtime Fact Verification
  ├── Risk Engine
  └── Policy Engine
  ↓
ALLOW / REVIEW / BLOCK
  ↓
TOOL EXECUTION

The Python runtime is the actual AGENTZERO security engine.

The HTML application in demo/index.html is the demonstration and control console used to visualize and test the runtime.

Why AGENTZERO?

Modern AI agents are increasingly capable of taking real actions:

Reading and modifying files
Calling APIs
Sending messages and email
Uploading data
Accessing external services
Changing permissions
Performing other consequential operations

That creates a new security boundary.

An agent can make a reasonable decision according to its own reasoning while still proposing an action that is unsafe, unauthorized, or inconsistent with the user's actual goal.

AGENTZERO provides an independent runtime security layer before the action reaches execution.

Core Principle

The AI agent can propose an action. It should not be the final authority over whether that action executes.

AGENTZERO separates the responsibilities of the system:

Component	Responsibility
AI Agent	Proposes what it wants to do
Semantic Analyzer	Interprets intent and security-relevant context
Runtime Layer	Provides concrete runtime evidence
Risk Engine	Calculates structured risk
Policy Engine	Decides ALLOW, REVIEW, or BLOCK

This separation is important because an AI-generated security judgment should not automatically become the final authorization decision.

Security Signals

AGENTZERO evaluates consequential actions across multiple dimensions.

Sensitive Information

Evaluates whether the action involves:

PII
Identity information
Financial information
Credentials
API keys
Secrets
Health information
Other classified sensitive data

A high sensitive-information score describes the data involved. It does not automatically mean the action is malicious.

Intent Deviation

Compares the user's actual request with the action the agent proposes.

Example:

User:
"Summarize my PDF."

Agent:
upload_file → external.example

The upload was not requested, so intent deviation can be high.

But:

User:
"Check my PDFs and send them to PDF.com."

Agent:
upload_file → PDF.com

is aligned with the user's request.

This distinction prevents external transfers from being incorrectly labeled as intent deviation simply because they cross a network boundary.

Prompt Injection

Detects signals indicating that untrusted content is attempting to manipulate the agent, such as:

Attempts to override instructions
Attempts to change the agent's goal
Requests for secrets
Attempts to bypass security controls
Instructions embedded in untrusted documents or external content
Destination Risk

Evaluates where information is going:

Internal destinations
Trusted external destinations
Approved services
Unknown or unapproved destinations
Trust Boundary

Tracks movement of data across trust boundaries, such as sending internal information to an external service.

Action Impact

Represents how consequential the proposed operation is.

Examples include:

File uploads
External messages
Data deletion
Permission changes
Financial or infrastructure operations

High impact is a property of an action, not automatically proof that the action is malicious.

Privilege Risk

Evaluates whether an action requires elevated authority.

Source / Provenance

Tracks where information came from and how trustworthy that source is.

Uncertainty

Represents missing or incomplete runtime information instead of silently treating unknown information as safe.

Risk Engine

AGENTZERO combines multiple signals into a structured 0–100 risk score.

Example:

Sensitive Information     88
Destination Risk           80
Action Impact              85
Intent Deviation            5
Source Risk                25
Prompt Injection            0
Privilege Risk               0
Trust Boundary             95
Uncertainty                13

The risk engine also evaluates interactions between signals.

For example:

Sensitive Data
      +
Risky External Destination
      ↓
Additional Risk
Prompt Injection
      +
Goal Deviation
      ↓
Additional Risk
High Privilege
      +
High Impact Action
      ↓
Additional Risk

The final score is then evaluated against the active security policies.

Policy Engine

AGENTZERO converts security evidence and risk into one of three outcomes:

ALLOW
REVIEW
BLOCK

Example:

Sensitive information
+
Unapproved external destination
+
External transfer
        ↓
BLOCK

Example:

High-impact action
+
Elevated action risk
        ↓
REVIEW

Example:

Low-risk action
+
No matching policy
        ↓
ALLOW

Hard policy rules can override score-only thresholds.

Human Approval

When an action requires review, AGENTZERO pauses execution.

Agent proposes action
        ↓
AGENTZERO evaluates
        ↓
REVIEW
        ↓
Execution PAUSED
        ↓
Human sees:
  • action
  • risk
  • reasons
  • evidence
  • policy
        ↓
APPROVE / DENY

The action cannot continue until the approval step is completed.

Explainable Events

Every evaluated action produces an auditable security event.

Instead of only:

BLOCKED — Risk 84

AGENTZERO can show:

Decision
BLOCK

Sensitive Information
88 / 100

Destination Risk
80 / 100

Action Impact
85 / 100

Intent Deviation
5 / 100

Prompt Injection
0 / 100

Trust Boundary
95 / 100

Events can also contain:

Event ID
Timestamp
Agent
Session
Task
Proposed action
Runtime features
Risk breakdown
Matched policies
Explanation
Evidence
Analyzer source

This makes decisions easier to understand, debug, and audit.

Architecture

The real AGENTZERO product is the Python runtime.

                    AGENTZERO
                         │
                         ▼
                 Proposed Tool Call
                         │
                         ▼
              ┌───────────────────┐
              │ Semantic Analysis │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ Runtime Evidence  │
              │                   │
              │ Files             │
              │ Provenance        │
              │ Permissions       │
              │ Destination       │
              │ Data Metadata     │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │    Risk Engine    │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │   Policy Engine   │
              └─────────┬─────────┘
                        │
             ┌──────────┼──────────┐
             ▼          ▼          ▼
           ALLOW      REVIEW      BLOCK
             │          │
             │          ▼
             │      HUMAN APPROVAL
             │
             ▼
        TOOL EXECUTION
Product vs Demo

The repository contains two distinct layers:

Real Product

The Python runtime implements the security engine, including:

Runtime evaluation
Risk calculation
Policy enforcement
Agent tool gating
Human approval flow
Security events
API endpoints
Demonstration Console

demo/index.html provides a browser-based demonstration of the runtime.

It is used for:

Visualizing security decisions
Running Attack Lab scenarios
Inspecting event explanations
Testing policies
Demonstrating human approval
Configuring providers and models
Exploring the AGENTZERO workflow

The demo is not the security boundary. The Python runtime is.

Project Structure

The repository is organized around the runtime and its demonstration interface.

agentzero/
├── agentzero_backend.py
├── demo/
│   └── index.html
└── README.md

If additional configuration or support files are present in the repository, keep them alongside the runtime when deploying the project.

Running AGENTZERO
Requirements

For the current local/demo build:

Python 3
A modern browser
No third-party Python packages are required for the default local runtime
Option 1 — Run the Real AGENTZERO Runtime

Clone the repository:

git clone https://github.com/website-hub-code/agentzero.git
cd agentzero

Start the Python runtime:

python3 agentzero_backend.py

The runtime starts its local HTTP server and exposes the AGENTZERO API.

By default, the development server uses:

http://127.0.0.1:8000

Open the server URL in your browser.

If the repository version you're using prints a different host or port at startup, use the URL shown in the terminal.

Option 2 — Open the Demo Directly

The repository contains a browser demo at:

demo/index.html

You can open it directly in a browser for the visual demonstration.

From the repository root:

cd demo

Then open index.html in Chrome or another modern browser.

On Linux, for example:

xdg-open index.html

On macOS:

open index.html

On Windows:

start index.html

The direct demo is useful for visual exploration, while the Python runtime is the actual AGENTZERO security engine.

Running the Demo Through the Python Runtime

For the most complete demonstration, run the Python backend first:

python3 agentzero_backend.py

Then open the runtime URL printed by the server.

This lets the demonstration interface communicate with the actual AGENTZERO runtime instead of behaving as a standalone visual mockup.

Demo Workflow

A useful demonstration sequence is:

1. Start agentzero_backend.py
2. Open the AGENTZERO interface
3. Open Live Agent
4. Submit a task
5. Watch the agent propose a tool call
6. Let AGENTZERO evaluate it
7. Inspect the risk breakdown
8. Open Attack Lab
9. Run a security scenario
10. Inspect the explanation
11. Trigger a REVIEW scenario
12. Approve or deny the action
13. Open the event history

The most important concept to demonstrate is:

AI Agent
   ↓
AGENTZERO
   ↓
Security Decision
   ↓
Execution
Attack Lab

The demo includes scenarios such as:

Malicious PDF

A document contains instructions attempting to manipulate the agent.

Expected behavior:

Prompt Injection
HIGH

Intent Deviation
HIGH

→ BLOCK
Data Exfiltration

Sensitive information is sent toward an unknown external endpoint.

Expected behavior:

Sensitive Information
HIGH

Destination Risk
HIGH

Trust Boundary
HIGH

→ BLOCK
Malicious Webpage

An external page attempts to influence the agent's instructions.

Goal Deviation

The agent attempts an unrelated privileged operation.

Benign Workflow

A legitimate action demonstrates that normal behavior can be allowed.

Example: PII + External Upload

Consider:

User:
"Check my PDFs and send them to PDF.com."

The agent proposes:

upload_file(
  file="research.pdf",
  destination="PDF.com"
)

Suppose the PDF contains PII.

AGENTZERO can distinguish:

Sensitive Information
HIGH

from:

Intent Deviation
LOW

because the user explicitly requested the upload.

The action can still require REVIEW or BLOCK because of the sensitive information and destination risk.

This is intentional:

Intent Deviation
=
Did the agent follow the user's requested goal?

Security Risk
=
Is executing the requested action acceptable under policy?

Those are different questions.

Agent and AGENTZERO Models

AGENTZERO can use separate models for:

AI Agent

and:

AGENTZERO Analyzer

For example:

Agent Model:
Gemini

AGENTZERO Analyzer:
Claude

This keeps the security evaluation layer independent from the model that originally proposed the action.

The runtime supports provider-aware model discovery for supported providers.

File and Artifact Security

AGENTZERO can retain the original document or image as security evidence alongside:

Original artifact
+
Metadata
+
Classification
+
Provenance
+
Security analysis

This is useful when extracted text alone would lose important information about the original artifact.

API

The runtime exposes an HTTP API for integrations and the demo console.

Important endpoints include:

GET  /api/health
GET  /api/stats
GET  /api/policies
GET  /api/events
GET  /api/events/<event_id>

POST /api/evaluate
POST /api/analyze
POST /api/decision

POST /api/agent/run
POST /api/agent/approve

POST /api/provider/models

POST /api/attacks/run

The exact API surface may evolve as the runtime develops.

Configuration

The runtime supports optional environment configuration.

Typical settings include:

AGENTZERO_HOST=127.0.0.1
AGENTZERO_PORT=8000
AGENTZERO_DB=agentzero.db

AGENTZERO_API_KEY=

LLM_ANALYZER=auto
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=
LLM_MODEL=llama3.1:8b

Provider credentials may also be configured through the application.

Do not commit API keys or other secrets to the repository.

Development Philosophy

AGENTZERO is built around several principles.

Independent security boundary

The agent proposes actions; AGENTZERO enforces them.

Runtime-aware decisions

The engine should use what is actually true at execution time rather than blindly trusting model-generated claims.

Deterministic enforcement

The final authorization decision should come from explicit risk and policy logic.

Explainability

Every security event should answer:

What happened?
Why was it detected?
What evidence supports it?
How much did each factor contribute?
Which policy matched?
Why was the action allowed, reviewed, or blocked?
Least authority

Agents should have only the capabilities required for the task.

Human control

Consequential actions can be paused for human approval.

Current Status

AGENTZERO is a functional prototype of a runtime security architecture for autonomous AI agents.

The current prototype demonstrates:

Runtime tool-call evaluation
Intent verification
Sensitive-data awareness
Prompt-injection detection
Destination risk
Trust-boundary analysis
Structured risk scoring
Policy enforcement
ALLOW / REVIEW / BLOCK decisions
Human approval
Explainable security events
Attack Lab scenarios
Independent agent and analyzer models
Event history and auditing

Some tool side effects in the demonstration environment are intentionally simulated for safe testing.

Roadmap

Future work includes:

Native integrations with major agent frameworks
Real DLP and data-classification engines
Stronger runtime permission verification
Destination reputation and trust intelligence
Sandboxed tool execution
Organization-wide policy management
Persistent approval workflows
Multi-agent monitoring
Behavioral anomaly detection
Enterprise audit and compliance support
Production deployment and observability
Vision

As AI agents gain access to more powerful systems, the important question is no longer only:

Can the agent complete the task?

It is also:

Can the agent complete the task while staying inside an enforceable security boundary?

AGENTZERO is built to provide that boundary.

AI autonomy
     ↓
AGENTZERO
     ↓
Observable
Explainable
Policy-controlled
Enforceable
     ↓
Real-world execution

AGENTZERO — Let agents act. Keep execution under control.

Repository

GitHub:
https://github.com/website-hub-code/agentzero
```
