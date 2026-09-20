# AGENTZERO

> **Runtime security for autonomous AI agents.**

AGENTZERO is a runtime security layer that sits between an autonomous AI agent and consequential tool execution.

The agent proposes an action. AGENTZERO independently evaluates the action using runtime facts, semantic analysis, risk scoring, and explicit security policies before allowing it to execute.

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
Why AGENTZERO?

AI agents can now do more than generate text. They can:

Read and modify files
Call APIs
Send emails and messages
Upload data
Access external services
Change permissions
Perform other consequential operations

The security problem is that an agent can make a reasonable internal decision while still proposing an action that is unsafe, unauthorized, or inconsistent with the user's actual request.

AGENTZERO adds an independent security boundary before execution.

Core Principle

The AI agent can propose an action. It should not be the final authority over whether that action executes.

AGENTZERO separates five responsibilities:

Component	Responsibility
AI Agent	Proposes what it wants to do
Semantic Analyzer	Interprets intent and security-relevant context
Runtime Layer	Provides concrete facts about the environment
Risk Engine	Calculates risk from multiple signals
Policy Engine	Decides ALLOW, REVIEW, or BLOCK

This separation helps reduce false positives and prevents an AI model's interpretation from becoming the final authorization decision.

Security Model

AGENTZERO evaluates consequential actions across multiple dimensions.

Sensitive Information

Detects and evaluates information such as:

PII
Identity data
Financial data
Credentials
API keys
Secrets
Health information
Other sensitive classifications

A high sensitive-information score describes the data involved. It does not, by itself, mean the action is malicious.

Intent Deviation

Compares the user's actual request with the action the agent proposes.

Example:

User:
"Summarize my PDF."

Agent:
upload_file → external.example

The upload is not part of the requested goal, so intent deviation can be high.

But:

User:
"Check my PDFs and send them to PDF.com."

Agent:
upload_file → PDF.com

is aligned with the user's request, so intent deviation should remain low.

Prompt Injection

Looks for untrusted instructions attempting to manipulate the agent, such as:

Override attempts
Goal-change instructions
Requests for secrets
Attempts to bypass policies
Instructions originating from documents or external content
Destination Risk

Evaluates whether information is moving to:

Internal destinations
Trusted external destinations
Approved services
Unknown or unapproved destinations
Trust Boundary

Tracks movement of data across trust boundaries, such as an internal runtime sending information to an external service.

Action Impact

Represents the consequence of the proposed operation.

Examples of potentially higher-impact actions include:

Uploading data
Sending external messages
Deleting data
Changing permissions
Financial or infrastructure operations

High impact is a property of an action, not an automatic verdict that the action is malicious.

Privilege Risk

Evaluates whether the action requires elevated authority.

Source / Provenance

Tracks where the information came from and how trustworthy that source is.

Uncertainty

Represents missing or incomplete runtime information instead of silently assuming unknown values are safe.

Risk Engine

AGENTZERO combines the security dimensions into a structured 0–100 risk score.

The current model includes:

Sensitive Information
Destination Risk
Action Impact
Intent Deviation
Source Risk
Prompt Injection
Privilege Risk
Trust Boundary
Uncertainty

The engine also supports interaction bonuses.

For example:

Sensitive Data
      +
Risky External Destination
      ↓
Additional Risk

or:

Prompt Injection
      +
Goal Deviation
      ↓
Additional Risk

or:

High Privilege
      +
High Impact Action
      ↓
Additional Risk

The exact weights and thresholds can be configured in the AGENTZERO runtime.

Policy Engine

Risk scores do not directly replace security policy.

The policy engine evaluates the observed security facts and risk level and produces one of:

ALLOW
REVIEW
BLOCK

Examples:

Sensitive data
+
Unapproved external destination
+
External transfer
        ↓
BLOCK
High-impact action
+
High action risk
        ↓
REVIEW
Low-risk action
+
No matching security policy
        ↓
ALLOW

Hard security policies can override score-only thresholds.

Human Approval

When AGENTZERO decides that an action requires review, execution is paused.

Agent proposes action
        ↓
AGENTZERO evaluates
        ↓
REVIEW
        ↓
Execution PAUSED
        ↓
Human sees evidence + risk + policy
        ↓
APPROVE / DENY
        ↓
Tool execution or cancellation

The UI exposes the exact reasons for review rather than showing only a generic warning.

Explainable Security Events

Every evaluated action produces an auditable event.

Instead of:

BLOCKED — risk 84

AGENTZERO provides a structured explanation:

Decision: BLOCK

Sensitive Information: 88 / 100
Destination Risk:       80 / 100
Action Impact:           85 / 100
Intent Deviation:        5 / 100
Prompt Injection:        0 / 100
Trust Boundary:         95 / 100

The event also records:

Event ID
Timestamp
Agent
Session
Task
Proposed action
Runtime features
Matched policies
Risk breakdown
Explanation
Analyzer source
Relevant evidence

This makes false positives easier to investigate and security decisions easier to audit.

Architecture

The real AGENTZERO product is the Python runtime security engine.

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
Product vs Demo Console

The Python runtime is the core product.

The HTML/JavaScript application is a demonstration and control console built around the runtime.

The console provides:

Security dashboard
Live Agent view
Risk visualization
Event/audit history
Attack Lab
File inspection
Policy configuration
Risk-weight configuration
Provider configuration
Model selection
Human approval UI

The browser interface is therefore not the security boundary. The Python runtime performs the actual evaluation and enforcement.

Agent and AGENTZERO Models

AGENTZERO supports independent models for:

The AI agent
The AGENTZERO semantic analyzer

For example:

Agent:
Gemini

AGENTZERO Analyzer:
Claude

or:

Agent:
OpenAI

AGENTZERO Analyzer:
Gemini

This keeps the security layer independent from the model proposing the action.

Provider model discovery can be performed through the backend rather than relying only on a hardcoded frontend list.

Supported provider integrations currently include:

OpenAI
Anthropic
Google Gemini
Groq
Files and Artifacts

AGENTZERO is designed to preserve original artifacts as security evidence whenever possible.

For documents and images, the system can work with:

Original Artifact
      +
Metadata
      +
Classification
      +
Provenance
      +
Security Analysis

The goal is to avoid relying only on extracted text when the original document or image contains security-relevant information.

Attack Lab

The demonstration console includes several security scenarios.

Malicious PDF

An untrusted document attempts to redirect the agent toward a malicious external action.

Data Exfiltration

Sensitive information is sent toward an unknown external destination.

Malicious Webpage

External content attempts to manipulate the agent's instructions.

Goal Deviation

The agent attempts an unrelated or privileged operation.

Benign Workflow

A legitimate action demonstrates that the system can allow normal behavior.

The Attack Lab is designed to demonstrate both:

Attack prevention
False-positive resistance
Example: Intent vs Risk

Consider:

User:
"Check my PDFs and send them to PDF.com."

The agent proposes:

upload_file(
  file="research.pdf",
  destination="PDF.com"
)

AGENTZERO might observe:

Sensitive Information    88
Destination Risk         80
Action Impact            85
Intent Deviation          5
Prompt Injection          0
Trust Boundary           95

This is an important distinction:

Intent Deviation = LOW

because the upload was explicitly requested.

The action can still require REVIEW or BLOCK because other security factors may create a policy violation.

That means AGENTZERO is not confusing:

"The agent misunderstood the user"

with:

"The requested action creates a security risk."

API

The Python runtime exposes an HTTP API for integrating with an agent or demonstration console.

Key routes include:

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

The exact available routes may evolve with the current runtime build.

Project Structure

A typical AGENTZERO package looks like:

agentzero/
├── agentzero_backend.py
├── agentzero_frontend/
│   └── index.html
├── agentzero.db
└── README.md

The database is local and used for event persistence when enabled.

The frontend can also maintain client-side demonstration state such as chat history and uploaded-file metadata.

Running AGENTZERO
Requirements

For the current local/demo build:

Python 3
A modern browser
No Python third-party packages are required for the default local runtime
Start the runtime
python3 agentzero_backend.py

By default, the server runs on:

http://127.0.0.1:8000

Open that address in your browser to access the demonstration console.

Configuration

Optional environment variables include:

AGENTZERO_HOST=127.0.0.1
AGENTZERO_PORT=8000

AGENTZERO_DB=agentzero.db

AGENTZERO_API_KEY=

LLM_ANALYZER=auto
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=
LLM_MODEL=llama3.1:8b

Provider API keys can also be supplied through the application configuration for the current session.

Do not commit real API keys to source control.

Demo Flow

A useful demo sequence is:

1. Open Live Agent
2. Give the agent a legitimate task
3. Show the proposed tool call
4. Show AGENTZERO evaluating it
5. Open the risk breakdown
6. Run an Attack Lab scenario
7. Show BLOCK or REVIEW
8. Open the event explanation
9. Demonstrate human approval
10. Show the resulting audit event

The most important concept to demonstrate is the boundary:

AI Agent
   ↓
AGENTZERO
   ↓
Security Decision
   ↓
Execution
Security Design Principles

AGENTZERO follows these principles:

Independence

The security layer should remain independent from the model proposing an action.

Runtime Awareness

Security decisions should use actual execution context and runtime facts whenever possible.

Deterministic Enforcement

The final authorization decision should be derived from explicit security logic and policies rather than simply trusting an AI model's judgment.

Explainability

Every event should answer:

What happened?
Why was it detected?
What evidence supports it?
How did each category contribute?
Which policy matched?
Why was it allowed, reviewed, or blocked?
Least Authority

Agents should not receive more capability than required for the task.

Human Control

Consequential actions can be paused for explicit human approval.

Current Status

AGENTZERO is currently a functional prototype demonstrating a runtime security architecture for autonomous AI agents.

The prototype focuses on:

Runtime action evaluation
Explainable risk
Policy enforcement
Human approval
Prompt-injection defense
Sensitive-data awareness
Destination and trust-boundary analysis
Attack scenarios
Independent agent/security models
Auditable event history

The current tool implementations include simulated side effects for safe demonstration purposes.

Roadmap

Future directions include:

Native integrations with major agent frameworks
Real DLP and data-classification engines
Stronger runtime permission verification
Destination reputation and trust intelligence
Sandboxed tool execution
Organization-wide policy management
Persistent approval workflows
Multi-agent monitoring
Advanced behavioral anomaly detection
Enterprise audit and compliance capabilities
Production-grade deployment and observability

The long-term vision is for AGENTZERO to become a security control plane for autonomous AI systems.

Vision

As AI agents gain access to increasingly powerful systems, the question is no longer only:

"Can the agent complete the task?"

It becomes:

"Can the agent complete the task while staying inside an enforceable security boundary?"

AGENTZERO is designed to provide that boundary.

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
