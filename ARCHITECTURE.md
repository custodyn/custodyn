# Custodyn — Architecture

## Overview

Custodyn is a **policy enforcement layer** that intercepts AI agent actions before they execute. It operates as a thin, fast middleware — not a framework replacement.

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Agent Runtime                               │
│  (OpenClaw / CrewAI / LangGraph / AutoGen / Claude / Custom)        │
└────────────────────────────┬────────────────────────────────────────┘
                             │ tool call / API request / browser event
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Custodyn Interception Layer                      │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────┐ │
│  │  SDK Mode    │  │  MCP Gateway │  │  API Proxy   │  │ Browser │ │
│  │ (custodyn.py │  │ before_tool_ │  │ /proxy/https │  │ Gateway │ │
│  │  custodyn.js)│  │  call hook   │  │ ://target... │  │  (CDP)  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └────┬────┘ │
│         └─────────────────┴─────────────────┴───────────────┘      │
│                                    │                                 │
│                                    ▼                                 │
│                        ┌───────────────────┐                        │
│                        │   Policy Engine   │                        │
│                        │                   │                        │
│                        │ 1. Agent status   │                        │
│                        │ 2. Tool perms     │                        │
│                        │ 3. Velocity limits│                        │
│                        │ 4. Policy rules   │                        │
│                        │ 5. Approval memory│                        │
│                        └─────────┬─────────┘                        │
│                                  │                                   │
│               ┌──────────────────┼──────────────────┐               │
│               ▼                  ▼                   ▼               │
│           allow              require_approval      block             │
│               │                  │                   │               │
└───────────────┼──────────────────┼───────────────────┼───────────────┘
                │                  │                   │
                ▼                  ▼                   ▼
         Tool executes     Human approval        Action blocked
                           queue (dashboard,     Error returned
                           Slack, Teams)         to agent
```

---

## Integration modes

Custodyn supports four ways to intercept agent actions:

**SDK mode** — Install the SDK and call `custodyn.check()` before any tool execution. Works with any Python or Node.js agent. Supports OpenClaw, CrewAI, AutoGen, LangChain, LangGraph, and more via native integrations.

**MCP gateway** — Hook into MCP protocol tool calls before they reach the tool server. Works with any MCP-compatible agent or client (Cursor, Claude Desktop, etc.).

**API proxy** — Route your agent's outbound HTTP requests through `custodyn.app/proxy/`. No SDK required — just prefix the URL and add two headers.

**Browser gateway** — Hook into browser agent sessions via Chrome DevTools Protocol. Intercepts clicks, form fills, and navigation before they execute.

---

## Data flow — SDK path

```
1. Agent calls custodyn.check("send_email", "send", "smtp.gmail.com")
2. SDK sends action details to Custodyn gateway
3. Policy engine evaluates against active rules
4. Decision returned: allow / block / require_approval

If "allow":
  → Tool executes, action logged with integrity hash

If "block":
  → Exception raised, tool does not execute, action logged

If "require_approval":
  → Action queued for human review
  → SDK polls for decision every 2 seconds
  → Human approves or denies in dashboard / Slack / Teams
  → Tool executes or is abandoned based on decision
```

---

## Data flow — API proxy path

```
Agent calls: https://custodyn.app/proxy/https://api.stripe.com/v1/charges

1. SSRF protection — private IPs, localhost, cloud metadata endpoints blocked
2. Policy engine evaluates method + target URL
3. If blocked: 403 returned to agent
4. If approved: request forwarded to real endpoint, response returned
5. Action logged in both cases
```

---

## Policy engine

Every action is evaluated against a set of rules before it executes. Rules can:

- **Allow** — explicitly permit an action
- **Block** — permanently prevent an action
- **Require approval** — pause and wait for a human decision
- **Rate limit** — cap how often an action can run

Rules support compound conditions:
- `parameter.amount gt "1000"` — only trigger for large amounts
- `target contains "production"` — only for production targets
- `risk_level eq "critical"` — only for critical-risk actions

Rules can be scoped to a specific agent or applied globally across all agents.

---

## Audit trail

Every action is sealed with a SHA-256 integrity hash at write time. The hash covers the action, agent, target, outcome, timestamp, and company. Any modification to a logged record breaks the hash — making the audit trail tamper-evident.

Actions are immutable after creation. Exports include integrity hashes for compliance evidence packages.

---

## Multi-tenancy

All data is strictly isolated per account. Every database query is scoped to the authenticated company. Cross-account data access is not possible by design.

---

## SDKs

The SDK is the only public component of Custodyn. Both SDKs are MIT licensed and available on npm and PyPI.

**`custodyn` (PyPI)** — Python SDK with native integrations for OpenClaw, CrewAI, AutoGen, LangChain, LangGraph, Anthropic, OpenAI Agents SDK, Claude Code, MCP servers, and Codex CLI.

**`custodyn` (npm)** — JavaScript/TypeScript SDK with OpenClaw plugin and a standalone `custodynCheck()` function for GitHub Copilot and VS Code extensions.

The platform backend (policy engine, dashboard, audit storage, billing) is proprietary and not included in the SDK.

---

## Deployment

Custodyn is a managed SaaS product available at [custodyn.app](https://custodyn.app).

The SDK (`custodyn.py` / `custodyn.js`) is open-source and can be used independently to build your own gateway. See the [README](README.md) for quick start instructions.
