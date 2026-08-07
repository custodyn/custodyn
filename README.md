<div align="center">

# Custodyn.

**Every AI agent action should be authorized before execution.**

Intercept high-impact agent actions, evaluate them against policy, and keep a tamper-evident record of the decision.

[![License: MIT](https://img.shields.io/badge/SDK_License-MIT-orange.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/custodyn.svg)](https://pypi.org/project/custodyn)
[![PyPI downloads](https://img.shields.io/pypi/dm/custodyn)](https://pypi.org/project/custodyn/)
[![npm](https://img.shields.io/npm/v/custodyn.svg)](https://npmjs.com/package/custodyn)
[![npm downloads](https://img.shields.io/npm/dw/custodyn)](https://www.npmjs.com/package/custodyn)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![Node 16+](https://img.shields.io/badge/node-16+-green.svg)](https://nodejs.org)
[![GitHub stars](https://img.shields.io/github/stars/custodyn/custodyn?style=social)](https://github.com/custodyn/custodyn/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/custodyn/custodyn)](https://github.com/custodyn/custodyn/issues)
[![Status](https://img.shields.io/badge/status-live-brightgreen.svg)](https://custodyn.app)

[Website](https://custodyn.app) · [Documentation](https://custodyn.app/docs.html) · [Security](https://custodyn.app/security.html) · [**Sign up free →**](https://custodyn.app/signup.html)

</div>

---

## What is Custodyn?

Custodyn is a policy enforcement layer for AI agents. Integrate the SDK or gateway before an agent reaches an external system, then evaluate each action against the controls your team defines.

Custodyn can allow an action, block it, or route it to a human approval queue. It records the resulting decision so teams can investigate behavior, demonstrate control coverage, and respond quickly when an agent needs to be paused.

> Custodyn is designed to be used in the execution path. The protection it provides depends on integrating the SDK or gateway with the actions you intend to govern.

Custodyn works as an SDK you integrate directly, or as a gateway proxy your agent's traffic passes through — no code changes required for the proxy path.

## Quick start

Create an account and register an agent at [custodyn.app](https://custodyn.app), then use its agent ID and API key in your application.

### Python

```bash
pip install custodyn
```

```python
from custodyn import Custodyn

custodyn = Custodyn(
    agent_id="agt_...",
    api_key="as_live_...",
    server_url="https://custodyn.app",
)

result = custodyn.check("send_email", "send", "smtp.gmail.com")

if result["allowed"]:
    send_email(...)
else:
    print(result["reason"])
```

### JavaScript / Node.js

```bash
npm install custodyn
```

```javascript
const { Custodyn } = require('custodyn');

const custodyn = new Custodyn({
  agentId: 'agt_...',
  apiKey: 'as_live_...',
  serverUrl: 'https://custodyn.app',
});

const result = await custodyn.check('delete_file', 'delete', '/prod/data');

if (result.allowed) {
  await deleteFile('/prod/data');
} else {
  console.log(result.reason);
}
```
### No-code / Gateway
Zero code? No problem.
Use the Custodyn Reverse Proxy — change one URL, add one header. Works with n8n, Make.com, Zapier, and any tool that makes HTTP calls. No SDK, no code changes.
```
# Before
https://api.stripe.com/v1/charges

# After (with Custodyn)
https://custodyn.app/proxy/https://api.stripe.com/v1/charges

# Required headers
X-API-Key: as_live_...
X-Custodyn-Agent-Id: agt_...
```
All requests are evaluated against your policy before being forwarded. Useful for n8n, Make, Zapier, or any HTTP tool where you can't install a package.
> See [gateway setup →](https://custodyn.app/docs.html) or login to custodyn and open integrations page for complete setup.

### OpenClaw

```python
from custodyn import CustodynPlugin
from openclaw import Agent

agent = Agent(plugins=[CustodynPlugin(
    api_key="as_live_...",
    agent_id="agt_...",
)])
```

## How it works

```text
Agent requests an action
        │
        ▼
Custodyn SDK or gateway intercepts it
        │
        ▼
Policy evaluation
  • agent status and permissions
  • policy rules and conditions
  • velocity limits
  • approval memory
        │
        ▼
allow  ·  block  ·  require approval
        │
        ▼
Decision and action record are available in Custodyn Cloud
```

Use `failClosed: true` (the SDK default) when an unavailable policy service should prevent the action from proceeding.

## Platform capabilities

- **Runtime enforcement** — SDK, gateway, API proxy, and browser-event integrations.
- **Policy controls** — block, allow, or require approval by agent, category, target, and condition.
- **Human approvals** — review high-impact actions, including optional two-person approval and expiry rules.
- **Audit evidence** — tamper-evident action records with policy context and integrity hashes.
- **Agent operations** — trust scoring, policy coverage, kill switch, and team role controls.

## SDK vs Custodyn Cloud

The SDK works standalone for local testing and development. For production use, connect to Custodyn Cloud to unlock the full control plane.

| Capability | SDK alone | With Custodyn Cloud |
|---|---|---|
| Policy checks | ✓ Local presets only | ✓ Custom org policies |
| Audit log | In-memory, lost on exit | Permanent, tamper-evident |
| Human approvals | Always times out → denied | Full approval queue + Slack/Teams |
| Multi-agent visibility | ✗ | ✓ Dashboard |
| Kill switch | ✗ | ✓ One click |
| SOC2 export | ✗ | ✓ |
| Fail-closed config | Local default only | Synced from dashboard |

[Sign up free →](https://custodyn.app/signup.html)

## Supported integrations

| Integration | Python | JavaScript |
|---|:---:|:---:|
| OpenClaw | ✓ | ✓ |
| CrewAI, AutoGen, LangChain, LangGraph | ✓ | — |
| Anthropic / Claude and OpenAI Agents SDK | ✓ | — |
| MCP servers and clients | ✓ | — |
| Codex CLI / shell | ✓ | — |
| GitHub Copilot / VS Code extensions | — | ✓ |
| HTTP clients, n8n, Make, and Zapier | ✓ | ✓ |

See the [documentation](https://custodyn.app/docs.html) for integration guides and configuration details.

## Why runtime controls matter

AI agents increasingly act on live systems rather than only generating text. Recent reporting on an OpenAI testing incident and Anthropic research on agentic misalignment illustrate why teams need action-time controls, not only model-time guardrails. [Reuters coverage](https://www.investing.com/news/world-news/openai-says-ai-models-went-rogue-during-testing-triggering-unprecedented-breach-at-startup-4804634) · [Anthropic research](https://alignment.anthropic.com/2026/agentic-misalignment-summer-2026/)

## Security and operations

Custodyn Cloud provides policy enforcement, account-scoped access controls, and tamper-evident audit records. For the current security overview and responsible disclosure contact, see [custodyn.app/security.html](https://custodyn.app/security.html).

For production use, keep API keys out of source control, scope agent permissions to the minimum required, and test policies before applying them to critical workflows.

## Open-source scope

The Custodyn SDKs are MIT-licensed and available through npm and PyPI.

| Component | Availability |
|---|---|
| Python and JavaScript SDKs | MIT licensed |
| Type definitions and SDK documentation | Public |
| Custodyn Cloud control plane, dashboard, policy storage, billing, and managed operations | Proprietary service |

## Repository contents

For the public SDK repository, the primary implementation files are:

- `custodyn.py` — Python SDK
- `sdk/custodyn.js` — JavaScript SDK
- `sdk/custodyn.d.ts` — TypeScript definitions
- `package.json` and `setup.py` — package metadata

The hosted platform is available at [custodyn.app](https://custodyn.app).

## Support

- Product and integration documentation: [custodyn.app/docs.html](https://custodyn.app/docs.html)
- Security overview: [custodyn.app/security.html](https://custodyn.app/security.html)
- Contact: [hello@custodyn.app](mailto:hello@custodyn.app)

## License

The Custodyn SDK is released under the [MIT License](LICENSE). Custodyn Cloud is a proprietary managed service.
