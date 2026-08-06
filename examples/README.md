# Custodyn SDK — Real-World Integration Examples

These examples show how to add Custodyn to any Python AI agent in minutes.
Each demo does something genuinely dangerous — and shows exactly how Custodyn
intercepts it before it causes harm.

## Install

```bash
pip install custodyn
```

## The Pattern

Every integration is the same 3 steps:

```python
from custodyn import Custodyn, PRESETS

# 1. Initialize
agent = Custodyn(
    agent_id="your-agent-id",
    api_key="as_live_your_key_here",
    server_url="https://custodyn.app",
    policies=PRESETS["balanced"],
    fail_closed=True  # block if dashboard is unreachable
)

# 2. Check before any dangerous action
result = agent.check(
    action="send_payment",
    category="pay",        # pay | delete | execute | write | read | send | auth
    target="vendor@acme.com",
    parameters={"amount": 12000}
)

# 3. Respect the decision
if not result["allowed"]:
    print(f"Blocked: {result['reason']}")
    return

# safe to proceed
execute_payment(...)
```

---

## Risk Levels (automatic by category)

| Category | Risk | Default behaviour |
|---|---|---|
| `read` | low | Always allowed |
| `write` | medium | Logged, allowed by policy |
| `execute` | medium | Logged, allowed by policy |
| `send` | high | Requires approval |
| `auth` | high | Requires approval |
| `delete` | high | Requires approval |
| `pay` | critical | Always requires approval |

---

## Policy Presets

```python
from custodyn import PRESETS

PRESETS["strict"]      # block all writes, deletes, payments
PRESETS["balanced"]    # block payments + bulk deletes (recommended)
PRESETS["permissive"]  # log everything, block only payments
```

---

## Examples

### 1. Financial Agent (`01_financial_agent.py`)
Payments and transfers. All `pay` category actions require human approval.

### 2. File Manager Agent (`02_file_manager_agent.py`)
Moves, deletes files and folders. Mirrors the Summer Yue / OpenClaw inbox wipe incident.

### 3. Database Agent (`03_database_agent.py`)
Routes SQL by intent — SELECT runs free, DROP TABLE is always blocked.
Mirrors the Replit production database wipe incident.

### 4. Deployment Agent (`04_deployment_agent.py`)
Pushes code, deploys to production. PRs are free — production deploys are always blocked.

---

## Dashboard

All blocked actions appear at **https://custodyn.app/dashboard**

Approve or deny with one click. Every action — allowed, blocked, or approved —
is logged permanently with full audit trail.

---

## Other Integrations

```python
# LangChain
from custodyn import CustodynCallbackHandler
handler = CustodynCallbackHandler(api_key="as_live_...", agent_id="agt_...")
llm = ChatOpenAI(callbacks=[handler])

# LangGraph
from custodyn import custodyn_langgraph_node
gate = custodyn_langgraph_node(api_key="as_live_...", agent_id="agt_...")
graph.add_node("custodyn_gate", gate)

# AutoGen
from custodyn import CustodynInterventionHandler
runtime = SingleThreadedAgentRuntime(
    intervention_handlers=[CustodynInterventionHandler(api_key="...", agent_id="...")]
)

# MCP Server
from custodyn import CustodynMCPMiddleware
custodyn = CustodynMCPMiddleware(api_key="as_live_...", agent_id="agt_...")
@app.call_tool()
async def handle_tool(name, arguments):
    custodyn.check(name, arguments)  # raises PermissionError if blocked
    return your_tool_logic(name, arguments)

# Shell commands
from custodyn import custodyn_shell_check
custodyn_shell_check("rm -rf /backups", api_key="...", agent_id="...")
```

---

## Get Started

1. Sign up at https://custodyn.app
2. Create an agent in the dashboard
3. Copy your `agent_id` and `api_key`
4. `pip install custodyn` and add `agent.check()` before any dangerous action

One check. Full control.
