"""
Custodyn Python SDK v1.1.0
AI Trust & Security Infrastructure

Install:
    pip install custodyn

Usage:
    from custodyn import Custodyn, PRESETS
"""

import hashlib
import json
import uuid
import time
from datetime import datetime, timezone
from typing import Callable, Optional
import asyncio

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─────────────────────────────────────────────
# RISK SCORING
# ─────────────────────────────────────────────

RISK_LEVELS = {
    "read":    "low",
    "write":   "medium",
    "execute": "medium",
    "auth":    "high",
    "send":    "high",
    "delete":  "high",
    "pay":     "critical",
}

SENSITIVE_TARGETS = [
    "stripe", "paypal", "bank", "payment",
    "production", "prod", "smtp", "twilio",
    "aws", "database", "db", "admin", "billing"
]

RISK_ORDER = ["low", "medium", "high", "critical"]


def score_risk(category: str, target: str, parameters: dict = {}) -> str:
    idx = RISK_ORDER.index(RISK_LEVELS.get(category, "medium"))
    if any(t in target.lower() for t in SENSITIVE_TARGETS):
        idx = min(idx + 1, 3)
    if parameters.get("bulk") or parameters.get("all") or parameters.get("count", 0) > 100:
        idx = 3
    return RISK_ORDER[idx]


# ─────────────────────────────────────────────
# POLICY ENGINE
# ─────────────────────────────────────────────

class PolicyEngine:
    def __init__(self, rules: list = []):
        self.rules = [r for r in rules if r.get("active", True)]

    def evaluate(self, category: str, target: str, parameters: dict = {}) -> dict:
        for rule in self.rules:
            if rule.get("category") != category:
                continue
            blocked = rule.get("blockedTargets") or rule.get("blocked_targets") or []
            allowed = rule.get("allowedTargets") or rule.get("allowed_targets") or []
            requires_approval = rule.get("requiresApproval") or rule.get("action") == "require_approval"
            if any(t in target for t in blocked):
                return {"verdict": "block", "rule": rule}
            if allowed and not any(t in target for t in allowed):
                return {"verdict": "block", "rule": rule}
            if requires_approval:
                return {"verdict": "require_approval", "rule": rule}
            if rule.get("action") == "block":
                return {"verdict": "block", "rule": rule}
        return {"verdict": "allow", "rule": None}


# ─────────────────────────────────────────────
# AUDIT LOGGER
# ─────────────────────────────────────────────

class AuditLogger:
    def __init__(self):
        self.sessions = {}

    def record(self, action: dict):
        sid = action["sessionId"]
        if sid not in self.sessions:
            self.sessions[sid] = []
        self.sessions[sid].append(action)

    def get_session(self, session_id: str) -> list:
        return self.sessions.get(session_id, [])

    def finalize(self, agent_id: str, session_id: str) -> dict:
        actions = self.sessions.get(session_id, [])
        log = {
            "logId": str(uuid.uuid4()),
            "agentId": agent_id,
            "sessionId": session_id,
            "actions": actions,
            "startedAt": actions[0]["timestamp"] if actions else datetime.now(timezone.utc).isoformat(),
            "endedAt": datetime.now(timezone.utc).isoformat(),
            "totalActions": len(actions),
            "blockedActions":  len([a for a in actions if a["outcome"] == "blocked"]),
            "approvedActions": len([a for a in actions if a["outcome"] == "approved"]),
            "allowedActions":  len([a for a in actions if a["outcome"] == "allowed"]),
            "hash": None,
        }
        content = json.dumps({**log, "hash": None}, sort_keys=True)
        log["hash"] = hashlib.sha256(content.encode()).hexdigest()
        return log


# ─────────────────────────────────────────────
# CUSTODYN — Main Class
# ─────────────────────────────────────────────

class Custodyn:
    def __init__(
        self,
        agent_id: str,
        api_key: Optional[str] = None,
        server_url: str = "http://localhost:5000",
        policies: list = [],
        fail_closed: Optional[bool] = None,
        on_approval_required: Optional[Callable] = None,
        on_action_blocked: Optional[Callable] = None,
        on_action_logged: Optional[Callable] = None,
    ):
        self.agent_id   = agent_id
        self.session_id = str(uuid.uuid4())
        self.api_key    = api_key
        self.server_url = server_url.rstrip("/")
        self.live_sync  = bool(api_key) and HAS_REQUESTS

        self.policy_engine = PolicyEngine(policies)
        self.audit_logger  = AuditLogger()

        self.on_approval_required = on_approval_required
        self.on_action_blocked    = on_action_blocked
        self.on_action_logged     = on_action_logged

        # Fail-closed config
        # Priority: constructor arg > server config > default (True = fail closed)
        self._fail_closed_override = fail_closed  # None = use server config
        self._fail_closed = fail_closed if fail_closed is not None else True  # safe default

        self._headers = {"X-API-Key": api_key} if api_key else {}

        status = "connected to dashboard" if self.live_sync else "local only (no api_key)"
        print(f"✓ Custodyn active | agent: {self.agent_id} | {status} | fail-closed: {self._fail_closed}")

        if api_key and not HAS_REQUESTS:
            print("⚠️  'requests' not installed — run: pip install requests")

        # Load fail-closed config from server in background if no override
        if self.live_sync and fail_closed is None:
            self._load_server_config()

    def _load_server_config(self):
        """Load fail-closed setting from server. Never raises."""
        try:
            resp = requests.get(
                f"{self.server_url}/sdk/config",
                headers=self._headers,
                timeout=3,
            )
            if resp.ok:
                data = resp.json()
                if isinstance(data.get("fail_closed"), bool):
                    self._fail_closed = data["fail_closed"]
                    print(f"✓ Custodyn: server config loaded | fail-closed: {self._fail_closed}")
        except Exception as e:
            print(f"⚠️  Custodyn: could not load server config — using default fail-closed: {self._fail_closed} ({e})")

    def _server_check(self, action: str, category: str, target: str) -> dict:
        """Check action against server policy. Returns verdict dict."""
        if not self.live_sync:
            return None
        try:
            resp = requests.post(
                f"{self.server_url}/sdk/strict-check",
                json={
                    "agent_id": self.agent_id,
                    "tool": action,
                    "category": category,
                    "target": target,
                },
                headers={**self._headers, "Content-Type": "application/json"},
                timeout=5,
            )
            data = resp.json()
            return {
                "verdict":   data.get("decision", "block" if data.get("error") else "allow"),
                "reason":    data.get("reason") or data.get("error"),
                "action_id": data.get("action_id"),
                "from_server": True,
            }
        except Exception as e:
            # Server unreachable — apply fail-closed config
            if self._fail_closed:
                print(f"✗ Custodyn server unreachable — fail-closed: action BLOCKED | {e}")
                return {"verdict": "block", "reason": "server_unreachable_fail_closed", "from_server": False}
            else:
                print(f"⚠️  Custodyn server unreachable — fail-open: action ALLOWED | {e}")
                return {"verdict": "allow", "reason": "server_unreachable_fail_open", "from_server": False}

    def _send_to_server(self, record: dict):
        """Fire-and-forget: send action to server. Never blocks or crashes."""
        if not self.live_sync:
            return
        try:
            requests.post(
                f"{self.server_url}/actions",
                json=record,
                headers={**self._headers, "Content-Type": "application/json"},
                timeout=3,
            )
        except Exception as e:
            print(f"⚠️  Custodyn: could not log action to server ({e})")

    def _poll_approval(self, action_id: str, timeout_seconds: int = 60) -> bool:
        """Poll server for approval decision. Returns True if approved."""
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            time.sleep(3)
            try:
                resp = requests.get(
                    f"{self.server_url}/action/{action_id}",
                    headers=self._headers,
                    timeout=5,
                )
                data = resp.json()
                outcome = (data.get("action") or data).get("outcome", "")
                if outcome == "approved": return True
                if outcome in ("blocked", "auto_denied"): return False
            except Exception:
                pass
        return False  # timeout = deny

    async def intercept(
        self,
        action: str,
        category: str,
        target: str,
        parameters: dict = {},
        metadata: dict = {}
    ) -> dict:
        risk_level = score_risk(category, target, parameters)

        record = {
            "id":        str(uuid.uuid4()),
            "agentId":   self.agent_id,
            "sessionId": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action":    action,
            "category":  category,
            "target":    target,
            "riskLevel": risk_level,
            "parameters": parameters,
            "metadata":   metadata,
            "outcome":    None,
            "blockedBy":  None,
            "approvedBy": None,
        }

        # 1. Server check (live enforcement)
        server_result = self._server_check(action, category, target)

        # 2. Local policy fallback
        local_result = self.policy_engine.evaluate(category, target, parameters)
        verdict = server_result["verdict"] if server_result else local_result["verdict"]
        rule    = local_result["rule"]

        # 3. Handle verdict
        if verdict == "block":
            record["outcome"]   = "blocked"
            record["blockedBy"] = (server_result or {}).get("reason") or (rule or {}).get("name", "policy")
            self.audit_logger.record(record)
            self._send_to_server(record)
            if self.on_action_blocked: self.on_action_blocked(record)
            if self.on_action_logged:  self.on_action_logged(record)
            return {"allowed": False, "reason": "blocked_by_policy", "action": record}

        if verdict == "require_approval":
            record["outcome"] = "pending_approval"
            self._send_to_server(record)
            approved = False
            if self.on_approval_required:
                if asyncio.iscoroutinefunction(self.on_approval_required):
                    approved = await self.on_approval_required(record)
                else:
                    approved = self.on_approval_required(record)
            elif server_result and server_result.get("action_id"):
                print(f"⏳ Custodyn: waiting for approval (action: {server_result['action_id']})...")
                approved = self._poll_approval(server_result["action_id"])

            record["outcome"]    = "approved" if approved else "blocked"
            record["approvedBy"] = "human" if approved else None
            record["blockedBy"]  = None if approved else "approval_denied"
            self.audit_logger.record(record)
            self._send_to_server(record)
            if self.on_action_logged: self.on_action_logged(record)
            return {"allowed": approved, "reason": record["outcome"], "action": record}

        # Allow
        record["outcome"] = "allowed"
        self.audit_logger.record(record)
        self._send_to_server(record)
        if self.on_action_logged: self.on_action_logged(record)
        return {"allowed": True, "reason": "allowed", "action": record}

    def check(self, action: str, category: str, target: str, parameters: dict = {}) -> dict:
        """Synchronous shorthand for intercept(). Runs event loop internally."""
        return asyncio.get_event_loop().run_until_complete(
            self.intercept(action, category, target, parameters)
        )

    def get_log(self) -> list:
        return self.audit_logger.get_session(self.session_id)

    def finalize_session(self) -> dict:
        return self.audit_logger.finalize(self.agent_id, self.session_id)

    def stats(self) -> dict:
        actions = self.get_log()
        return {
            "total":    len(actions),
            "allowed":  len([a for a in actions if a["outcome"] == "allowed"]),
            "blocked":  len([a for a in actions if a["outcome"] == "blocked"]),
            "approved": len([a for a in actions if a["outcome"] == "approved"]),
            "fail_closed": self._fail_closed,
            "risk_breakdown": {
                "low":      len([a for a in actions if a["riskLevel"] == "low"]),
                "medium":   len([a for a in actions if a["riskLevel"] == "medium"]),
                "high":     len([a for a in actions if a["riskLevel"] == "high"]),
                "critical": len([a for a in actions if a["riskLevel"] == "critical"]),
            }
        }


# ─────────────────────────────────────────────
# PRESETS
# ─────────────────────────────────────────────

PRESETS = {
    "strict": [
        {"id": "p1", "name": "Approve all sends",    "category": "send",   "requiresApproval": True, "active": True},
        {"id": "p2", "name": "Approve all deletes",  "category": "delete", "requiresApproval": True, "active": True},
        {"id": "p3", "name": "Approve all auth",     "category": "auth",   "requiresApproval": True, "active": True},
        {"id": "p4", "name": "Approve all payments", "category": "pay",    "requiresApproval": True, "active": True},
    ],
    "balanced": [
        {"id": "p1", "name": "Approve payments",     "category": "pay",    "requiresApproval": True, "active": True},
        {"id": "p2", "name": "Approve bulk deletes", "category": "delete", "requiresApproval": True, "active": True},
    ],
    "permissive": [],
}




# ─────────────────────────────────────────────
# FRAMEWORK INTEGRATIONS
# ─────────────────────────────────────────────

# Shared helpers for framework plugins
import re as _re

_CATEGORY_MAP = {
    'read_file':'read','read':'read','get':'read','fetch':'read','list':'read','search':'read',
    'write_file':'write','write':'write','create':'write','update':'write','edit':'write',
    'delete':'delete','remove':'delete','rm':'delete',
    'execute':'execute','run':'execute','exec':'execute','bash':'execute','shell':'execute',
    'send':'send','email':'send','mail':'send','message':'send','notify':'send',
    'pay':'pay','payment':'pay','charge':'pay','invoice':'pay','stripe':'pay',
    'login':'auth','auth':'auth','token':'auth','oauth':'auth',
}

def _infer_cat(name):
    low = (name or '').lower()
    for k,v in _CATEGORY_MAP.items():
        if k in low: return v
    return 'execute'

def _infer_tgt(name, inp):
    if not inp: return name
    s = inp if isinstance(inp,str) else __import__('json').dumps(inp)
    m = _re.search(r'https?://([^\s"\']+)', s)
    if m: return m.group(1).split('/')[0]
    return name

def _custodyn_check(api_key, agent_id, server_url, tool_name, tool_input, fail_closed, timeout):
    import json, urllib.request
    payload = json.dumps({'agent_id':agent_id,'session_id':'custodyn',
        'tool_name':tool_name,'tool_input':tool_input if isinstance(tool_input,dict) else {},
        'category':_infer_cat(tool_name),'target':_infer_tgt(tool_name,tool_input)}).encode()
    try:
        req = urllib.request.Request(f'{server_url}/openclaw/before_tool_call',
            data=payload, headers={'Content-Type':'application/json','X-API-Key':api_key}, method='POST')
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception as e:
        return {'decision':'block','policy':f'unreachable:{e}'} if fail_closed else {'decision':'allow'}


# ── OpenClaw Plugin ───────────────────────────

class CustodynPlugin:
    """OpenClaw native plugin. Usage: agent = Agent(plugins=[CustodynPlugin(api_key=..., agent_id=...)])"""
    id   = 'custodyn'
    name = 'Custodyn Agent Trust'

    def __init__(self, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
        if not api_key:  raise ValueError('[Custodyn] api_key required')
        if not agent_id: raise ValueError('[Custodyn] agent_id required')
        self.api_key=api_key; self.agent_id=agent_id
        self.server_url=server_url.rstrip('/'); self.fail_closed=fail_closed; self.timeout=timeout

    def register(self, api):
        api.on('before_tool_call', self._check, priority=100)

    def _check(self, event):
        tool  = getattr(event,'toolName','') or getattr(event,'tool_name','') or ''
        inp   = getattr(event,'params',{})   or getattr(event,'tool_input',{}) or {}
        data  = _custodyn_check(self.api_key,self.agent_id,self.server_url,tool,inp,self.fail_closed,self.timeout)
        dec   = data.get('decision','allow')
        if dec=='block':
            return {'block':True,'blockReason':f"'{tool}' blocked by Custodyn: {data.get('policy','')}"}
        if dec=='pending':
            return {'requireApproval':{'title':'Custodyn approval required','description':f"'{tool}' needs approval in your Custodyn dashboard.",'severity':'warning','timeoutMs':60000,'timeoutBehavior':'deny'}}
        return None


# ── CrewAI Integration ────────────────────────

def register_custodyn(api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
    """Register Custodyn hook for CrewAI. Call before crew.kickoff()."""
    try:
        from crewai.hooks.tool_hooks import register_before_tool_call_hook
    except ImportError:
        raise ImportError('[Custodyn] crewai>=1.9.1 required. Run: pip install --upgrade crewai')
    def hook(ctx):
        tool = getattr(ctx,'tool_name','') or ''; inp = getattr(ctx,'tool_input',{}) or {}
        data = _custodyn_check(api_key,agent_id,server_url,tool,inp,fail_closed,timeout)
        if data.get('decision') in ('block','pending'):
            print(f"[Custodyn] {'BLOCKED' if data['decision']=='block' else 'PENDING'}: {tool}")
            return False
        return None
    register_before_tool_call_hook(hook)
    print('[Custodyn] ✓ CrewAI integration active')


# ── AutoGen Integration ───────────────────────

class CustodynInterventionHandler:
    """AutoGen intervention handler. Usage: runtime = SingleThreadedAgentRuntime(intervention_handlers=[CustodynInterventionHandler(...)])"""
    def __init__(self, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
        if not api_key:  raise ValueError('[Custodyn] api_key required')
        if not agent_id: raise ValueError('[Custodyn] agent_id required')
        self.api_key=api_key; self.agent_id=agent_id
        self.server_url=server_url.rstrip('/'); self.fail_closed=fail_closed; self.timeout=timeout
        print('[Custodyn] ✓ AutoGen integration active')

    async def on_send(self, message, *, sender, recipient):
        try:
            from autogen_core import FunctionCall, DropMessage
            if isinstance(message, FunctionCall):
                tool=getattr(message,'name',''); inp=getattr(message,'arguments',{})
                data=_custodyn_check(self.api_key,self.agent_id,self.server_url,tool,inp,self.fail_closed,self.timeout)
                if data.get('decision') in ('block','pending'):
                    print(f"[Custodyn] {'BLOCKED' if data['decision']=='block' else 'PENDING'}: {tool}")
                    return DropMessage()
        except ImportError: pass
        return message

    async def on_publish(self, message, *, sender): return message
    async def on_response(self, message, *, sender, recipient): return message



# ── LangChain Integration ─────────────────────

class CustodynCallbackHandler:
    """
    LangChain callback handler. Intercepts every tool call before execution.

    Usage:
        from custodyn import CustodynCallbackHandler
        from langchain_openai import ChatOpenAI

        handler = CustodynCallbackHandler(api_key="as_live_...", agent_id="agt_...")
        llm = ChatOpenAI(callbacks=[handler])
    """
    def __init__(self, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
        if not api_key:  raise ValueError('[Custodyn] api_key required')
        if not agent_id: raise ValueError('[Custodyn] agent_id required')
        self.api_key    = api_key
        self.agent_id   = agent_id
        self.server_url = server_url.rstrip('/')
        self.fail_closed= fail_closed
        self.timeout    = timeout
        print('[Custodyn] ✓ LangChain integration active')

    def on_tool_start(self, serialized, input_str, **kwargs):
        tool = serialized.get('name', '') if isinstance(serialized, dict) else str(serialized)
        inp  = {'input': input_str}
        data = _custodyn_check(self.api_key, self.agent_id, self.server_url, tool, inp, self.fail_closed, self.timeout)
        if data.get('decision') in ('block', 'pending'):
            action = 'BLOCKED' if data['decision'] == 'block' else 'PENDING APPROVAL'
            raise PermissionError(f'[Custodyn] {action}: {tool} — {data.get("policy", "")}')

    def on_tool_end(self, output, **kwargs): pass
    def on_tool_error(self, error, **kwargs): pass
    def on_chain_start(self, serialized, inputs, **kwargs): pass
    def on_chain_end(self, outputs, **kwargs): pass
    def on_llm_start(self, serialized, prompts, **kwargs): pass
    def on_llm_end(self, response, **kwargs): pass


# ── LangGraph Integration ─────────────────────

def custodyn_langgraph_node(api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
    """
    LangGraph policy gate node. Add to your graph before any tool-calling node.

    Usage:
        from custodyn import custodyn_langgraph_node
        from langgraph.graph import StateGraph

        gate = custodyn_langgraph_node(api_key="as_live_...", agent_id="agt_...")
        graph = StateGraph(State)
        graph.add_node("custodyn_gate", gate)
        graph.add_edge("custodyn_gate", "tools")
    """
    def gate(state):
        tool = state.get('next_tool') or state.get('tool') or 'unknown'
        inp  = state.get('tool_input') or state.get('input') or {}
        data = _custodyn_check(api_key, agent_id, server_url, tool, inp if isinstance(inp, dict) else {'input': inp}, fail_closed, timeout)
        if data.get('decision') == 'block':
            return {**state, 'blocked': True, 'block_reason': data.get('policy', 'policy')}
        if data.get('decision') == 'pending':
            return {**state, 'pending_approval': True, 'action_id': data.get('action_id', '')}
        return state
    print('[Custodyn] ✓ LangGraph node ready')
    return gate


# ── OpenAI Agents SDK Integration ────────────

def custodyn_tool(api_key, agent_id, category='execute', server_url='https://custodyn.app', fail_closed=True, timeout=5):
    """
    Decorator for OpenAI Agents SDK tool functions. Wraps any tool with a Custodyn policy check.

    Usage:
        from custodyn import custodyn_tool

        @custodyn_tool(api_key="as_live_...", agent_id="agt_...", category="execute")
        def run_code(code: str) -> str:
            return exec(code)
    """
    def decorator(fn):
        def wrapper(**kwargs):
            data = _custodyn_check(api_key, agent_id, server_url, fn.__name__, kwargs, fail_closed, timeout)
            if data.get('decision') in ('block', 'pending'):
                action = 'BLOCKED' if data['decision'] == 'block' else 'PENDING APPROVAL'
                raise PermissionError(f'[Custodyn] {action}: {fn.__name__}')
            return fn(**kwargs)
        wrapper.__name__ = fn.__name__
        wrapper.__doc__  = fn.__doc__
        return wrapper
    return decorator


# ── Claude Code Integration ───────────────────

def custodyn_claude_hook(api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
    """
    Claude Code before_tool_call hook. Save as .claude/hooks/before_tool_call.py
    and call this function with the hook payload from stdin.

    Usage (in .claude/hooks/before_tool_call.py):
        import sys, json
        from custodyn import custodyn_claude_hook

        hook = json.loads(sys.stdin.read())
        result = custodyn_claude_hook(
            api_key="as_live_...",
            agent_id="agt_..."
        )(hook)
        if result:
            print(json.dumps(result))
            sys.exit(2)  # block the tool call
    """
    def handler(hook_payload):
        tool = hook_payload.get('tool_name', '')
        inp  = hook_payload.get('tool_input', {})
        data = _custodyn_check(api_key, agent_id, server_url, tool, inp, fail_closed, timeout)
        if data.get('decision') == 'block':
            return {'decision': 'block', 'reason': f'[Custodyn] Blocked by policy: {data.get("policy", "")}'}
        if data.get('decision') == 'pending':
            return {'decision': 'block', 'reason': f'[Custodyn] Pending approval in dashboard (action: {data.get("action_id", "")})'}
        return None
    return handler


# ── MCP Middleware ────────────────────────────

class CustodynMCPMiddleware:
    """
    MCP server middleware. Wraps any MCP server tool with a Custodyn policy check.

    Usage:
        from custodyn import CustodynMCPMiddleware
        from mcp.server import Server

        app = Server("my-mcp-server")
        custodyn = CustodynMCPMiddleware(api_key="as_live_...", agent_id="agt_...")

        @app.call_tool()
        async def handle_tool(name, arguments):
            custodyn.check(name, arguments)  # raises PermissionError if blocked
            # ... your tool logic
    """
    def __init__(self, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
        if not api_key:  raise ValueError('[Custodyn] api_key required')
        if not agent_id: raise ValueError('[Custodyn] agent_id required')
        self.api_key    = api_key
        self.agent_id   = agent_id
        self.server_url = server_url.rstrip('/')
        self.fail_closed= fail_closed
        self.timeout    = timeout
        print('[Custodyn] ✓ MCP middleware active')

    def check(self, tool_name, arguments=None):
        data = _custodyn_check(self.api_key, self.agent_id, self.server_url,
                               tool_name, arguments or {}, self.fail_closed, self.timeout)
        if data.get('decision') in ('block', 'pending'):
            action = 'BLOCKED' if data['decision'] == 'block' else 'PENDING APPROVAL'
            raise PermissionError(f'[Custodyn] {action}: {tool_name}')
        return data


# ── Anthropic / Claude Tool Use Integration ──

class CustodynAnthropicInterceptor:
    """
    Anthropic Claude tool use interceptor. Checks each tool call before
    passing it back to Claude for execution.

    Usage:
        from custodyn import CustodynAnthropicInterceptor
        import anthropic

        custodyn = CustodynAnthropicInterceptor(api_key="as_live_...", agent_id="agt_...")

        # In your tool execution loop:
        for block in response.content:
            if block.type == "tool_use":
                custodyn.check(block.name, block.input)  # raises if blocked
                result = execute_tool(block.name, block.input)
    """
    def __init__(self, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
        if not api_key:  raise ValueError('[Custodyn] api_key required')
        if not agent_id: raise ValueError('[Custodyn] agent_id required')
        self.api_key    = api_key
        self.agent_id   = agent_id
        self.server_url = server_url.rstrip('/')
        self.fail_closed= fail_closed
        self.timeout    = timeout
        print('[Custodyn] ✓ Anthropic/Claude integration active')

    def check(self, tool_name, tool_input=None, category='execute'):
        data = _custodyn_check(self.api_key, self.agent_id, self.server_url,
                               tool_name, tool_input or {}, self.fail_closed, self.timeout)
        if data.get('decision') in ('block', 'pending'):
            action = 'BLOCKED' if data['decision'] == 'block' else 'PENDING APPROVAL'
            raise PermissionError(f'[Custodyn] {action}: {tool_name} — {data.get("policy", "")}')
        return data


# ── Cursor / MCP Server Integration ──────────

class CustodynMCPServer:
    """
    MCP server tool guard for Cursor and other MCP clients.
    Use inside any @app.call_tool() handler.

    Usage:
        from custodyn import CustodynMCPServer
        from mcp.server import Server

        app = Server("my-server")
        guard = CustodynMCPServer(api_key="as_live_...", agent_id="agt_...")

        @app.call_tool()
        async def handle_tool(name: str, arguments: dict):
            guard.check(name, arguments)  # raises PermissionError if blocked
            return your_tool_logic(name, arguments)
    """
    def __init__(self, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
        if not api_key:  raise ValueError('[Custodyn] api_key required')
        if not agent_id: raise ValueError('[Custodyn] agent_id required')
        self.api_key    = api_key
        self.agent_id   = agent_id
        self.server_url = server_url.rstrip('/')
        self.fail_closed= fail_closed
        self.timeout    = timeout
        print('[Custodyn] ✓ MCP server guard active')

    def check(self, tool_name, arguments=None):
        data = _custodyn_check(self.api_key, self.agent_id, self.server_url,
                               tool_name, arguments or {}, self.fail_closed, self.timeout)
        if data.get('decision') in ('block', 'pending'):
            action = 'BLOCKED' if data['decision'] == 'block' else 'PENDING APPROVAL'
            raise PermissionError(f'[Custodyn] {action}: {tool_name}')
        return data


# ── Codex CLI / Shell wrapper ─────────────────

def custodyn_shell_check(command, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True, timeout=5):
    """
    Check a shell command against Custodyn policies before executing.
    Use as a wrapper around subprocess calls in any CLI agent.

    Usage:
        from custodyn import custodyn_shell_check
        import subprocess

        def safe_run(command):
            custodyn_shell_check(command, api_key="as_live_...", agent_id="agt_...")
            return subprocess.run(command, shell=True, capture_output=True)
    """
    data = _custodyn_check(api_key, agent_id, server_url, 'shell_execute',
                           {'command': command}, fail_closed, timeout)
    if data.get('decision') in ('block', 'pending'):
        action = 'BLOCKED' if data['decision'] == 'block' else 'PENDING APPROVAL'
        raise PermissionError(f'[Custodyn] {action}: {command}')
    return data

# ── One-line helper ───────────────────────────

def monitor(agent, api_key, agent_id, server_url='https://custodyn.app', fail_closed=True):
    """One-line OpenClaw integration: custodyn.monitor(agent, api_key='...', agent_id='...')"""
    plugin = CustodynPlugin(api_key=api_key, agent_id=agent_id, server_url=server_url, fail_closed=fail_closed)
    if hasattr(agent,'plugins') and isinstance(agent.plugins,list): agent.plugins.append(plugin)
    elif hasattr(agent,'add_plugin'): agent.add_plugin(plugin)
    elif hasattr(agent,'register'): plugin.register(agent)
    return agent
