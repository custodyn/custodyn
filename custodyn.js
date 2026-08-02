/**
 * custodyn.js — Agent Trust SDK v1.1.0
 * Server-integrated version: calls Custodyn backend for policy checks,
 * logs every action, and supports strict-mode enforcement with fail-closed config.
 */

const crypto = require('crypto');

// ── RISK SCORING ──────────────────────────────────────

const RISK_LEVELS = {
  read:'low', write:'medium', execute:'medium',
  auth:'high', send:'high', delete:'high', pay:'critical'
};
const SENSITIVE_TARGETS = [
  'stripe','paypal','bank','payment','production','prod',
  'smtp','twilio','aws','database','db','admin','billing'
];

function scoreRisk(category, target, parameters = {}) {
  const levels = ['low','medium','high','critical'];
  let idx = levels.indexOf(RISK_LEVELS[category] || 'medium');
  if (SENSITIVE_TARGETS.some(t => (target||'').toLowerCase().includes(t))) idx = Math.min(idx+1, 3);
  if (parameters.bulk || parameters.all || (parameters.count > 100)) idx = 3;
  return levels[idx];
}

// ── LOCAL POLICY ENGINE (fallback when server unreachable) ───

class PolicyEngine {
  constructor(rules = []) { this.rules = rules.filter(r => r.active !== false); }
  evaluate(category, target) {
    for (const rule of this.rules) {
      if (rule.category !== category) continue;
      const blocked = rule.blockedTargets || rule.blocked_targets || [];
      const allowed = rule.allowedTargets || rule.allowed_targets || null;
      if (blocked.some(t => (target||'').includes(t))) return { verdict:'block', rule };
      if (allowed && !allowed.some(t => (target||'').includes(t))) return { verdict:'block', rule };
      if (rule.action === 'require_approval' || rule.requiresApproval) return { verdict:'require_approval', rule };
      if (rule.action === 'block') return { verdict:'block', rule };
    }
    return { verdict:'allow', rule:null };
  }
}

// ── AUDIT LOGGER ──────────────────────────────────────

class AuditLogger {
  constructor() { this.sessions = new Map(); }
  record(action) {
    const s = this.sessions.get(action.sessionId) || [];
    s.push(action);
    this.sessions.set(action.sessionId, s);
  }
  getSession(sessionId) { return this.sessions.get(sessionId) || []; }
  finalize(agentId, sessionId) {
    const actions = this.sessions.get(sessionId) || [];
    const log = {
      logId: crypto.randomUUID(), agentId, sessionId, actions,
      startedAt: actions[0]?.timestamp || new Date().toISOString(),
      endedAt: new Date().toISOString(),
      totalActions: actions.length,
      blockedActions:  actions.filter(a => a.outcome==='blocked').length,
      approvedActions: actions.filter(a => a.outcome==='approved').length,
      allowedActions:  actions.filter(a => a.outcome==='allowed').length,
    };
    const content = JSON.stringify({...log});
    log.hash = crypto.createHash('sha256').update(content).digest('hex');
    return log;
  }
}

// ── HTTP HELPER ───────────────────────────────────────

async function fetchJSON(url, options = {}) {
  const fetchFn = typeof fetch !== 'undefined' ? fetch : require('node-fetch');
  const res = await fetchFn(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    signal: AbortSignal.timeout(5000),
  });
  return res.json();
}

// ── MAIN CLASS ────────────────────────────────────────

class Custodyn {
  constructor(config = {}) {
    if (!config.agentId) throw new Error('Custodyn: agentId is required');
    if (!config.apiKey)  throw new Error('Custodyn: apiKey is required');

    this.agentId    = config.agentId;
    this.apiKey     = config.apiKey;
    this.serverUrl  = (config.serverUrl || 'http://localhost:5000').replace(/\/$/, '');
    this.sessionId  = crypto.randomUUID();
    this.strictMode = config.strictMode !== false;

    // Fail-closed by default — can be overridden by server config or constructor
    // failClosed: true  = block actions when server is unreachable (safe default)
    // failClosed: false = allow actions when server is unreachable (use with caution)
    this._failClosedOverride = config.failClosed !== undefined ? config.failClosed : null;
    this._failClosed = config.failClosed !== false; // default true until server config loaded

    this.policyEngine = new PolicyEngine(config.policies || []);
    this.auditLogger  = new AuditLogger();

    this.onApprovalRequired = config.onApprovalRequired || null;
    this.onActionBlocked    = config.onActionBlocked    || null;
    this.onActionLogged     = config.onActionLogged     || null;

    this._headers = {
      'Content-Type': 'application/json',
      'X-API-Key': this.apiKey,
    };

    console.log(`✓ Custodyn active | agent: ${this.agentId} | session: ${this.sessionId.slice(0,8)} | server: ${this.serverUrl} | fail-closed: ${this._failClosed}`);

    // Load server config (fail-closed setting) in background
    this._loadServerConfig();
  }

  // ── LOAD FAIL-CLOSED CONFIG FROM SERVER ───────────
  async _loadServerConfig() {
    // If failClosed was explicitly set in constructor, use that — don't override
    if (this._failClosedOverride !== null) return;
    try {
      const data = await fetchJSON(`${this.serverUrl}/sdk/config`, {
        headers: this._headers,
      });
      if (typeof data.fail_closed === 'boolean') {
        this._failClosed = data.fail_closed;
        console.log(`✓ Custodyn: server config loaded | fail-closed: ${this._failClosed}`);
      }
    } catch (err) {
      // Can't load config — keep default (fail closed)
      console.warn(`⚠️  Custodyn: could not load server config — using default fail-closed: ${this._failClosed}`);
    }
  }

  // ── SERVER POLICY CHECK ────────────────────────────
  async _serverCheck(action, category, target) {
    try {
      const data = await fetchJSON(`${this.serverUrl}/sdk/strict-check`, {
        method: 'POST',
        headers: this._headers,
        body: JSON.stringify({
          agent_id: this.agentId,
          tool: action,
          category,
          target,
        }),
      });
      return {
        verdict: data.decision || (data.error ? 'block' : 'allow'),
        reason:  data.reason || data.error || null,
        actionId: data.action_id || null,
        fromServer: true,
      };
    } catch (err) {
      // Server unreachable — apply fail-closed config
      if (this._failClosed) {
        console.error(`✗ Custodyn server unreachable — fail-closed: action BLOCKED | ${err.message}`);
        return { verdict: 'block', reason: 'server_unreachable_fail_closed', fromServer: false };
      } else {
        console.warn(`⚠️  Custodyn server unreachable — fail-open: action ALLOWED | ${err.message}`);
        return { verdict: 'allow', reason: 'server_unreachable_fail_open', fromServer: false };
      }
    }
  }

  // ── LOG ACTION TO SERVER ───────────────────────────
  async _logToServer(record) {
    try {
      await fetchJSON(`${this.serverUrl}/actions`, {
        method: 'POST',
        headers: this._headers,
        body: JSON.stringify(record),
      });
    } catch (err) {
      console.warn(`⚠️  Custodyn: failed to log action to server: ${err.message}`);
    }
  }

  // ── POLL FOR APPROVAL ──────────────────────────────
  async _pollApproval(actionId, timeoutMs = 60000) {
    const interval = 3000;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, interval));
      try {
        const data = await fetchJSON(`${this.serverUrl}/action/${actionId}`, {
          headers: this._headers,
        });
        if (data.outcome === 'approved') return true;
        if (data.outcome === 'blocked')  return false;
      } catch (err) { /* keep polling */ }
    }
    return false;
  }

  // ── MAIN INTERCEPT ────────────────────────────────
  async intercept({ action, category, target, parameters = {}, metadata = {} }) {
    const riskLevel = scoreRisk(category, target, parameters);

    const record = {
      id:        crypto.randomUUID(),
      agentId:   this.agentId,
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      action, category, target, riskLevel,
      parameters, metadata,
      outcome:   null,
      blockedBy: null,
      approvedBy: null,
    };

    let serverResult = null;
    if (this.strictMode) {
      serverResult = await this._serverCheck(action, category, target);
    }

    const localResult = this.policyEngine.evaluate(category, target);
    const verdict = serverResult ? serverResult.verdict : localResult.verdict;
    const rule    = localResult.rule;

    if (verdict === 'block') {
      record.outcome   = 'blocked';
      record.blockedBy = serverResult?.reason || rule?.name || 'policy';
      this.auditLogger.record(record);
      await this._logToServer(record);
      this.onActionBlocked?.(record);
      this.onActionLogged?.(record);
      return { allowed: false, reason: 'blocked_by_policy', action: record };
    }

    if (verdict === 'require_approval') {
      record.outcome = 'pending_approval';
      await this._logToServer(record);

      let approved = false;
      if (this.onApprovalRequired) {
        approved = await this.onApprovalRequired(record);
      } else if (serverResult?.action_id) {
        console.log(`⏳ Custodyn: waiting for approval (action: ${serverResult.action_id})...`);
        approved = await this._pollApproval(serverResult.action_id);
      }

      record.outcome    = approved ? 'approved' : 'blocked';
      record.approvedBy = approved ? 'human'    : null;
      record.blockedBy  = approved ? null        : 'approval_denied';
      this.auditLogger.record(record);
      await this._logToServer({...record});
      this.onActionLogged?.(record);
      return { allowed: approved, reason: record.outcome, action: record };
    }

    record.outcome = 'allowed';
    this.auditLogger.record(record);
    await this._logToServer(record);
    this.onActionLogged?.(record);
    return { allowed: true, reason: 'allowed', action: record };
  }

  // ── SHORTHAND ─────────────────────────────────────
  async check(action, category, target, parameters = {}) {
    return this.intercept({ action, category, target, parameters });
  }

  // ── UTILITIES ─────────────────────────────────────
  getLog()          { return this.auditLogger.getSession(this.sessionId); }
  finalizeSession() { return this.auditLogger.finalize(this.agentId, this.sessionId); }

  stats() {
    const actions = this.getLog();
    return {
      total:    actions.length,
      allowed:  actions.filter(a => a.outcome==='allowed').length,
      blocked:  actions.filter(a => a.outcome==='blocked').length,
      approved: actions.filter(a => a.outcome==='approved').length,
      failClosed: this._failClosed,
      riskBreakdown: {
        low:      actions.filter(a => a.riskLevel==='low').length,
        medium:   actions.filter(a => a.riskLevel==='medium').length,
        high:     actions.filter(a => a.riskLevel==='high').length,
        critical: actions.filter(a => a.riskLevel==='critical').length,
      }
    };
  }
}

// ── PRESETS ───────────────────────────────────────────

const PRESETS = {
  strict: [
    { id:'p1', name:'Block all payments',  category:'pay',    action:'block',            active:true },
    { id:'p2', name:'Approve all sends',   category:'send',   action:'require_approval', active:true },
    { id:'p3', name:'Approve all deletes', category:'delete', action:'require_approval', active:true },
    { id:'p4', name:'Approve all auth',    category:'auth',   action:'require_approval', active:true },
    { id:'p5', name:'Approve all writes',  category:'write',  action:'require_approval', active:true },
  ],
  balanced: [
    { id:'p1', name:'Approve payments',    category:'pay',    action:'require_approval', active:true },
    { id:'p2', name:'Approve bulk deletes',category:'delete', action:'require_approval', active:true },
  ],
  permissive: [],
};

// ── OpenClaw Plugin ──────────────────────────────────────

class CustodynPlugin {
  constructor({ apiKey, agentId, serverUrl = 'https://custodyn.app', failClosed = true, timeout = 5 } = {}) {
    if (!apiKey)   throw new Error('[Custodyn] apiKey is required');
    if (!agentId)  throw new Error('[Custodyn] agentId is required');
    this.apiKey     = apiKey;
    this.agentId    = agentId;
    this.serverUrl  = serverUrl.replace(/\/$/, '');
    this.failClosed = failClosed;
    this.timeout    = timeout;
  }

  register(api) {
    api.on('before_tool_call', (event) => this._check(event), { priority: 100 });
  }

  async _check(event) {
    const tool   = event.toolName || event.tool_name || '';
    const params = event.params   || event.tool_input || {};
    const payload = JSON.stringify({
      agent_id:   this.agentId,
      session_id: 'custodyn',
      tool_name:  tool,
      tool_input: (typeof params === 'object' && params !== null) ? params : {},
      category:   scoreRisk(tool, ''),
    });

    try {
      const https = require('https');
      const http  = require('http');
      const url   = new URL(this.serverUrl + '/openclaw/before_tool_call');
      const lib   = url.protocol === 'https:' ? https : http;
      const data  = await new Promise((resolve, reject) => {
        const req = lib.request({
          hostname: url.hostname,
          port:     url.port,
          path:     url.pathname,
          method:   'POST',
          headers:  { 'Content-Type': 'application/json', 'X-API-Key': this.apiKey },
          timeout:  this.timeout * 1000,
        }, (res) => {
          let body = '';
          res.on('data', d => body += d);
          res.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.write(payload);
        req.end();
      });

      const decision = data.decision || 'allow';
      if (decision === 'block') {
        return { block: true, blockReason: `'${tool}' blocked by Custodyn: ${data.policy || ''}` };
      }
      if (decision === 'pending') {
        return {
          requireApproval: {
            title:           'Custodyn approval required',
            description:     `'${tool}' needs approval in your Custodyn dashboard.`,
            severity:        'warning',
            timeoutMs:       60000,
            timeoutBehavior: 'deny',
          }
        };
      }
      return null;

    } catch (e) {
      if (this.failClosed) {
        return { block: true, blockReason: `Custodyn unreachable (fail-closed): ${tool}` };
      }
      return null;
    }
  }
}



// ── GitHub Copilot / VS Code Extension Integration ───────────────────
/**
 * Custodyn check function for GitHub Copilot workspace agents and VS Code extensions.
 *
 * Usage (in your VS Code extension or Copilot agent):
 *   const { custodynCheck } = require('custodyn');
 *
 *   const decision = await custodynCheck({
 *     apiKey: 'as_live_...',
 *     agentId: 'agt_...',
 *     tool: 'run_terminal_command',
 *     category: 'execute',
 *     target: command,
 *     serverUrl: 'https://custodyn.app'
 *   });
 *   if (!decision.allowed) throw new Error(`Blocked: ${decision.reason}`);
 */
async function custodynCheck({ apiKey, agentId, tool, category = 'execute', target = '', parameters = {}, serverUrl = 'https://custodyn.app', failClosed = true }) {
  try {
    const res = await fetch(`${serverUrl}/gateway/check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      body: JSON.stringify({ agent_id: agentId, tool, category, target, parameters })
    });
    const data = await res.json();
    return {
      allowed:  data.decision === 'allow',
      decision: data.decision,
      reason:   data.policy || data.explanation || '',
      actionId: data.action_id || ''
    };
  } catch (e) {
    if (failClosed) return { allowed: false, decision: 'block', reason: `Custodyn unreachable (fail-closed)` };
    return { allowed: true, decision: 'allow', reason: 'failOpen' };
  }
}

module.exports = { Custodyn, PolicyEngine, AuditLogger, scoreRisk, PRESETS, CustodynPlugin, custodynCheck };
