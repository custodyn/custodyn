export interface CustodynConfig {
  agentId: string;
  apiKey: string;
  serverUrl?: string;
  strictMode?: boolean;
  failOpen?: boolean;
  policies?: PolicyRule[];
}

export interface PolicyRule {
  category: string;
  action: 'allow' | 'block' | 'require_approval';
  blockedTargets?: string[];
  allowedTargets?: string[];
  active?: boolean;
}

export interface InterceptOptions {
  action: string;
  category: 'pay' | 'send' | 'delete' | 'auth' | 'write' | 'execute' | 'read';
  target?: string;
  parameters?: Record<string, unknown>;
  sessionId?: string;
}

export interface InterceptResult {
  allowed: boolean;
  reason: string;
  action: Record<string, unknown>;
  requiresApproval?: boolean;
}

export class Custodyn {
  constructor(config: CustodynConfig);
  intercept(options: InterceptOptions): Promise<InterceptResult>;
  log(options: InterceptOptions & { outcome: string }): Promise<void>;
}
