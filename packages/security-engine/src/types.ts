export type DecisionAction = 'ALLOW' | 'BLOCK';

export interface SignedDecisionPayload {
  payload: {
    timestamp: number;
    nonce: string;
    eventType: 'SECURITY_DECISION';
    decision: Omit<SecurityDecision, 'signedPayload'>;
  };
  signature: string; // Base64URL detached signature
  alg: 'Ed25519';
  keyId?: string;
}

export interface TelemetrySigner {
  validateKey?(): void;
  sign(input: {
    timestamp: number;
    nonce: string;
    eventType: 'SECURITY_DECISION';
    decision: Omit<SecurityDecision, 'signedPayload'>;
  }): Promise<SignedDecisionPayload>;
}

export interface SecurityTelemetryOptions {
  signer?: TelemetrySigner;
  asyncSigning?: boolean;
}

export interface InternalRequestContext {
  method: string;
  path: string;
  ip: string;
  headers: Record<string, string | string[] | undefined>;
  userId?: string;
  payload?: unknown;
  payloadSizeBytes?: number;
}

export interface RuleRateLimitConfig {
  window: string;
  max: number;
  keyBy?: 'ip' | 'user' | 'ip+path' | 'user+path';
}

export interface RuleBotProtectionConfig {
  block: boolean;
  userAgentDenylist?: string[];
}

export interface RulePiiMaskingConfig {
  enabled: boolean;
  fields?: string[];
}

export interface SecurityRules {
  rateLimit?: RuleRateLimitConfig;
  botProtection?: RuleBotProtectionConfig;
  piiMasking?: RulePiiMaskingConfig;
}

export interface SecurityConfig {
  rules: SecurityRules;
  failOpen?: boolean;
  telemetry?: SecurityTelemetryOptions;
}

export interface DecisionContextMetadata {
  ip: string;
  method: string;
  path: string;
  userId?: string;
  payloadSizeBytes?: number;
}

export interface SecurityDecision {
  allowed: boolean;
  action: DecisionAction;
  reason: string;
  matchedRules: string[];
  context: DecisionContextMetadata;
  tags?: Record<string, string>;
  redactedPayload?: unknown;
  signedPayload?: SignedDecisionPayload;
}

export interface DecisionEvent {
  timestamp: number;
  decision: SecurityDecision;
}

export interface SignedDecisionEvent {
  timestamp: number;
  decision: SecurityDecision;
  signedPayload: SignedDecisionPayload;
}

export interface StateProvider {
  incrementCounter(key: string, windowMs: number): Promise<number>;
}

export type DecisionListener = (event: DecisionEvent) => void;
export type SignedDecisionListener = (event: SignedDecisionEvent) => void;