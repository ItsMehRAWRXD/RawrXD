import {
  type DecisionListener,
  type InternalRequestContext,
  type SecurityConfig,
  type SecurityDecision,
  type SecurityRules,
  type SignedDecisionListener,
  type SignedDecisionPayload,
  type StateProvider,
} from './types';
import { InMemoryStateProvider, parseDurationToMs } from './state-provider';

interface RateLimitResult {
  blocked: boolean;
  currentCount: number;
  limit: number;
}

function normalizeHeaderValue(value: string | string[] | undefined): string {
  if (Array.isArray(value)) {
    return value.join(',').toLowerCase();
  }
  return (value ?? '').toLowerCase();
}

function buildRateLimitKey(
  context: InternalRequestContext,
  keyBy: NonNullable<SecurityRules['rateLimit']>['keyBy']
): string {
  const user = context.userId ?? 'anonymous';

  if (keyBy === 'user') {
    return `rate:user:${user}`;
  }
  if (keyBy === 'ip+path') {
    return `rate:ip-path:${context.ip}:${context.path}`;
  }
  if (keyBy === 'user+path') {
    return `rate:user-path:${user}:${context.path}`;
  }
  return `rate:ip:${context.ip}`;
}

function maskPayloadFields(payload: unknown, fields: string[]): unknown {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return payload;
  }

  const result: Record<string, unknown> = { ...(payload as Record<string, unknown>) };
  for (const field of fields) {
    if (field in result) {
      result[field] = '[REDACTED]';
    }
  }
  return result;
}

export class SecurityEngine {
  private readonly config: Required<Pick<SecurityConfig, 'rules' | 'failOpen'>>;
  private readonly telemetry: Required<Pick<NonNullable<SecurityConfig['telemetry']>, 'asyncSigning'>> & {
    signer?: NonNullable<SecurityConfig['telemetry']>['signer'];
  };
  private readonly stateProvider: StateProvider;
  private listeners = new Set<DecisionListener>();
  private signedListeners = new Set<SignedDecisionListener>();

  constructor(config: SecurityConfig, stateProvider?: StateProvider) {
    this.config = {
      rules: config.rules,
      failOpen: config.failOpen ?? true,
    };
    this.telemetry = {
      signer: config.telemetry?.signer,
      asyncSigning: config.telemetry?.asyncSigning ?? true,
    };

    // Validate key material at initialization time before serving requests.
    this.telemetry.signer?.validateKey?.();

    this.stateProvider = stateProvider ?? new InMemoryStateProvider();
  }

  public onDecision(listener: DecisionListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  public onSignedDecision(listener: SignedDecisionListener): () => void {
    this.signedListeners.add(listener);
    return () => this.signedListeners.delete(listener);
  }

  public getConfig(): SecurityConfig {
    return {
      rules: this.config.rules,
      failOpen: this.config.failOpen,
      telemetry: {
        signer: this.telemetry.signer,
        asyncSigning: this.telemetry.asyncSigning,
      },
    };
  }

  public async evaluate(context: InternalRequestContext): Promise<SecurityDecision> {
    try {
      const matchedRules: string[] = [];
      let reason = 'Allowed';
      let allowed = true;
      let tags: Record<string, string> | undefined;
      let redactedPayload: unknown;

      const rateLimit = await this.evaluateRateLimit(context);
      if (rateLimit.blocked) {
        allowed = false;
        reason = `rate_limit_exceeded:${rateLimit.currentCount}/${rateLimit.limit}`;
        matchedRules.push('rateLimit');
        tags = { rule: 'rateLimit' };
      }

      if (allowed) {
        const botBlocked = this.evaluateBotProtection(context);
        if (botBlocked) {
          allowed = false;
          reason = 'bot_detected';
          matchedRules.push('botProtection');
          tags = { rule: 'botProtection' };
        }
      }

      const piiResult = this.evaluatePiiMasking(context);
      if (piiResult.applied) {
        matchedRules.push('piiMasking');
        redactedPayload = piiResult.payload;
      }

      const decision: SecurityDecision = {
        allowed,
        action: allowed ? 'ALLOW' : 'BLOCK',
        reason,
        matchedRules,
        context: {
          ip: context.ip,
          method: context.method,
          path: context.path,
          userId: context.userId,
          payloadSizeBytes: context.payloadSizeBytes,
        },
        tags,
        redactedPayload,
      };

      this.emitDecision(decision);
      return decision;
    } catch (error) {
      if (this.config.failOpen) {
        const fallback: SecurityDecision = {
          allowed: true,
          action: 'ALLOW',
          reason: 'fail_open_engine_error',
          matchedRules: [],
          context: {
            ip: context.ip,
            method: context.method,
            path: context.path,
            userId: context.userId,
            payloadSizeBytes: context.payloadSizeBytes,
          },
          tags: {
            error: error instanceof Error ? error.name : 'unknown_error',
          },
        };
        this.emitDecision(fallback);
        return fallback;
      }

      throw error;
    }
  }

  public protect() {
    return async <T>(
      context: InternalRequestContext,
      next: () => Promise<T>
    ): Promise<{ decision: SecurityDecision; value?: T }> => {
      const decision = await this.evaluate(context);
      if (!decision.allowed) {
        return { decision };
      }

      const value = await next();
      return { decision, value };
    };
  }

  public async signDecision(
    decision: SecurityDecision,
    timestamp: number = Date.now()
  ): Promise<SignedDecisionPayload | undefined> {
    const signer = this.telemetry.signer;
    if (!signer) {
      return undefined;
    }

    const { signedPayload: _ignore, ...decisionToSign } = decision;
    const nonce = globalThis.crypto?.randomUUID?.() ?? `${timestamp}-${Math.random().toString(36).slice(2, 10)}`;

    return signer.sign({
      timestamp,
      nonce,
      eventType: 'SECURITY_DECISION',
      decision: decisionToSign,
    });
  }

  private emitDecision(decision: SecurityDecision): void {
    const timestamp = Date.now();
    const event = {
      timestamp,
      decision,
    };

    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Listener failures must never break request flow.
      }
    }

    // Sign telemetry off the hot path by default.
    const signer = this.telemetry.signer;
    if (!signer || !this.telemetry.asyncSigning) {
      return;
    }

    queueMicrotask(async () => {
      try {
        const signedPayload = await this.signDecision(decision, timestamp);
        if (!signedPayload) {
          return;
        }

        const signedEvent = {
          timestamp,
          decision: {
            ...decision,
            signedPayload,
          },
          signedPayload,
        };

        for (const listener of this.signedListeners) {
          try {
            listener(signedEvent);
          } catch {
            // Listener failures must never break request flow.
          }
        }
      } catch {
        // Signing must never impact request path.
      }
    });
  }

  private async evaluateRateLimit(context: InternalRequestContext): Promise<RateLimitResult> {
    const config = this.config.rules.rateLimit;
    if (!config) {
      return { blocked: false, currentCount: 0, limit: 0 };
    }

    const windowMs = parseDurationToMs(config.window);
    const key = buildRateLimitKey(context, config.keyBy ?? 'ip');
    const count = await this.stateProvider.incrementCounter(key, windowMs);

    return {
      blocked: count > config.max,
      currentCount: count,
      limit: config.max,
    };
  }

  private evaluateBotProtection(context: InternalRequestContext): boolean {
    const config = this.config.rules.botProtection;
    if (!config?.block) {
      return false;
    }

    const defaultDenylist = ['curl/', 'python-requests', 'scrapy', 'bot'];
    const denylist = config.userAgentDenylist ?? defaultDenylist;

    const ua = normalizeHeaderValue(context.headers['user-agent']);
    if (!ua) {
      return false;
    }

    return denylist.some((marker) => ua.includes(marker.toLowerCase()));
  }

  private evaluatePiiMasking(context: InternalRequestContext): { applied: boolean; payload?: unknown } {
    const config = this.config.rules.piiMasking;
    if (!config?.enabled) {
      return { applied: false };
    }

    const fields = config.fields ?? ['email', 'phone', 'ssn', 'token', 'password'];
    return {
      applied: true,
      payload: maskPayloadFields(context.payload, fields),
    };
  }
}

export class SecuritySDK {
  private readonly engine: SecurityEngine;

  constructor(config: SecurityConfig, stateProvider?: StateProvider) {
    this.engine = new SecurityEngine(config, stateProvider);
  }

  public onDecision(listener: DecisionListener): () => void {
    return this.engine.onDecision(listener);
  }

  public onSignedDecision(listener: SignedDecisionListener): () => void {
    return this.engine.onSignedDecision(listener);
  }

  public async evaluate(context: InternalRequestContext): Promise<SecurityDecision> {
    return this.engine.evaluate(context);
  }

  public protect() {
    return this.engine.protect();
  }

  public signDecision(
    decision: SecurityDecision,
    timestamp?: number
  ): Promise<SignedDecisionPayload | undefined> {
    return this.engine.signDecision(decision, timestamp);
  }

  public getConfig(): SecurityConfig {
    return this.engine.getConfig();
  }
}