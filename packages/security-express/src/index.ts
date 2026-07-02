import { SecuritySDK, type InternalRequestContext, type SecurityDecision } from '@rawrxd/security-engine';

export interface ExpressLikeRequest {
  method: string;
  url: string;
  originalUrl?: string;
  ip: string;
  socket: { remoteAddress?: string | null };
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
}

export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  json(body: unknown): void;
  setHeader?(name: string, value: string): void;
}

export type ExpressLikeNextFunction = () => void;

export interface SecurityJwksKey {
  kid: string;
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  use?: 'sig';
  alg?: 'EdDSA';
  nbf?: number; // epoch milliseconds
  exp?: number; // epoch milliseconds
}

export interface SecurityJwksDocument {
  keys: SecurityJwksKey[];
}

export interface ExpressContextAdapterOptions {
  userIdHeader?: string;
  trustProxy?: boolean;
}

export interface BlockResponseBody {
  error: 'REQUEST_BLOCKED';
  reason: string;
  matchedRules: string[];
}

export interface ExpressMiddlewareOptions extends ExpressContextAdapterOptions {
  blockStatusCode?: number;
  attachDecisionToRequest?: boolean;
  attachSignatureHeaders?: boolean;
  signatureHeaderName?: string;
  signatureAlgorithmHeaderName?: string;
  signatureKeyIdHeaderName?: string;
}

function getHeader(req: ExpressLikeRequest, name: string): string | string[] | undefined {
  const value = req.headers[name.toLowerCase()];
  return value as string | string[] | undefined;
}

function estimatePayloadSize(payload: unknown): number | undefined {
  if (payload == null) {
    return undefined;
  }

  try {
    return new TextEncoder().encode(JSON.stringify(payload)).length;
  } catch {
    return undefined;
  }
}

export function toInternalRequestContext(
  req: ExpressLikeRequest,
  options: ExpressContextAdapterOptions = {}
): InternalRequestContext {
  const userIdHeader = options.userIdHeader ?? 'x-user-id';
  const userId = getHeader(req, userIdHeader);

  return {
    method: req.method,
    path: req.originalUrl || req.url,
    ip: options.trustProxy ? req.ip : req.socket.remoteAddress ?? 'unknown',
    headers: req.headers,
    userId: Array.isArray(userId) ? userId[0] : userId,
    payload: req.body,
    payloadSizeBytes: estimatePayloadSize(req.body),
  };
}

export function createExpressMiddleware(
  sdk: SecuritySDK,
  options: ExpressMiddlewareOptions = {}
) {
  const blockStatusCode = options.blockStatusCode ?? 403;
  const attachDecisionToRequest = options.attachDecisionToRequest ?? true;
  const attachSignatureHeaders = options.attachSignatureHeaders ?? false;
  const signatureHeaderName = options.signatureHeaderName ?? 'X-Governance-Signature';
  const signatureAlgorithmHeaderName = options.signatureAlgorithmHeaderName ?? 'X-Governance-Signature-Alg';
  const signatureKeyIdHeaderName = options.signatureKeyIdHeaderName ?? 'X-Governance-Key-Id';

  const attachHeaders = async (res: ExpressLikeResponse, decision: SecurityDecision): Promise<SecurityDecision> => {
    if (!attachSignatureHeaders || typeof res.setHeader !== 'function') {
      return decision;
    }

    const signedPayload = await sdk.signDecision(decision);
    if (!signedPayload) {
      return decision;
    }

    res.setHeader(signatureHeaderName, signedPayload.signature);
    res.setHeader(signatureAlgorithmHeaderName, signedPayload.alg);
    if (signedPayload.keyId) {
      res.setHeader(signatureKeyIdHeaderName, signedPayload.keyId);
    }

    return {
      ...decision,
      signedPayload,
    };
  };

  return async (
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: ExpressLikeNextFunction
  ): Promise<void> => {
    try {
      const context = toInternalRequestContext(req, options);
      const decision = await attachHeaders(res, await sdk.evaluate(context));

      if (attachDecisionToRequest) {
        (req as ExpressLikeRequest & { securityDecision?: SecurityDecision }).securityDecision = decision;
      }

      if (decision.allowed) {
        next();
        return;
      }

      const body: BlockResponseBody = {
        error: 'REQUEST_BLOCKED',
        reason: decision.reason,
        matchedRules: decision.matchedRules,
      };

      res.status(blockStatusCode).json(body);
    } catch {
      // Fail-open behavior for adapter failures to avoid app-level DoS.
      next();
    }
  };
}

export function createSecurityKeysHandler(
  source: SecurityJwksDocument | (() => Promise<SecurityJwksDocument> | SecurityJwksDocument)
) {
  return async (_req: ExpressLikeRequest, res: ExpressLikeResponse): Promise<void> => {
    const doc = typeof source === 'function' ? await source() : source;
    const normalized: SecurityJwksDocument = {
      keys: (doc.keys ?? []).map((k) => ({
        kid: k.kid,
        kty: 'OKP',
        crv: 'Ed25519',
        x: k.x,
        use: k.use ?? 'sig',
        alg: k.alg ?? 'EdDSA',
        nbf: k.nbf,
        exp: k.exp,
      })),
    };

    if (typeof res.setHeader === 'function') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'public, max-age=60, must-revalidate');
    }

    res.status(200).json(normalized);
  };
}