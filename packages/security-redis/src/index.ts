import type { StateProvider } from '@rawrxd/security-engine';

export interface RedisEvalClient {
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<number | string>;
}

export interface RedisStateProviderOptions {
  keyPrefix?: string;
  maxKeyLength?: number;
}

const SLIDING_WINDOW_LUA = `
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local member = ARGV[3]

local min_score = now_ms - window_ms
redis.call('ZREMRANGEBYSCORE', key, '-inf', min_score)
redis.call('ZADD', key, now_ms, member)
local count = redis.call('ZCARD', key)
redis.call('PEXPIRE', key, window_ms)

return count
`;

function sanitizeKeyPart(value: string): string {
  return value.replace(/[^a-zA-Z0-9:_-]/g, '_');
}

function buildMember(nowMs: number): string {
  const random = Math.random().toString(36).slice(2, 10);
  return `${nowMs}-${random}`;
}

export class RedisSlidingWindowStateProvider implements StateProvider {
  private readonly client: RedisEvalClient;
  private readonly keyPrefix: string;
  private readonly maxKeyLength: number;

  constructor(client: RedisEvalClient, options: RedisStateProviderOptions = {}) {
    this.client = client;
    this.keyPrefix = options.keyPrefix ?? 'rawrxd:security:rate';
    this.maxKeyLength = options.maxKeyLength ?? 256;
  }

  public async incrementCounter(key: string, windowMs: number): Promise<number> {
    const nowMs = Date.now();
    const redisKey = this.composeKey(key);
    const member = buildMember(nowMs);

    const result = await this.client.eval(
      SLIDING_WINDOW_LUA,
      1,
      redisKey,
      nowMs,
      windowMs,
      member
    );

    const count = typeof result === 'string' ? Number(result) : result;
    if (!Number.isFinite(count)) {
      throw new Error('Redis returned non-numeric sliding-window count');
    }

    return count;
  }

  private composeKey(key: string): string {
    const safe = sanitizeKeyPart(key);
    const full = `${this.keyPrefix}:${safe}`;
    if (full.length <= this.maxKeyLength) {
      return full;
    }
    return full.slice(0, this.maxKeyLength);
  }
}

export function createRedisStateProvider(
  client: RedisEvalClient,
  options?: RedisStateProviderOptions
): RedisSlidingWindowStateProvider {
  return new RedisSlidingWindowStateProvider(client, options);
}