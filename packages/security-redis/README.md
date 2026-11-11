# @rawrxd/security-redis

Redis-backed distributed `StateProvider` for `@rawrxd/security-engine`.

## Design

- Uses atomic `EVAL` Lua script for sliding-window counting.
- No `GET`/`SET` race window.
- Compatible with horizontal scaling (shared Redis state).

## Usage

```ts
import Redis from 'ioredis';
import { SecuritySDK } from '@rawrxd/security-engine';
import { createRedisStateProvider } from '@rawrxd/security-redis';

const redis = new Redis(process.env.REDIS_URL!);
const stateProvider = createRedisStateProvider(redis, {
  keyPrefix: 'rawrxd:security:rate'
});

const sdk = new SecuritySDK(
  {
    rules: {
      rateLimit: { window: '1m', max: 100, keyBy: 'ip+path' }
    }
  },
  stateProvider
);
```

## Redis Contract

Your Redis client only needs:

```ts
interface RedisEvalClient {
  eval(script: string, numKeys: number, ...args: Array<string | number>): Promise<number | string>;
}
```

This keeps the provider decoupled from a specific Redis library.