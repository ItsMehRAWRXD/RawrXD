import type { StateProvider } from './types';

interface CounterEntry {
  count: number;
  expiresAt: number;
}

export class InMemoryStateProvider implements StateProvider {
  private counters = new Map<string, CounterEntry>();

  public async incrementCounter(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const existing = this.counters.get(key);

    if (!existing || existing.expiresAt <= now) {
      this.counters.set(key, { count: 1, expiresAt: now + windowMs });
      return 1;
    }

    existing.count += 1;
    return existing.count;
  }
}

const DURATION_PATTERN = /^(\d+)(ms|s|m|h)$/;

export function parseDurationToMs(input: string): number {
  const match = DURATION_PATTERN.exec(input.trim());
  if (!match) {
    throw new Error(`Invalid duration format: ${input}`);
  }

  const value = Number(match[1]);
  const unit = match[2];

  if (unit === 'ms') {
    return value;
  }
  if (unit === 's') {
    return value * 1000;
  }
  if (unit === 'm') {
    return value * 60 * 1000;
  }
  return value * 60 * 60 * 1000;
}