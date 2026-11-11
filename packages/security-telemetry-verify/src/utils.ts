function sortObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortObjectKeys);
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const out: Record<string, unknown> = {};

  for (const key of sortedKeys) {
    out[key] = sortObjectKeys(obj[key]);
  }

  return out;
}

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function decodeBase64ToBytes(base64: string): Uint8Array {
  let clean = base64.replace(/\s+/g, '');
  while (clean.length % 4 !== 0) {
    clean += '=';
  }

  const output: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const c1 = BASE64_CHARS.indexOf(clean[i]);
    const c2 = BASE64_CHARS.indexOf(clean[i + 1]);
    const c3 = clean[i + 2] === '=' ? -1 : BASE64_CHARS.indexOf(clean[i + 2]);
    const c4 = clean[i + 3] === '=' ? -1 : BASE64_CHARS.indexOf(clean[i + 3]);

    if (c1 < 0 || c2 < 0 || (c3 < 0 && clean[i + 2] !== '=') || (c4 < 0 && clean[i + 3] !== '=')) {
      throw new Error('Invalid base64 input');
    }

    const b1 = (c1 << 2) | (c2 >> 4);
    output.push(b1 & 0xff);

    if (c3 >= 0) {
      const b2 = ((c2 & 0x0f) << 4) | (c3 >> 2);
      output.push(b2 & 0xff);
    }

    if (c4 >= 0) {
      const b3 = ((c3 & 0x03) << 6) | c4;
      output.push(b3 & 0xff);
    }
  }

  return new Uint8Array(output);
}

function encodeBytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b1 = bytes[i];
    const b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    const n = (b1 << 16) | (b2 << 8) | b3;
    const c1 = (n >> 18) & 0x3f;
    const c2 = (n >> 12) & 0x3f;
    const c3 = (n >> 6) & 0x3f;
    const c4 = n & 0x3f;

    out += BASE64_CHARS[c1] + BASE64_CHARS[c2];
    out += i + 1 < bytes.length ? BASE64_CHARS[c3] : '=';
    out += i + 2 < bytes.length ? BASE64_CHARS[c4] : '=';
  }

  return out;
}

export function canonicalSerialize(value: unknown): string {
  return JSON.stringify(sortObjectKeys(value));
}

export function decodeBase64Url(input: string): Uint8Array {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  return decodeBase64ToBytes(normalized);
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return encodeBytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}