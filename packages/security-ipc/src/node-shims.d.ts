// Minimal Node.js type shims for security-ipc compilation without @types/node.

declare namespace NodeJS {
  interface ReadableStream {
    on(event: 'data', listener: (chunk: Buffer) => void): void;
    on(event: 'end', listener: () => void): void;
    on(event: 'error', listener: (err: Error) => void): void;
    off(event: 'data', listener: (chunk: Buffer) => void): void;
    off(event: 'end', listener: () => void): void;
    off(event: 'error', listener: (err: Error) => void): void;
    once(event: 'error', listener: (err: Error) => void): void;
  }

  interface WritableStream {
    write(chunk: Buffer | string, cb?: (err?: Error | null) => void): boolean;
    off(event: 'error', listener: (err: Error) => void): void;
    on(event: 'error', listener: (err: Error) => void): void;
    once(event: 'error', listener: (err: Error) => void): void;
  }
}

declare class Buffer {
  constructor(value: string | number[] | ArrayBuffer, encoding?: string);
  static from(data: string | number[] | ArrayBuffer, encoding?: string): Buffer;
  static allocUnsafe(size: number): Buffer;
  static concat(chunks: Buffer[]): Buffer;
  static isBuffer(obj: unknown): boolean;
  length: number;
  toString(encoding?: string): string;
  slice(start?: number, end?: number): Buffer;
  subarray(start?: number, end?: number): Buffer;
  readUInt32LE(offset: number): number;
  writeUInt32LE(value: number, offset: number): number;
}

declare module 'node:net' {
  export interface Socket extends NodeJS.ReadableStream, NodeJS.WritableStream {
    destroyed: boolean;
    destroy(): void;
    once(event: 'error', listener: (err: Error) => void): void;
  }

  export interface Server {
    once(event: 'error', listener: (err: Error) => void): void;
    off(event: 'error', listener: (err: Error) => void): void;
    listen(path: string, callback?: () => void): void;
    close(callback?: () => void): void;
  }

  export function createServer(connectionListener?: (socket: Socket) => void): Server;
  export function connect(path: string, callback?: () => void): Socket;
}

declare module 'node:crypto' {
  export function randomUUID(): string;
}
