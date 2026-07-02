declare namespace NodeJS {
  interface ProcessEnv {
    [key: string]: string | undefined;
  }
}

declare module 'node:path' {
  const api: {
    dirname(input: string): string;
  };
  export = api;
}

declare module 'node:child_process' {
  export interface ChildProcess {
    kill(): void;
    on(event: 'exit', listener: () => void): void;
  }

  export interface SpawnOptions {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    stdio?: string[];
    windowsHide?: boolean;
    detached?: boolean;
  }

  export function spawn(
    command: string,
    args?: string[],
    options?: SpawnOptions
  ): ChildProcess;
}

declare module 'node:assert' {
  export const strict: {
    equal(actual: unknown, expected: unknown, message?: string): void;
    ok(value: unknown, message?: string): void;
  };
}

declare const process: {
  execPath: string;
  env: NodeJS.ProcessEnv;
  stdout: { write(text: string): void };
  stderr: { write(text: string): void };
  exitCode: number;
};

declare class Buffer {
  constructor(value: string | number[] | ArrayBuffer, encoding?: string);
  static from(data: string | number[] | ArrayBuffer, encoding?: string): Buffer;
  static alloc(size: number): Buffer;
  static allocUnsafe(size: number): Buffer;
  static concat(chunks: Buffer[]): Buffer;
  static isBuffer(obj: unknown): boolean;
  length: number;
  toString(encoding?: string): string;
  slice(start?: number, end?: number): Buffer;
  subarray(start?: number, end?: number): Buffer;
  readUInt8(offset: number): number;
  writeUInt8(value: number, offset: number): number;
  readUInt32LE(offset: number): number;
  writeUInt32LE(value: number, offset: number): number;
}
