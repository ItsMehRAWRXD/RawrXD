import { ChildProcess, spawn } from 'node:child_process';
import path from 'node:path';
import type { ExtensionRuntimeSpec } from './types';

export interface SpawnedExtension {
  process: ChildProcess;
  extensionId: string;
  entryFile: string;
}

function buildIsolatedEnv(allowEnvKeys: string[], pipeName?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of allowEnvKeys) {
    if (process.env[key] != null) {
      env[key] = process.env[key];
    }
  }
  if (pipeName) {
    env['RAWRXD_PIPE_NAME'] = pipeName;
  }
  return env;
}

export class ProcessBroker {
  private readonly children = new Map<string, SpawnedExtension>();

  public spawnExtension(spec: ExtensionRuntimeSpec): SpawnedExtension {
    if (this.children.has(spec.extensionId)) {
      throw new Error(`Extension already running: ${spec.extensionId}`);
    }

    const runtimePath = spec.runtimePath ?? process.execPath;
    const cwd = spec.workingDirectory ?? path.dirname(spec.entryFile);
    const allowEnvKeys = spec.allowEnvKeys ?? ['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP'];

    const child = spawn(runtimePath, [spec.entryFile, ...(spec.args ?? [])], {
      cwd,
      env: buildIsolatedEnv(allowEnvKeys, spec.pipeName),
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      detached: false,
    });

    const launched: SpawnedExtension = {
      process: child,
      extensionId: spec.extensionId,
      entryFile: spec.entryFile,
    };

    this.children.set(spec.extensionId, launched);
    child.on('exit', () => {
      this.children.delete(spec.extensionId);
    });

    return launched;
  }

  public terminateExtension(extensionId: string): boolean {
    const child = this.children.get(extensionId);
    if (!child) {
      return false;
    }
    child.process.kill();
    this.children.delete(extensionId);
    return true;
  }

  public terminateAll(): void {
    for (const extensionId of Array.from(this.children.keys())) {
      this.terminateExtension(extensionId);
    }
  }

  public listRunning(): string[] {
    return Array.from(this.children.keys());
  }
}
