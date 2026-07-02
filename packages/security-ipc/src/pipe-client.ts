// SovereignPipeClient — extension-side JSON-RPC over Windows Named Pipes.
// Connects to the broker's kernel-gated pipe and exposes a request/response API.

import { connect, Socket } from 'node:net';
import { randomUUID } from 'node:crypto';
import { readFrame, writeFrame } from './protocol';
import { JsonRpcMessage, JsonRpcRequest, JsonRpcSuccess, JsonRpcError, parseJsonRpc, serializeJsonRpc } from './index';

export interface PipeClientOptions {
  pipeName: string;
  onNotification?: (msg: JsonRpcMessage) => void;
}

export class SovereignPipeClient {
  private socket: Socket | null = null;
  private pending = new Map<string, { resolve: (v: JsonRpcSuccess) => void; reject: (e: Error) => void }>();
  private readonly options: PipeClientOptions;
  private pumpRunning = false;

  constructor(options: PipeClientOptions) {
    this.options = options;
  }

  public async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = connect(this.options.pipeName, () => {
        this.socket = socket;
        this.startPump();
        resolve();
      });

      socket.once('error', (err: Error) => {
        reject(new Error(`SovereignPipeClient: connection failed — ${err.message}`));
      });
    });
  }

  public disconnect(): void {
    this.socket?.destroy();
    this.socket = null;
    for (const [, { reject }] of this.pending) {
      reject(new Error('SovereignPipeClient: disconnected before response'));
    }
    this.pending.clear();
  }

  public async request<TParams = unknown, TResult = unknown>(
    method: string,
    params?: TParams
  ): Promise<TResult> {
    if (!this.socket || this.socket.destroyed) {
      throw new Error('SovereignPipeClient: not connected');
    }

    const id = randomUUID();
    const req: JsonRpcRequest<TParams> = { jsonrpc: '2.0', method, params, id };

    return new Promise((resolve, reject) => {
      this.pending.set(id, {
        resolve: (success: JsonRpcSuccess) => resolve(success.result as TResult),
        reject: (e: Error) => reject(e),
      });
      writeFrame(this.socket!, serializeJsonRpc(req)).catch((err) => {
        this.pending.delete(id);
        reject(err);
      });
    });
  }

  private startPump(): void {
    if (this.pumpRunning) return;
    this.pumpRunning = true;

    const loop = async () => {
      try {
        while (this.socket && !this.socket.destroyed) {
          const line = await readFrame(this.socket);
          const msg = parseJsonRpc(line);

          if ('id' in msg && msg.id !== undefined && msg.id !== null) {
            const pending = this.pending.get(msg.id);
            if (pending) {
              this.pending.delete(msg.id);
              if ('error' in msg) {
                const errMsg = msg as JsonRpcError;
                pending.reject(new Error(`JSON-RPC error ${errMsg.error.code}: ${errMsg.error.message}`));
              } else {
                pending.resolve(msg as JsonRpcSuccess);
              }
            }
          } else {
            this.options.onNotification?.(msg);
          }
        }
      } catch {
        // Frame error or disconnect — clean up pending requests.
      } finally {
        this.pumpRunning = false;
        for (const [, { reject }] of this.pending) {
          reject(new Error('SovereignPipeClient: pump terminated'));
        }
        this.pending.clear();
      }
    };

    loop();
  }
}
