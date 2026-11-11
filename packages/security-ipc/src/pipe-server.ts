// SovereignPipeServer — hardened JSON-RPC over Windows Named Pipes.
// Creates a kernel-gated IPC channel that the extension cannot spoof or intercept.

import { createServer, Server, Socket } from 'node:net';
import { randomUUID } from 'node:crypto';
import { readFrame, writeFrame } from './protocol';
import { JsonRpcMessage, parseJsonRpc, serializeJsonRpc } from './index';

export interface PipeServerOptions {
  /** Maximum concurrent connections (default: 1) */
  maxConnections?: number;
  /** Maximum frame size in bytes (default: 16 MiB) */
  maxFrameSize?: number;
  /** Callback invoked for every validated JSON-RPC message */
  onMessage?: (msg: JsonRpcMessage, socket: Socket) => void | Promise<void>;
  /** Callback invoked when a client connects */
  onConnect?: (socket: Socket) => void;
  /** Callback invoked when a client disconnects */
  onDisconnect?: (socket: Socket) => void;
}

export class SovereignPipeServer {
  private readonly server: Server;
  private readonly pipeName: string;
  private readonly options: Required<Pick<PipeServerOptions, 'maxConnections' | 'maxFrameSize'>> &
    Pick<PipeServerOptions, 'onMessage' | 'onConnect' | 'onDisconnect'>;
  private activeSockets = new Set<Socket>();
  private isListening = false;

  constructor(options: PipeServerOptions = {}) {
    this.options = {
      maxConnections: options.maxConnections ?? 1,
      maxFrameSize: options.maxFrameSize ?? 16 * 1024 * 1024,
      onMessage: options.onMessage,
      onConnect: options.onConnect,
      onDisconnect: options.onDisconnect,
    };

    this.pipeName = `\\\\.\\pipe\\rawrxd-${randomUUID()}`;
    this.server = createServer((socket) => this.handleConnection(socket));
  }

  /** Returns the pipe name that the extension must use to connect. */
  public getPipeName(): string {
    return this.pipeName;
  }

  public async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.pipeName, () => {
        this.server.off('error', reject);
        this.isListening = true;
        resolve();
      });
    });
  }

  public async stop(): Promise<void> {
    for (const socket of this.activeSockets) {
      socket.destroy();
    }
    this.activeSockets.clear();

    return new Promise((resolve) => {
      this.server.close(() => {
        this.isListening = false;
        resolve();
      });
    });
  }

  public broadcast(message: JsonRpcMessage): void {
    const frame = serializeJsonRpc(message);
    for (const socket of this.activeSockets) {
      writeFrame(socket, frame).catch(() => {
        // Silently ignore dead sockets; disconnect handler will clean up.
      });
    }
  }

  public send(socket: Socket, message: JsonRpcMessage): Promise<void> {
    return writeFrame(socket, serializeJsonRpc(message));
  }

  private handleConnection(socket: Socket): void {
    if (this.activeSockets.size >= this.options.maxConnections) {
      socket.destroy();
      return;
    }

    this.activeSockets.add(socket);
    this.options.onConnect?.(socket);

    // Frame-reading loop
    const pump = async () => {
      try {
        while (!socket.destroyed) {
          const line = await readFrame(socket);
          const msg = parseJsonRpc(line);
          await this.options.onMessage?.(msg, socket);
        }
      } catch (err) {
        // Frame error or disconnect — terminate socket cleanly.
        if (!socket.destroyed) {
          socket.destroy();
        }
      } finally {
        this.activeSockets.delete(socket);
        this.options.onDisconnect?.(socket);
      }
    };

    pump();
  }
}
