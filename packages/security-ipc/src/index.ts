export interface JsonRpcRequest<TParams = unknown> {
  jsonrpc: '2.0';
  method: string;
  params?: TParams;
  id: string;
}

export interface JsonRpcNotification<TParams = unknown> {
  jsonrpc: '2.0';
  method: string;
  params?: TParams;
}

export interface JsonRpcSuccess<TResult = unknown> {
  jsonrpc: '2.0';
  result: TResult;
  id: string;
}

export interface JsonRpcErrorBody {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcError {
  jsonrpc: '2.0';
  error: JsonRpcErrorBody;
  id: string | null;
}

export type JsonRpcMessage =
  | JsonRpcRequest
  | JsonRpcNotification
  | JsonRpcSuccess
  | JsonRpcError;

export function serializeJsonRpc(message: JsonRpcMessage): string {
  return `${JSON.stringify(message)}\n`;
}

export function parseJsonRpc(line: string): JsonRpcMessage {
  const parsed = JSON.parse(line) as JsonRpcMessage;
  if (!parsed || (parsed as { jsonrpc?: string }).jsonrpc !== '2.0') {
    throw new Error('Invalid JSON-RPC message');
  }
  return parsed;
}

export const IPC_METHODS = {
  ReadWorkspaceFile: 'ReadWorkspaceFile',
  ListWorkspaceDir: 'ListWorkspaceDir',
  ProposePatch: 'ProposePatch',
  RequestAuth: 'RequestAuth',
} as const;

export type IpcMethod = (typeof IPC_METHODS)[keyof typeof IPC_METHODS];

// Sovereign Pipe Transport
export { SovereignPipeServer, type PipeServerOptions } from './pipe-server';
export { SovereignPipeClient, type PipeClientOptions } from './pipe-client';
export { readFrame, writeFrame, type SovereignFrame } from './protocol';
