// Debug Adapter for RawrXD Native Toolchain
// Bridges VS Code DAP to DebugIntegration.cpp DAP server

import * as vscode from 'vscode';
import { spawn, ChildProcess } from 'child_process';
import * as path from 'path';

export class RawrXDDebugAdapter {
    private dapProcess: ChildProcess | undefined;
    private outputChannel: vscode.OutputChannel;
    private nextSeq = 1;
    private pendingRequests = new Map<number, (response: any) => void>();
    private breakpoints = new Map<string, number[]>();

    constructor() {
        this.outputChannel = vscode.window.createOutputChannel('RawrXD Debug');
    }

    async startDebugSession(program: string, cwd: string, stopOnEntry: boolean): Promise<void> {
        this.outputChannel.clear();
        this.outputChannel.show();
        this.outputChannel.appendLine(`🐛 Starting debug session for ${path.basename(program)}...`);

        // Start the DAP server from DebugIntegration.cpp
        const dapServerPath = 'd:\\rawrxd\\build\\bin\\RawrXD_Win32IDE.exe';
        
        this.dapProcess = spawn(dapServerPath, ['--dap-server'], {
            stdio: ['pipe', 'pipe', 'pipe'],
            cwd: cwd,
            windowsHide: true
        });

        // Handle DAP server output
        this.dapProcess.stdout?.on('data', (data) => {
            this.handleDAPMessage(data.toString());
        });

        this.dapProcess.stderr?.on('data', (data) => {
            this.outputChannel.appendLine(`[DAP Server] ${data.toString().trim()}`);
        });

        this.dapProcess.on('exit', (code) => {
            this.outputChannel.appendLine(`Debug session ended (exit code: ${code})`);
        });

        // Send initialize request
        await this.sendRequest('initialize', {
            clientID: 'vscode',
            clientName: 'VS Code',
            adapterID: 'rawrxd',
            pathFormat: 'path',
            linesStartAt1: true,
            columnsStartAt1: true,
            supportsVariableType: true,
            supportsVariablePaging: false,
            supportsRunInTerminalRequest: false,
            locale: 'en'
        });

        // Send configuration done
        await this.sendRequest('configurationDone', {});

        // Send launch request
        await this.sendRequest('launch', {
            program: program,
            cwd: cwd,
            stopOnEntry: stopOnEntry
        });

        this.outputChannel.appendLine('✅ Debug session started');
    }

    async stopDebugSession(): Promise<void> {
        if (this.dapProcess) {
            await this.sendRequest('disconnect', { restart: false });
            this.dapProcess.kill();
            this.dapProcess = undefined;
        }
    }

    async setBreakpoint(file: string, line: number): Promise<void> {
        const response = await this.sendRequest('setBreakpoints', {
            source: { path: file },
            breakpoints: [{ line: line }]
        });

        if (response.breakpoints) {
            const fileBreakpoints = this.breakpoints.get(file) || [];
            fileBreakpoints.push(line);
            this.breakpoints.set(file, fileBreakpoints);
        }
    }

    async clearBreakpoint(file: string, line: number): Promise<void> {
        const fileBreakpoints = this.breakpoints.get(file) || [];
        const index = fileBreakpoints.indexOf(line);
        if (index > -1) {
            fileBreakpoints.splice(index, 1);
        }

        await this.sendRequest('setBreakpoints', {
            source: { path: file },
            breakpoints: fileBreakpoints.map(l => ({ line: l }))
        });
    }

    async continue(): Promise<void> {
        await this.sendRequest('continue', { threadId: 1 });
    }

    async pause(): Promise<void> {
        await this.sendRequest('pause', { threadId: 1 });
    }

    async stepIn(): Promise<void> {
        await this.sendRequest('stepIn', { threadId: 1 });
    }

    async stepOver(): Promise<void> {
        await this.sendRequest('next', { threadId: 1 });
    }

    async stepOut(): Promise<void> {
        await this.sendRequest('stepOut', { threadId: 1 });
    }

    private sendRequest(command: string, args: any): Promise<any> {
        return new Promise((resolve, reject) => {
            if (!this.dapProcess?.stdin) {
                reject(new Error('DAP server not running'));
                return;
            }

            const seq = this.nextSeq++;
            const request = {
                seq: seq,
                type: 'request',
                command: command,
                arguments: args
            };

            this.pendingRequests.set(seq, resolve);

            const message = JSON.stringify(request);
            const header = `Content-Length: ${Buffer.byteLength(message)}\r\n\r\n`;
            
            this.dapProcess.stdin.write(header + message);

            // Timeout after 10 seconds
            setTimeout(() => {
                if (this.pendingRequests.has(seq)) {
                    this.pendingRequests.delete(seq);
                    reject(new Error(`Request ${command} timed out`));
                }
            }, 10000);
        });
    }

    private handleDAPMessage(data: string): void {
        // Parse DAP messages (header + JSON body)
        const messages = this.parseDAPMessages(data);
        
        for (const message of messages) {
            if (message.type === 'response') {
                const callback = this.pendingRequests.get(message.request_seq);
                if (callback) {
                    this.pendingRequests.delete(message.request_seq);
                    callback(message.body);
                }
            } else if (message.type === 'event') {
                this.handleDAPEvent(message);
            }
        }
    }

    private parseDAPMessages(data: string): any[] {
        const messages = [];
        let remaining = data;

        while (remaining.length > 0) {
            // Parse Content-Length header
            const headerMatch = remaining.match(/Content-Length: (\d+)\r\n\r\n/);
            if (!headerMatch) break;

            const contentLength = parseInt(headerMatch[1]);
            const headerLength = headerMatch[0].length;
            const body = remaining.substring(headerLength, headerLength + contentLength);

            try {
                messages.push(JSON.parse(body));
            } catch (e) {
                this.outputChannel.appendLine(`[Error] Failed to parse DAP message: ${e}`);
            }

            remaining = remaining.substring(headerLength + contentLength);
        }

        return messages;
    }

    private handleDAPEvent(event: any): void {
        switch (event.event) {
            case 'stopped':
                this.outputChannel.appendLine(`⏸️ Stopped: ${event.body?.reason || 'unknown'}`);
                break;
            case 'continued':
                this.outputChannel.appendLine('▶️ Continued');
                break;
            case 'output':
                this.outputChannel.appendLine(event.body?.output || '');
                break;
            case 'terminated':
                this.outputChannel.appendLine('🏁 Program terminated');
                break;
        }
    }
}

// Export singleton instance
export const debugAdapter = new RawrXDDebugAdapter();
