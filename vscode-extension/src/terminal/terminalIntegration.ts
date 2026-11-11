import * as vscode from 'vscode';
import { EventEmitter } from 'events';

export interface TerminalCommand {
    command: string;
    cwd?: string;
    env?: { [key: string]: string };
}

export interface TerminalOutput {
    stdout: string;
    stderr: string;
    exitCode: number | null;
}

/**
 * Terminal integration with streamed output
 * King style - real-time command execution and capture
 */
export class TerminalIntegration extends EventEmitter {
    private _terminal: vscode.Terminal | undefined;
    private _outputBuffer: string = '';
    private _errorBuffer: string = '';
    private _commandRunning: boolean = false;
    private _currentResolve: ((value: TerminalOutput) => void) | undefined;

    constructor() {
        super();
    }

    /**
     * Execute a command with streamed output
     */
    async executeCommand(cmd: TerminalCommand): Promise<TerminalOutput> {
        if (this._commandRunning) {
            throw new Error('A command is already running');
        }

        this._commandRunning = true;
        this._outputBuffer = '';
        this._errorBuffer = '';

        // Create or reuse terminal
        if (!this._terminal) {
            this._terminal = vscode.window.createTerminal({
                name: 'RawrXD Agent',
                cwd: cmd.cwd,
                env: cmd.env
            });
        }

        this._terminal.show();

        // Send command with output capture marker
        const marker = `___RAWRXD_CMD_START_${Date.now()}___`;
        const endMarker = `___RAWRXD_CMD_END_${Date.now()}___`;
        
        // Wrap command to capture exit code
        const wrappedCommand = `echo "${marker}" && ${cmd.command}; echo "ExitCode: $?" && echo "${endMarker}"`;
        
        this._terminal.sendText(wrappedCommand);

        return new Promise((resolve, reject) => {
            this._currentResolve = resolve;

            // Set timeout
            const timeout = setTimeout(() => {
                this._commandRunning = false;
                reject(new Error('Command timeout'));
            }, 120000); // 2 minute timeout

            // Listen for terminal output (using proposed API)
            const disposable = (vscode.window as any).onDidWriteTerminalData((e: {terminal: vscode.Terminal, data: string}) => {
                if (e.terminal === this._terminal) {
                    this._processOutput(e.data, marker, endMarker, timeout, resolve);
                }
            });

            // Cleanup on dispose
            this.once('completed', () => {
                disposable.dispose();
            });
        });
    }

    /**
     * Execute command with real-time streaming
     */
    async executeStreaming(
        cmd: TerminalCommand,
        onOutput: (data: string) => void,
        onError: (data: string) => void
    ): Promise<TerminalOutput> {
        return new Promise((resolve, reject) => {
            const output: TerminalOutput = {
                stdout: '',
                stderr: '',
                exitCode: null
            };

            // Create terminal
            const terminal = vscode.window.createTerminal({
                name: 'RawrXD Stream',
                cwd: cmd.cwd,
                env: cmd.env
            });

            terminal.show();

            // Capture output (using proposed API)
            const disposable = (vscode.window as any).onDidWriteTerminalData((e: {terminal: vscode.Terminal, data: string}) => {
                if (e.terminal === terminal) {
                    const data = e.data;
                    output.stdout += data;
                    onOutput(data);
                }
            });

            // Send command
            terminal.sendText(cmd.command);
            terminal.sendText('echo "___EXIT___:$?"');

            // Wait for completion
            const checkInterval = setInterval(() => {
                if (output.stdout.includes('___EXIT___:')) {
                    clearInterval(checkInterval);
                    disposable.dispose();
                    
                    // Parse exit code
                    const match = output.stdout.match(/___EXIT___:(\d+)/);
                    output.exitCode = match ? parseInt(match[1]) : null;
                    output.stdout = output.stdout.replace(/___EXIT___:\d+\n?/, '');
                    
                    resolve(output);
                }
            }, 100);

            // Timeout
            setTimeout(() => {
                clearInterval(checkInterval);
                disposable.dispose();
                terminal.dispose();
                reject(new Error('Command timeout'));
            }, 120000);
        });
    }

    /**
     * Run build command
     */
    async build(cwd?: string): Promise<TerminalOutput> {
        return this.executeCommand({
            command: 'npm run build',
            cwd
        });
    }

    /**
     * Run tests
     */
    async test(cwd?: string, pattern?: string): Promise<TerminalOutput> {
        const cmd = pattern ? `npm test -- ${pattern}` : 'npm test';
        return this.executeCommand({
            command: cmd,
            cwd
        });
    }

    /**
     * Run lint
     */
    async lint(cwd?: string): Promise<TerminalOutput> {
        return this.executeCommand({
            command: 'npm run lint',
            cwd
        });
    }

    /**
     * Check if command is running
     */
    isRunning(): boolean {
        return this._commandRunning;
    }

    /**
     * Kill current command
     */
    kill(): void {
        if (this._terminal) {
            this._terminal.sendText('\u0003', false); // Ctrl+C
            this._commandRunning = false;
        }
    }

    private _processOutput(
        data: string,
        marker: string,
        endMarker: string,
        timeout: NodeJS.Timeout,
        resolve: (value: TerminalOutput) => void
    ): void {
        this._outputBuffer += data;

        // Check for end marker
        if (this._outputBuffer.includes(endMarker)) {
            clearTimeout(timeout);
            this._commandRunning = false;

            // Extract output between markers
            const startIdx = this._outputBuffer.indexOf(marker);
            const endIdx = this._outputBuffer.indexOf(endMarker);
            
            let output = '';
            if (startIdx !== -1 && endIdx !== -1) {
                output = this._outputBuffer.substring(
                    startIdx + marker.length,
                    endIdx
                );
            }

            // Parse exit code
            const exitMatch = output.match(/ExitCode:\s*(\d+)/);
            const exitCode = exitMatch ? parseInt(exitMatch[1]) : null;
            
            // Clean up output
            const cleanOutput = output.replace(/ExitCode:\s*\d+\n?/, '').trim();

            const result: TerminalOutput = {
                stdout: cleanOutput,
                stderr: this._errorBuffer,
                exitCode
            };

            this.emit('completed', result);
            resolve(result);
        }
    }

    dispose(): void {
        this.kill();
        this._terminal?.dispose();
        this.removeAllListeners();
    }
}
