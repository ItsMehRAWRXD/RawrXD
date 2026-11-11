"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.TerminalIntegration = void 0;
const vscode = __importStar(require("vscode"));
const events_1 = require("events");
/**
 * Terminal integration with streamed output
 * King style - real-time command execution and capture
 */
class TerminalIntegration extends events_1.EventEmitter {
    _terminal;
    _outputBuffer = '';
    _errorBuffer = '';
    _commandRunning = false;
    _currentResolve;
    constructor() {
        super();
    }
    /**
     * Execute a command with streamed output
     */
    async executeCommand(cmd) {
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
            // Listen for terminal output
            const disposable = vscode.window.onDidWriteTerminalData((e) => {
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
    async executeStreaming(cmd, onOutput, onError) {
        return new Promise((resolve, reject) => {
            const output = {
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
            // Capture output
            const disposable = vscode.window.onDidWriteTerminalData((e) => {
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
    async build(cwd) {
        return this.executeCommand({
            command: 'npm run build',
            cwd
        });
    }
    /**
     * Run tests
     */
    async test(cwd, pattern) {
        const cmd = pattern ? `npm test -- ${pattern}` : 'npm test';
        return this.executeCommand({
            command: cmd,
            cwd
        });
    }
    /**
     * Run lint
     */
    async lint(cwd) {
        return this.executeCommand({
            command: 'npm run lint',
            cwd
        });
    }
    /**
     * Check if command is running
     */
    isRunning() {
        return this._commandRunning;
    }
    /**
     * Kill current command
     */
    kill() {
        if (this._terminal) {
            this._terminal.sendText('\u0003', false); // Ctrl+C
            this._commandRunning = false;
        }
    }
    _processOutput(data, marker, endMarker, timeout, resolve) {
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
                output = this._outputBuffer.substring(startIdx + marker.length, endIdx);
            }
            // Parse exit code
            const exitMatch = output.match(/ExitCode:\s*(\d+)/);
            const exitCode = exitMatch ? parseInt(exitMatch[1]) : null;
            // Clean up output
            const cleanOutput = output.replace(/ExitCode:\s*\d+\n?/, '').trim();
            const result = {
                stdout: cleanOutput,
                stderr: this._errorBuffer,
                exitCode
            };
            this.emit('completed', result);
            resolve(result);
        }
    }
    dispose() {
        this.kill();
        this._terminal?.dispose();
        this.removeAllListeners();
    }
}
exports.TerminalIntegration = TerminalIntegration;
//# sourceMappingURL=terminalIntegration.js.map