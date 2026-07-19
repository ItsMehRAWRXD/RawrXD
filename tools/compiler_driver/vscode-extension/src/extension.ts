import * as vscode from 'vscode';
import * as path from 'path';
import * as child_process from 'child_process';
import { promisify } from 'util';

const exec = promisify(child_process.exec);

// RAWRXD Compiler Driver Extension
// Provides IDE integration for the unified compiler driver

let outputChannel: vscode.OutputChannel;
let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('RAWRXD Compiler');
    diagnosticCollection = vscode.languages.createDiagnosticCollection('rawrxd');

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd.compile', compileCurrentFile),
        vscode.commands.registerCommand('rawrxd.compileProject', compileProject),
        vscode.commands.registerCommand('rawrxd.clean', cleanBuild),
        vscode.commands.registerCommand('rawrxd.listBackends', listBackends),
        vscode.commands.registerCommand('rawrxd.runTests', runSmokeTests)
    );

    // Register task provider
    context.subscriptions.push(
        vscode.tasks.registerTaskProvider('rawrxd', new RAWRXDTaskProvider())
    );

    outputChannel.appendLine('RAWRXD Compiler Driver extension activated');
}

export function deactivate() {
    diagnosticCollection.dispose();
    outputChannel.dispose();
}

// Get compiler path from configuration
function getCompilerPath(): string {
    const config = vscode.workspace.getConfiguration('rawrxd');
    return config.get<string>('compilerPath', 'rawrxd-compiler.exe');
}

// Compile current file
async function compileCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }

    const document = editor.document;
    const filePath = document.fileName;

    // Check if file is supported
    const ext = path.extname(filePath).toLowerCase();
    const supportedExts = ['.c', '.h', '.asm', '.s', '.cs'];
    if (!supportedExts.includes(ext)) {
        vscode.window.showErrorMessage(`Unsupported file type: ${ext}`);
        return;
    }

    // Save document if modified
    if (document.isDirty) {
        await document.save();
    }

    const config = vscode.workspace.getConfiguration('rawrxd');
    const compilerPath = getCompilerPath();
    
    // Build command
    let cmd = `"${compilerPath}" compile "${filePath}"`;
    
    if (config.get<boolean>('optimize', false)) {
        cmd += ' -O';
    }
    if (config.get<boolean>('debugInfo', true)) {
        cmd += ' -g';
    }
    if (config.get<boolean>('verbose', false)) {
        cmd += ' -v';
    }

    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine(`Compiling: ${path.basename(filePath)}`);
    outputChannel.appendLine(`Command: ${cmd}`);
    outputChannel.appendLine('');

    try {
        const { stdout, stderr } = await exec(cmd, { 
            cwd: vscode.workspace.workspaceFolders?.[0].uri.fsPath,
            timeout: 60000 
        });

        outputChannel.appendLine(stdout);
        if (stderr) {
            outputChannel.appendLine(stderr);
        }

        // Parse diagnostics
        parseDiagnostics(filePath, stdout + stderr);

        vscode.window.showInformationMessage(`Compiled successfully: ${path.basename(filePath)}`);
    } catch (error: any) {
        outputChannel.appendLine(error.stdout || '');
        outputChannel.appendLine(error.stderr || '');
        
        parseDiagnostics(filePath, (error.stdout || '') + (error.stderr || ''));
        
        vscode.window.showErrorMessage(`Compilation failed: ${path.basename(filePath)}`);
    }
}

// Compile entire project
async function compileProject(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    const compilerPath = getCompilerPath();
    const cmd = `"${compilerPath}" build`;

    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine('Building project...');
    outputChannel.appendLine(`Command: ${cmd}`);
    outputChannel.appendLine('');

    try {
        const { stdout, stderr } = await exec(cmd, {
            cwd: workspaceFolders[0].uri.fsPath,
            timeout: 120000
        });

        outputChannel.appendLine(stdout);
        if (stderr) {
            outputChannel.appendLine(stderr);
        }

        vscode.window.showInformationMessage('Project built successfully');
    } catch (error: any) {
        outputChannel.appendLine(error.stdout || '');
        outputChannel.appendLine(error.stderr || '');
        vscode.window.showErrorMessage('Project build failed');
    }
}

// Clean build artifacts
async function cleanBuild(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showErrorMessage('No workspace folder open');
        return;
    }

    // Remove build directory
    const buildDir = path.join(workspaceFolders[0].uri.fsPath, 'build');
    
    try {
        await exec(`rmdir /S /Q "${buildDir}" 2>nul || echo No build directory`);
        vscode.window.showInformationMessage('Build cleaned');
    } catch (error) {
        vscode.window.showWarningMessage('Could not clean build directory');
    }
}

// List available backends
async function listBackends(): Promise<void> {
    const compilerPath = getCompilerPath();
    const cmd = `"${compilerPath}" list-backends`;

    try {
        const { stdout } = await exec(cmd);
        
        const panel = vscode.window.createWebviewPanel(
            'rawrxdBackends',
            'RAWRXD Compiler Backends',
            vscode.ViewColumn.One,
            {}
        );

        panel.webview.html = `
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body { font-family: sans-serif; padding: 20px; }
                    h1 { color: #333; }
                    pre { background: #f4f4f4; padding: 15px; border-radius: 5px; }
                </style>
            </head>
            <body>
                <h1>RAWRXD Compiler Backends</h1>
                <pre>${stdout}</pre>
            </body>
            </html>
        `;
    } catch (error) {
        vscode.window.showErrorMessage('Failed to list backends');
    }
}

// Run smoke tests
async function runSmokeTests(): Promise<void> {
    const compilerPath = getCompilerPath();
    const testScript = path.join(path.dirname(compilerPath), '..', 'tests', 'smoke_test.bat');

    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine('Running smoke tests...');
    outputChannel.appendLine('');

    try {
        const { stdout, stderr } = await exec(`"${testScript}"`, { timeout: 120000 });
        outputChannel.appendLine(stdout);
        if (stderr) {
            outputChannel.appendLine(stderr);
        }

        if (stdout.includes('[SUCCESS]')) {
            vscode.window.showInformationMessage('All smoke tests passed!');
        } else {
            vscode.window.showWarningMessage('Some smoke tests failed');
        }
    } catch (error: any) {
        outputChannel.appendLine(error.stdout || '');
        outputChannel.appendLine(error.stderr || '');
        vscode.window.showErrorMessage('Smoke tests failed');
    }
}

// Parse diagnostics from compiler output
function parseDiagnostics(filePath: string, output: string): void {
    const diagnostics: vscode.Diagnostic[] = [];
    const lines = output.split('\n');

    // Pattern: file(line,column): severity code: message
    const pattern = /^(.*)\((\d+),(\d+)\):\s*(error|warning|info)\s*(\w+):\s*(.*)$/;

    for (const line of lines) {
        const match = line.match(pattern);
        if (match) {
            const [, file, lineNum, colNum, severity, code, message] = match;
            
            const range = new vscode.Range(
                parseInt(lineNum) - 1,
                parseInt(colNum) - 1,
                parseInt(lineNum) - 1,
                parseInt(colNum)
            );

            let severityLevel: vscode.DiagnosticSeverity;
            switch (severity.toLowerCase()) {
                case 'error':
                    severityLevel = vscode.DiagnosticSeverity.Error;
                    break;
                case 'warning':
                    severityLevel = vscode.DiagnosticSeverity.Warning;
                    break;
                default:
                    severityLevel = vscode.DiagnosticSeverity.Information;
            }

            const diagnostic = new vscode.Diagnostic(range, message, severityLevel);
            diagnostic.code = code;
            diagnostics.push(diagnostic);
        }
    }

    const uri = vscode.Uri.file(filePath);
    diagnosticCollection.set(uri, diagnostics);
}

// Task Provider
class RAWRXDTaskProvider implements vscode.TaskProvider {
    provideTasks(): vscode.Task[] {
        const tasks: vscode.Task[] = [];
        
        // Compile task
        const compileTask = new vscode.Task(
            { type: 'rawrxd', task: 'compile' },
            vscode.TaskScope.Workspace,
            'Compile Current File',
            'rawrxd',
            new vscode.ShellExecution('rawrxd-compiler compile ${file}'),
            ['$rawrxd']
        );
        tasks.push(compileTask);

        // Build task
        const buildTask = new vscode.Task(
            { type: 'rawrxd', task: 'build' },
            vscode.TaskScope.Workspace,
            'Build Project',
            'rawrxd',
            new vscode.ShellExecution('rawrxd-compiler build'),
            ['$rawrxd']
        );
        tasks.push(buildTask);

        return tasks;
    }

    resolveTask(task: vscode.Task): vscode.Task | undefined {
        return task;
    }
}
