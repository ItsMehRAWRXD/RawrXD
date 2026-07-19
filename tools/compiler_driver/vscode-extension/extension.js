// RAWRXD Compiler Driver - VS Code Extension
// Zero-dependency JavaScript extension
// Works out of the box - no npm/build required

const vscode = require('vscode');
const path = require('path');
const child_process = require('child_process');

// Extension activation
function activate(context) {
    console.log('RAWRXD Compiler Driver extension activated');
    
    // Register compile command
    let compileCommand = vscode.commands.registerCommand('rawrxd.compile', compileCurrentFile);
    context.subscriptions.push(compileCommand);
    
    // Register build command
    let buildCommand = vscode.commands.registerCommand('rawrxd.build', buildProject);
    context.subscriptions.push(buildCommand);
    
    // Register clean command
    let cleanCommand = vscode.commands.registerCommand('rawrxd.clean', cleanBuild);
    context.subscriptions.push(cleanCommand);
    
    // Register list backends command
    let listCommand = vscode.commands.registerCommand('rawrxd.listBackends', listBackends);
    context.subscriptions.push(listCommand);
    
    // Create output channel
    const outputChannel = vscode.window.createOutputChannel('RAWRXD Compiler');
    context.subscriptions.push(outputChannel);
    
    // Create diagnostic collection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('rawrxd');
    context.subscriptions.push(diagnosticCollection);
    
    // Register task provider
    const taskProvider = vscode.tasks.registerTaskProvider('rawrxd', {
        provideTasks: () => {
            return [
                new vscode.Task(
                    { type: 'rawrxd', task: 'compile' },
                    vscode.TaskScope.Workspace,
                    'Compile Current File',
                    'rawrxd',
                    new vscode.ShellExecution('rawrxd-compiler compile ${file}'),
                    ['$rawrxd']
                ),
                new vscode.Task(
                    { type: 'rawrxd', task: 'build' },
                    vscode.TaskScope.Workspace,
                    'Build Project',
                    'rawrxd',
                    new vscode.ShellExecution('rawrxd-compiler build'),
                    ['$rawrxd']
                )
            ];
        },
        resolveTask: (task) => task
    });
    context.subscriptions.push(taskProvider);
    
    // Store globals for commands
    global.rawrxdOutputChannel = outputChannel;
    global.rawrxdDiagnosticCollection = diagnosticCollection;
}

// Compile current file
async function compileCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showErrorMessage('No active editor');
        return;
    }
    
    const document = editor.document;
    const filePath = document.fileName;
    const ext = path.extname(filePath).toLowerCase();
    
    // Check if supported
    const supported = ['.c', '.h', '.asm', '.s', '.cs'];
    if (!supported.includes(ext)) {
        vscode.window.showErrorMessage(`Unsupported file type: ${ext}`);
        return;
    }
    
    // Save if dirty
    if (document.isDirty) {
        await document.save();
    }
    
    const outputChannel = global.rawrxdOutputChannel;
    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine(`Compiling: ${path.basename(filePath)}`);
    
    // Get configuration
    const config = vscode.workspace.getConfiguration('rawrxd');
    const compilerPath = config.get('compilerPath', 'rawrxd-compiler');
    
    // Build command
    let cmd = `"${compilerPath}" compile "${filePath}"`;
    
    if (config.get('optimize', false)) cmd += ' -O';
    if (config.get('debugInfo', true)) cmd += ' -g';
    if (config.get('verbose', false)) cmd += ' -v';
    
    // Execute
    try {
        const result = child_process.execSync(cmd, { 
            encoding: 'utf8',
            cwd: vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath,
            timeout: 60000
        });
        
        outputChannel.appendLine(result);
        vscode.window.showInformationMessage(`Compiled: ${path.basename(filePath)}`);
        
        // Parse diagnostics
        parseDiagnostics(filePath, result);
        
    } catch (error) {
        const output = error.stdout || '';
        const stderr = error.stderr || '';
        outputChannel.appendLine(output + stderr);
        
        parseDiagnostics(filePath, output + stderr);
        vscode.window.showErrorMessage(`Compilation failed: ${path.basename(filePath)}`);
    }
}

// Build project
async function buildProject() {
    const outputChannel = global.rawrxdOutputChannel;
    outputChannel.clear();
    outputChannel.show();
    outputChannel.appendLine('Building project...');
    
    const config = vscode.workspace.getConfiguration('rawrxd');
    const compilerPath = config.get('compilerPath', 'rawrxd-compiler');
    
    try {
        const result = child_process.execSync(`"${compilerPath}" build`, {
            encoding: 'utf8',
            cwd: vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath,
            timeout: 120000
        });
        
        outputChannel.appendLine(result);
        vscode.window.showInformationMessage('Project built successfully');
        
    } catch (error) {
        outputChannel.appendLine(error.stdout || '');
        outputChannel.appendLine(error.stderr || '');
        vscode.window.showErrorMessage('Project build failed');
    }
}

// Clean build
async function cleanBuild() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) return;
    
    const buildDir = path.join(workspaceFolders[0].uri.fsPath, 'build');
    
    try {
        // Remove build directory
        const fs = require('fs');
        if (fs.existsSync(buildDir)) {
            fs.rmSync(buildDir, { recursive: true });
        }
        vscode.window.showInformationMessage('Build cleaned');
    } catch (error) {
        vscode.window.showWarningMessage('Could not clean build directory');
    }
}

// List backends
async function listBackends() {
    const config = vscode.workspace.getConfiguration('rawrxd');
    const compilerPath = config.get('compilerPath', 'rawrxd-compiler');
    
    try {
        const result = child_process.execSync(`"${compilerPath}" list-backends`, {
            encoding: 'utf8',
            timeout: 10000
        });
        
        // Show in output panel
        const outputChannel = global.rawrxdOutputChannel;
        outputChannel.clear();
        outputChannel.show();
        outputChannel.appendLine('RAWRXD Compiler Backends');
        outputChannel.appendLine('========================');
        outputChannel.appendLine(result);
        
    } catch (error) {
        vscode.window.showErrorMessage('Failed to list backends');
    }
}

// Parse diagnostics from output
function parseDiagnostics(filePath, output) {
    const diagnosticCollection = global.rawrxdDiagnosticCollection;
    const diagnostics = [];
    
    // Pattern: file(line,column): severity code: message
    const pattern = /^(.*)\((\d+),(\d+)\):\s*(error|warning|info)\s*(\w+):\s*(.*)$/gm;
    let match;
    
    while ((match = pattern.exec(output)) !== null) {
        const [, file, line, col, severity, code, message] = match;
        
        const range = new vscode.Range(
            parseInt(line) - 1,
            parseInt(col) - 1,
            parseInt(line) - 1,
            parseInt(col)
        );
        
        let severityLevel;
        switch (severity.toLowerCase()) {
            case 'error': severityLevel = vscode.DiagnosticSeverity.Error; break;
            case 'warning': severityLevel = vscode.DiagnosticSeverity.Warning; break;
            default: severityLevel = vscode.DiagnosticSeverity.Information;
        }
        
        const diagnostic = new vscode.Diagnostic(range, message, severityLevel);
        diagnostic.code = code;
        diagnostics.push(diagnostic);
    }
    
    const uri = vscode.Uri.file(filePath);
    diagnosticCollection.set(uri, diagnostics);
}

// Extension deactivation
function deactivate() {
    console.log('RAWRXD Compiler Driver extension deactivated');
}

module.exports = { activate, deactivate };
