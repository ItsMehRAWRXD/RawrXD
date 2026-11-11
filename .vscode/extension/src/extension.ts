// extension.ts
// VS Code Extension for RawrXD Debugger
// ============================================================================
// This extension registers the RawrXD debug adapter with VS Code
// ============================================================================

import * as vscode from 'vscode';
import * as path from 'path';
import * as os from 'os';

export function activate(context: vscode.ExtensionContext) {
    console.log('RawrXD Debugger extension activated');

    // Register debug adapter descriptor factory
    context.subscriptions.push(
        vscode.debug.registerDebugAdapterDescriptorFactory('rawrxd-debug', {
            createDebugAdapterDescriptor(session: vscode.DebugSession) {
                const config = vscode.workspace.getConfiguration('rawrxd-debug');
                const debuggerPath = config.get<string>('debuggerPath') || 
                    path.join('d:', 'rawrxd', 'bin', 'BeaconDebugger.exe');
                
                // Use the Node.js launcher script
                const launcherPath = path.join('d:', 'rawrxd', 'dap-server-launcher.js');
                
                console.log(`Starting RawrXD debugger: ${debuggerPath}`);
                console.log(`Using launcher: ${launcherPath}`);
                
                // Return executable descriptor
                return new vscode.DebugAdapterExecutable(
                    'node',
                    [launcherPath, debuggerPath],
                    { cwd: session.configuration.cwd || vscode.workspace.rootPath }
                );
            }
        })
    );

    // Register configuration provider
    context.subscriptions.push(
        vscode.debug.registerDebugConfigurationProvider('rawrxd-debug', {
            provideDebugConfigurations(folder: vscode.WorkspaceFolder | undefined) {
                return [
                    {
                        type: 'rawrxd-debug',
                        request: 'launch',
                        name: 'RawrXD: Launch Program',
                        program: '${workspaceFolder}/Victim.exe',
                        args: [],
                        stopOnEntry: true,
                        cwd: '${workspaceFolder}',
                        verbose: false
                    }
                ];
            },
            
            resolveDebugConfiguration(folder: vscode.WorkspaceFolder | undefined, 
                                      config: vscode.DebugConfiguration) {
                // Validate configuration
                if (!config.program) {
                    vscode.window.showErrorMessage('Debug configuration missing "program" property');
                    return undefined;
                }
                
                // Set defaults
                if (config.stopOnEntry === undefined) {
                    config.stopOnEntry = true;
                }
                if (config.cwd === undefined) {
                    config.cwd = '${workspaceFolder}';
                }
                
                return config;
            }
        })
    );

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd-debug.toggleBreakpoint', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const line = editor.selection.active.line + 1; // 1-based
                vscode.debug.addBreakpoints([
                    new vscode.SourceBreakpoint(
                        new vscode.Location(
                            editor.document.uri,
                            new vscode.Position(line - 1, 0)
                        )
                    )
                ]);
            }
        })
    );

    // Status bar item
    const statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Left,
        100
    );
    statusBarItem.text = "$(debug) RawrXD";
    statusBarItem.tooltip = "RawrXD Debugger Ready";
    statusBarItem.command = 'workbench.action.debug.start';
    statusBarItem.show();
    
    context.subscriptions.push(statusBarItem);

    // Listen for debug events
    vscode.debug.onDidStartDebugSession(session => {
        console.log(`Debug session started: ${session.name}`);
        vscode.window.showInformationMessage(`RawrXD: Debugging ${session.name}`);
    });

    vscode.debug.onDidTerminateDebugSession(session => {
        console.log(`Debug session ended: ${session.name}`);
        vscode.window.showInformationMessage(`RawrXD: Debug session ended`);
    });
}

export function deactivate() {
    console.log('RawrXD Debugger extension deactivated');
}
