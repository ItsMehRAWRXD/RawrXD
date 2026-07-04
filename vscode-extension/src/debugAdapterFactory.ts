// ============================================================================
// debugAdapterFactory.ts - Debug Adapter Factory
// ============================================================================
// Factory for creating the RawrXD-Script debug adapter
// Handles both launch and attach configurations
//
// Copyright (c) 2026 RawrXD Project
// ============================================================================

import * as vscode from 'vscode';
import * as path from 'path';
import { spawn, ChildProcess } from 'child_process';

export class RawrXDScriptDebugAdapterFactory implements vscode.DebugAdapterDescriptorFactory {
    private outputChannel: vscode.OutputChannel;
    private serverProcess: ChildProcess | undefined;
    private extensionPath: string;

    constructor(outputChannel: vscode.OutputChannel, extensionPath: string) {
        this.outputChannel = outputChannel;
        this.extensionPath = extensionPath;
    }

    createDebugAdapterDescriptor(
        session: vscode.DebugSession,
        executable: vscode.DebugAdapterExecutable | undefined
    ): vscode.ProviderResult<vscode.DebugAdapterDescriptor> {
        const config = session.configuration;
        const workspaceConfig = vscode.workspace.getConfiguration('rawrxd-script');
        
        // Get the debug adapter path
        let adapterPath = workspaceConfig.get<string>('debug.adapterPath', '');
        
        if (!adapterPath) {
            // Try multiple possible locations
            const possiblePaths = [
                // Packaged extension
                path.join(this.extensionPath, 'bin', 'RawrXDScriptDAPAdapter.exe'),
                // Development build
                path.join(this.extensionPath, '..', '..', 'build', 'RawrXDScriptDAPAdapter.exe'),
                // Source tree
                path.join(this.extensionPath, '..', '..', 'src', 'script', 'debug', 'RawrXDScriptDAPAdapter.exe'),
            ];
            
            const fs = require('fs');
            for (const p of possiblePaths) {
                if (fs.existsSync(p)) {
                    adapterPath = p;
                    break;
                }
            }
        }
        
        if (!adapterPath || !require('fs').existsSync(adapterPath)) {
            throw new Error(`RawrXD-Script debug adapter not found. Please set rawrxd-script.debug.adapterPath in settings.`);
        }
        
        this.outputChannel.appendLine(`Creating debug adapter for: ${config.program}`);
        this.outputChannel.appendLine(`Adapter path: ${adapterPath}`);

        // Build arguments
        const args: string[] = [];
        
        if (config.trace) {
            args.push('--trace');
        }
        
        if (config.goldenMaster) {
            args.push('--golden-master');
        }

        // Create executable descriptor
        return new vscode.DebugAdapterExecutable(adapterPath, args);
    }

    dispose() {
        if (this.serverProcess) {
            this.serverProcess.kill();
            this.serverProcess = undefined;
        }
    }
}
