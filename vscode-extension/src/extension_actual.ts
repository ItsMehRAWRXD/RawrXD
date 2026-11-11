// extension_actual.ts
// ACTUAL VS Code extension implementation - NO MORE SCAFFOLDING
// This wires BuildIntegration.ts to REAL VS Code commands

import * as vscode from 'vscode';
import * as path from 'path';
import { BuildSystem, AnalysisTools } from './BuildIntegration';

// Output channel for build messages
let outputChannel: vscode.OutputChannel;
let statusBarItem: vscode.StatusBarItem;

// =============================================================================
// ACTIVATION - Called when extension loads
// =============================================================================

export function activate(context: vscode.ExtensionContext) {
    console.log('RawrXD extension activating...');
    
    // Create output channel
    outputChannel = vscode.window.createOutputChannel('RawrXD');
    outputChannel.show();
    outputChannel.appendLine('🔥 RawrXD Extension Activated');
    
    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(
        vscode.StatusBarAlignment.Left, 
        100
    );
    statusBarItem.text = "$(play) RawrXD";
    statusBarItem.tooltip = "Click to build";
    statusBarItem.command = 'rawrxd.build';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    
    // =============================================================================
    // COMMAND: Build
    // =============================================================================
    
    let buildCommand = vscode.commands.registerCommand('rawrxd.build', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('❌ No active editor');
            return;
        }
        
        const sourceFile = editor.document.fileName;
        const outputFile = sourceFile.replace(/\.[^.]+$/, '.exe');
        
        outputChannel.clear();
        outputChannel.appendLine(`🔨 Building ${path.basename(sourceFile)}...`);
        statusBarItem.text = "$(sync~spin) Building...";
        
        try {
            // ACTUALLY call the build system
            const success = await BuildSystem.compileFile(sourceFile, outputFile);
            
            if (success) {
                outputChannel.appendLine(`✅ Build successful!`);
                outputChannel.appendLine(`Output: ${outputFile}`);
                statusBarItem.text = "$(check) Build OK";
                vscode.window.showInformationMessage('✅ Build successful!');
            } else {
                outputChannel.appendLine(`❌ Build failed`);
                statusBarItem.text = "$(error) Build Failed";
                vscode.window.showErrorMessage('❌ Build failed');
            }
        } catch (error) {
            outputChannel.appendLine(`❌ Error: ${error}`);
            statusBarItem.text = "$(error) Error";
            vscode.window.showErrorMessage(`Error: ${error}`);
        }
    });
    
    context.subscriptions.push(buildCommand);
    
    // =============================================================================
    // COMMAND: Run
    // =============================================================================
    
    let runCommand = vscode.commands.registerCommand('rawrxd.run', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('❌ No active editor');
            return;
        }
        
        const sourceFile = editor.document.fileName;
        const exeFile = sourceFile.replace(/\.[^.]+$/, '.exe');
        
        // Check if executable exists
        const fs = require('fs');
        if (!fs.existsSync(exeFile)) {
            vscode.window.showErrorMessage('❌ Executable not found. Build first.');
            return;
        }
        
        outputChannel.appendLine(`🏃 Running ${path.basename(exeFile)}...`);
        statusBarItem.text = "$(run) Running...";
        
        try {
            // ACTUALLY run the executable
            const success = await BuildSystem.runExecutable(exeFile);
            
            if (success) {
                outputChannel.appendLine(`✅ Program completed`);
                statusBarItem.text = "$(check) Done";
            } else {
                outputChannel.appendLine(`❌ Run failed`);
                statusBarItem.text = "$(error) Run Failed";
            }
        } catch (error) {
            outputChannel.appendLine(`❌ Error: ${error}`);
            statusBarItem.text = "$(error) Error";
        }
    });
    
    context.subscriptions.push(runCommand);
    
    // =============================================================================
    // COMMAND: Analyze
    // =============================================================================
    
    let analyzeCommand = vscode.commands.registerCommand('rawrxd.analyze', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('❌ No active editor');
            return;
        }
        
        const sourceFile = editor.document.fileName;
        const exeFile = sourceFile.replace(/\.[^.]+$/, '.exe');
        
        const fs = require('fs');
        if (!fs.existsSync(exeFile)) {
            vscode.window.showErrorMessage('❌ Executable not found. Build first.');
            return;
        }
        
        outputChannel.appendLine(`🔍 Analyzing ${path.basename(exeFile)}...`);
        statusBarItem.text = "$(search) Analyzing...";
        
        try {
            // ACTUALLY analyze the PE
            const result = await AnalysisTools.analyzePE(exeFile);
            outputChannel.appendLine(result);
            outputChannel.appendLine(`✅ Analysis complete`);
            statusBarItem.text = "$(check) Analysis OK";
        } catch (error) {
            outputChannel.appendLine(`❌ Analysis failed: ${error}`);
            statusBarItem.text = "$(error) Analysis Failed";
        }
    });
    
    context.subscriptions.push(analyzeCommand);
    
    // =============================================================================
    // COMMAND: Clean
    // =============================================================================
    
    let cleanCommand = vscode.commands.registerCommand('rawrxd.clean', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('❌ No active editor');
            return;
        }
        
        const sourceFile = editor.document.fileName;
        const exeFile = sourceFile.replace(/\.[^.]+$/, '.exe');
        
        const fs = require('fs');
        if (fs.existsSync(exeFile)) {
            fs.unlinkSync(exeFile);
            outputChannel.appendLine(`🧹 Cleaned ${path.basename(exeFile)}`);
            vscode.window.showInformationMessage('🧹 Cleaned');
        } else {
            outputChannel.appendLine('Nothing to clean');
        }
    });
    
    context.subscriptions.push(cleanCommand);
    
    // =============================================================================
    // COMMAND: Agent Chat
    // =============================================================================
    
    let chatCommand = vscode.commands.registerCommand('rawrxd.openChat', () => {
        // Show chat panel
        vscode.commands.executeCommand('workbench.view.extension.rawrxd-chat');
    });
    
    context.subscriptions.push(chatCommand);
    
    // =============================================================================
    // KEYBOARD SHORTCUTS
    // =============================================================================
    
    // Ctrl+Shift+B - Build
    let buildKeybinding = vscode.commands.registerCommand('rawrxd.buildShortcut', () => {
        vscode.commands.executeCommand('rawrxd.build');
    });
    context.subscriptions.push(buildKeybinding);
    
    // Ctrl+Shift+R - Run
    let runKeybinding = vscode.commands.registerCommand('rawrxd.runShortcut', () => {
        vscode.commands.executeCommand('rawrxd.run');
    });
    context.subscriptions.push(runKeybinding);
    
    // =============================================================================
    // STATUS BAR
    // =============================================================================
    
    // Update status bar when editor changes
    vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor) {
            const ext = path.extname(editor.document.fileName).toLowerCase();
            if (ext === '.c' || ext === '.cpp' || ext === '.h') {
                statusBarItem.show();
            } else {
                statusBarItem.hide();
            }
        }
    }, null, context.subscriptions);
    
    // =============================================================================
    // LANGUAGE SUPPORT
    // =============================================================================
    
    // Register for C/C++ files
    const disposable = vscode.workspace.onDidOpenTextDocument(doc => {
        if (doc.languageId === 'c' || doc.languageId === 'cpp') {
            outputChannel.appendLine(`Opened ${path.basename(doc.fileName)}`);
        }
    });
    context.subscriptions.push(disposable);
    
    console.log('RawrXD extension activated successfully!');
    outputChannel.appendLine('✅ Ready to build!');
}

// =============================================================================
// DEACTIVATION - Called when extension unloads
// =============================================================================

export function deactivate() {
    console.log('RawrXD extension deactivated');
    if (outputChannel) {
        outputChannel.appendLine('👋 Goodbye!');
        outputChannel.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}
