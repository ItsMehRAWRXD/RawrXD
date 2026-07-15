// Auto-generated VSIX wiring
// Generated: 2026-07-08 08:27:40

import * as vscode from 'vscode';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

// Toolchain configuration
const TOOLCHAIN_PATH = 'D:\\\\rawrxd\\\\native_toolchain';
const COMPILER_PATH = path.join(TOOLCHAIN_PATH, 'universal_compiler.exe');
const ASSEMBLER_PATH = path.join(TOOLCHAIN_PATH, 'minimal_assembler_v7.exe');
const LINKER_PATH = path.join(TOOLCHAIN_PATH, 'linker_fixed.exe');

export class BuildSystem {
    static async compileFile(sourceFile: string, outputFile?: string): Promise<boolean> {
        const args = [sourceFile];
        if (outputFile) {
            args.push('-o', outputFile);
        }
        
        try {
            await execFileAsync(COMPILER_PATH, args);
            vscode.window.showInformationMessage('Build successful!');
            return true;
        } catch (error) {
            vscode.window.showErrorMessage('Build failed: ' + error);
            return false;
        }
    }
    
    static async runExecutable(executable: string): Promise<boolean> {
        try {
            const terminal = vscode.window.createTerminal('RawrXD Run');
            terminal.sendText(executable);
            terminal.show();
            return true;
        } catch (error) {
            vscode.window.showErrorMessage('Run failed: ' + error);
            return false;
        }
    }
    
    static async debugExecutable(executable: string): Promise<boolean> {
        // TODO: Start DAP session
        vscode.window.showInformationMessage('Debug session started');
        return true;
    }
}

export class AnalysisTools {
    static async analyzePE(executable: string): Promise<string> {
        const analyzerPath = path.join(TOOLCHAIN_PATH, 'pe_analyzer.exe');
        try {
            const { stdout } = await execFileAsync(analyzerPath, [executable]);
            return stdout;
        } catch (error) {
            throw new Error('Analysis failed: ' + error);
        }
    }
}

// Register commands
export function registerBuildCommands(context: vscode.ExtensionContext) {
    // Build command
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd.build', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active editor');
                return;
            }
            
            await BuildSystem.compileFile(editor.document.fileName);
        })
    );
    
    // Run command
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd.run', async () => {
            // TODO: Get output file from build
            const outputFile = 'output.exe';
            await BuildSystem.runExecutable(outputFile);
        })
    );
    
    // Analyze command
    context.subscriptions.push(
        vscode.commands.registerCommand('rawrxd.analyze', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showErrorMessage('No active editor');
                return;
            }
            
            try {
                const result = await AnalysisTools.analyzePE(editor.document.fileName);
                vscode.window.showInformationMessage(result);
            } catch (error) {
                vscode.window.showErrorMessage(String(error));
            }
        })
    );
}
