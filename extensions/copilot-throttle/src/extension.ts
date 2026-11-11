import * as vscode from 'vscode';
import { ThrottleInterceptor } from './throttleInterceptor';

let interceptor: ThrottleInterceptor | undefined;

export function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('copilotThrottle');
    
    // Only activate if enabled
    if (config.get('enabled', true)) {
        interceptor = new ThrottleInterceptor();
        interceptor.activate();
        
        vscode.window.showInformationMessage('✅ Copilot Throttle activated - Local models will be throttled to prevent "Response too long" errors');
    }

    // Register toggle command
    const toggleCmd = vscode.commands.registerCommand('copilotThrottle.toggle', () => {
        const cfg = vscode.workspace.getConfiguration('copilotThrottle');
        const current = cfg.get('enabled', true);
        cfg.update('enabled', !current, true);
        
        if (!current && !interceptor) {
            interceptor = new ThrottleInterceptor();
            interceptor.activate();
            vscode.window.showInformationMessage('✅ Copilot Throttle ENABLED');
        } else if (current && interceptor) {
            interceptor.deactivate();
            interceptor = undefined;
            vscode.window.showInformationMessage('⏸️ Copilot Throttle DISABLED');
        }
    });

    // Register status command
    const statusCmd = vscode.commands.registerCommand('copilotThrottle.status', () => {
        const cfg = vscode.workspace.getConfiguration('copilotThrottle');
        const enabled = cfg.get('enabled', true);
        const maxTokens = cfg.get('maxTokens', 2048);
        const maxChars = cfg.get('maxChars', 8000);
        
        vscode.window.showInformationMessage(
            `Copilot Throttle: ${enabled ? '✅ ENABLED' : '⏸️ DISABLED'} | Max: ${maxTokens} tokens / ${maxChars} chars`
        );
    });

    context.subscriptions.push(toggleCmd, statusCmd);
}

export function deactivate() {
    interceptor?.deactivate();
}
