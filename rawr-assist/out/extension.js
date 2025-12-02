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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const llamaBridge_1 = require("./llamaBridge");
const agentRunner_1 = require("./agentRunner");
const inlineProvider_1 = require("./inlineProvider");
let llama;
function activate(context) {
    const cfg = vscode.workspace.getConfiguration('rawr-assist');
    const ggufPath = cfg.get('ggufPath');
    llama = new llamaBridge_1.LlamaBridge(ggufPath, cfg.get('contextLen'));
    // 1.  inline completions
    const provider = new inlineProvider_1.InlineProvider(llama);
    const sel = { scheme: '*', language: '*' };
    context.subscriptions.push(vscode.languages.registerInlineCompletionItemProvider(sel, provider));
    // 2.  agentic command
    context.subscriptions.push(vscode.commands.registerCommand('rawr-assist.runAgent', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        const selection = editor.document.getText(editor.selection);
        if (!selection) {
            vscode.window.showErrorMessage('No selection');
            return;
        }
        await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Rawr agent running…' }, async () => {
            const agent = new agentRunner_1.AgentRunner(llama);
            const result = await agent.run(selection);
            editor.edit(b => b.replace(editor.selection, result));
        });
    }));
    vscode.window.showInformationMessage('Rawr Assist – local Q2_K GGUF loaded');
}
function deactivate() { llama?.dispose(); }
//# sourceMappingURL=extension.js.map