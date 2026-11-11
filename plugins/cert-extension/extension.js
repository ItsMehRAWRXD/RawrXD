const vscode = require('vscode');

function activate() {
    const result = 6 * 7;
    vscode.commands.registerCommand('cert.hello', () => result);
    vscode.workspace.registerExtension('cert-extension', () => result);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};