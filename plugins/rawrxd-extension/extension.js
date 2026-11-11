const vscode = require('vscode');

function activate() {
    const result = 6 * 7;
    vscode.commands.registerCommand('rawrxd.hello', () => result);
    vscode.workspace.registerExtension('rawrxd-extension', () => result);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};