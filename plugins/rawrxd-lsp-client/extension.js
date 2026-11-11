const vscode = require('vscode');

function activate() {
    vscode.commands.registerCommand('rawrxd-lsp-client.hello', () => {
        vscode.window.showInformationMessage('RawrXD LSP Client activated!');
    });
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};