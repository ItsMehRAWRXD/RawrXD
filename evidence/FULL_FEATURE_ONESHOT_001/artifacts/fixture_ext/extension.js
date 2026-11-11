function activate(context) {
  // Prefer globalThis.vscode (host-bound); require('vscode') also maps to it.
  var vscode = globalThis.vscode || require('vscode');
  if (!vscode || !vscode.commands) {
    throw new Error('vscode.commands missing after host bind');
  }
  var disp = vscode.commands.registerCommand('oneshotFixture.ping', function () {
    if (vscode.window && vscode.window.showInformationMessage) {
      vscode.window.showInformationMessage('oneshot-fixture-ping');
    }
    return 'pong';
  });
  if (context && context.subscriptions && context.subscriptions.push) {
    context.subscriptions.push(disp);
  }
}
function deactivate() {}
module.exports = { activate: activate, deactivate: deactivate };
