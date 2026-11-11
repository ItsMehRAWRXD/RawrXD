/* RawrXD QuickJS fixture extension — activate/deactivate + one command */
var g_activated = false;
var g_invoked = 0;

function activate(context) {
  g_activated = true;
  if (typeof vscode !== 'undefined' && vscode.commands && vscode.commands.registerCommand) {
    vscode.commands.registerCommand('rawrxd.smoke.ping', function () {
      g_invoked += 1;
      if (vscode.window && vscode.window.showInformationMessage) {
        vscode.window.showInformationMessage('rawrxd.smoke.ping');
      }
      return 'pong';
    });
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__rawrxd_smoke_activated = true;
    globalThis.__rawrxd_smoke_invoke = function () {
      g_invoked += 1;
      return g_invoked;
    };
  }
}

function deactivate() {
  g_activated = false;
  if (typeof globalThis !== 'undefined') {
    globalThis.__rawrxd_smoke_activated = false;
  }
}

module.exports = { activate: activate, deactivate: deactivate };
