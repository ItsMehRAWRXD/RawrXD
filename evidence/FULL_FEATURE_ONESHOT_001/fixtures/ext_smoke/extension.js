function activate(context) {
  globalThis.__ONESHOT_EXT_ACTIVATED = true;
  if (typeof vscode !== 'undefined' && vscode.commands && vscode.commands.registerCommand) {
    vscode.commands.registerCommand('oneshot.ext.ping', function () {
      globalThis.__ONESHOT_EXT_PING = 'pong';
      return 'pong';
    });
  }
  return { ok: true };
}
function deactivate() {
  globalThis.__ONESHOT_EXT_DEACTIVATED = true;
}
module.exports = { activate: activate, deactivate: deactivate };
