/* oneshot EXT_LOAD fixture — registerCommand + ping (no UI MessageBox). */
var g_activated = false;
var g_invoked = 0;

function activate(context) {
  g_activated = true;
  var api = (typeof vscode !== 'undefined' && vscode) ? vscode : null;
  if (!api && typeof require === 'function') {
    try { api = require('vscode'); } catch (e) { api = null; }
  }
  if (!api) api = (typeof globalThis !== 'undefined') ? globalThis.vscode : null;
  if (!api || !api.commands || !api.commands.registerCommand) {
    throw new Error('vscode.commands.registerCommand unavailable');
  }
  var disp = api.commands.registerCommand('extHello.ping', function () {
    g_invoked += 1;
    if (typeof globalThis !== 'undefined') {
      globalThis.__ext_hello_invoked = function () { return g_invoked; };
    }
    // Do NOT call window.showInformationMessage here — MessageBox blocks headless smoke.
    return 'pong';
  });
  if (context && context.subscriptions && context.subscriptions.push) {
    context.subscriptions.push(disp);
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.__ext_hello_activated = true;
    globalThis.__ext_hello_invoked = function () { return g_invoked; };
  }
}

function deactivate() {
  g_activated = false;
  if (typeof globalThis !== 'undefined') {
    globalThis.__ext_hello_activated = false;
  }
}

module.exports = { activate: activate, deactivate: deactivate };
