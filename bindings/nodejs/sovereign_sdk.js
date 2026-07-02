// Sovereign SDK Node binding scaffold.
// This is intentionally minimal and ABI-focused.

/*
  To activate runtime binding, install:
    npm i ffi-napi ref-napi
*/

'use strict';

const path = require('path');

function resolveDefaultDll() {
  return path.join(process.cwd(), 'build', 'bin', 'sovereign_sdk.dll');
}

module.exports = {
  resolveDefaultDll,
  // Future binding shape:
  // init(config)
  // shutdown(handle)
  // getStatus(handle)
  // querySemanticGraph(handle, query)
};
