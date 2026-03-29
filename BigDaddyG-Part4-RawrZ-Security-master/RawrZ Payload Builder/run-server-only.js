// Run only the embedded API server (no Electron) for curl/testing
const { startEmbeddedServer } = require('./src/embedded-api-server');
startEmbeddedServer()
  .then(() => console.log('[OK] Server ready at http://127.0.0.1:3000'))
  .catch((err) => { console.error(err); process.exit(1); });
