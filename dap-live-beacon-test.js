const { spawn } = require('child_process');

class DAPClient {
  constructor(exePath, args) {
    this.exePath = exePath;
    this.args = args;
    this.seq = 0;
    this.buffer = '';
    this.readingHeader = true;
    this.expectedLength = 0;
    this.pending = new Map();
    this.events = [];
  }

  start() {
    return new Promise((resolve, reject) => {
      this.proc = spawn(this.exePath, this.args, { stdio: ['pipe', 'pipe', 'pipe'] });

      this.proc.stdout.on('data', (chunk) => this.onData(chunk));
      this.proc.stderr.on('data', () => {});
      this.proc.on('error', reject);
      this.proc.on('spawn', resolve);
    });
  }

  stop() {
    if (!this.proc) return;
    try { this.proc.stdin.end(); } catch {}
    try { this.proc.kill(); } catch {}
  }

  onData(chunk) {
    this.buffer += chunk.toString('utf8');

    while (this.buffer.length > 0) {
      if (this.readingHeader) {
        const end = this.buffer.indexOf('\r\n\r\n');
        if (end === -1) return;

        const header = this.buffer.slice(0, end);
        const match = header.match(/Content-Length:\s*(\d+)/i);
        if (!match) {
          this.buffer = this.buffer.slice(end + 4);
          continue;
        }

        this.expectedLength = parseInt(match[1], 10);
        this.buffer = this.buffer.slice(end + 4);
        this.readingHeader = false;
      } else {
        if (this.buffer.length < this.expectedLength) return;

        const jsonPayload = this.buffer.slice(0, this.expectedLength);
        this.buffer = this.buffer.slice(this.expectedLength);
        this.readingHeader = true;

        let msg;
        try {
          msg = JSON.parse(jsonPayload);
        } catch {
          continue;
        }

        if (msg.type === 'response' && this.pending.has(msg.request_seq)) {
          const callbacks = this.pending.get(msg.request_seq);
          this.pending.delete(msg.request_seq);
          if (msg.success) {
            callbacks.resolve(msg);
          } else {
            callbacks.reject(new Error(JSON.stringify(msg)));
          }
        } else if (msg.type === 'event') {
          this.events.push(msg);
        }
      }
    }
  }

  sendRequest(command, args = {}, timeoutMs = 12000) {
    return new Promise((resolve, reject) => {
      const seq = ++this.seq;
      const req = {
        seq,
        type: 'request',
        command,
        arguments: args
      };

      const timer = setTimeout(() => {
        if (this.pending.has(seq)) {
          this.pending.delete(seq);
          reject(new Error(`Timeout waiting for response: ${command}`));
        }
      }, timeoutMs);

      const payload = JSON.stringify(req);
      const header = `Content-Length: ${Buffer.byteLength(payload, 'utf8')}\r\n\r\n`;
      this.pending.set(seq, {
        resolve: (msg) => {
          clearTimeout(timer);
          resolve(msg);
        },
        reject: (err) => {
          clearTimeout(timer);
          reject(err);
        }
      });
      this.proc.stdin.write(header + payload, 'utf8');
    });
  }

  waitForEvent(eventName, timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const timer = setInterval(() => {
        const idx = this.events.findIndex((e) => e.event === eventName);
        if (idx !== -1) {
          const ev = this.events[idx];
          this.events.splice(idx, 1);
          clearInterval(timer);
          resolve(ev);
          return;
        }

        if (Date.now() - start > timeoutMs) {
          clearInterval(timer);
          reject(new Error(`Timeout waiting for event: ${eventName}`));
        }
      }, 50);
    });
  }
}

async function main() {
  const [,, beaconExe, launchTarget, victimAsm, serverLog] = process.argv;
  if (!beaconExe || !launchTarget || !victimAsm || !serverLog) {
    console.error('Usage: node dap-live-beacon-test.js <beaconExe> <launchTarget> <victimAsm> <serverLog>');
    process.exit(2);
  }

  const client = new DAPClient(beaconExe, ['--stdio', '--log', serverLog]);

  try {
    await client.start();

    await client.sendRequest('initialize', {});
    await client.waitForEvent('initialized', 12000);

    await client.sendRequest('launch', { program: launchTarget });

    try { await client.waitForEvent('process', 6000); } catch {}
    try { await client.waitForEvent('stopped', 6000); } catch {}

    await client.sendRequest('setBreakpoints', {
      source: { path: victimAsm },
      breakpoints: [{ line: 25 }, { line: 35 }, { line: 999 }]
    });

    await client.sendRequest('disconnect', {});

    console.log('LIVE_DAP_OK');
    process.exit(0);
  } catch (err) {
    console.error(`LIVE_DAP_FAIL: ${err.message}`);
    process.exit(1);
  } finally {
    client.stop();
  }
}

main();
