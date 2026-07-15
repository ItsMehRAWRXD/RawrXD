// dap-protocol-test.js
// Automated DAP Protocol Compliance Test
// Validates the complete message flow without requiring C++ build

const { spawn } = require('child_process');
const path = require('path');

const TEST_RESULTS = {
    passed: 0,
    failed: 0,
    tests: []
};

function test(name, fn) {
    return new Promise((resolve) => {
        fn()
            .then(() => {
                TEST_RESULTS.passed++;
                TEST_RESULTS.tests.push({ name, status: 'PASS' });
                console.log(`✅ PASS: ${name}`);
                resolve();
            })
            .catch((err) => {
                TEST_RESULTS.failed++;
                TEST_RESULTS.tests.push({ name, status: 'FAIL', error: err.message });
                console.log(`❌ FAIL: ${name}`);
                console.log(`   Error: ${err.message}`);
                resolve();
            });
    });
}

function assertEqual(actual, expected, message) {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw new Error(`${message}\n  Expected: ${JSON.stringify(expected)}\n  Actual: ${JSON.stringify(actual)}`);
    }
}

// DAP Client for testing
class DAPTestClient {
    constructor(serverPath) {
        this.serverPath = serverPath;
        this.seq = 0;
        this.pending = new Map();
        this.buffer = '';
        this.expectedLength = 0;
        this.readingHeader = true;
    }
    
    async start() {
        return new Promise((resolve, reject) => {
            this.server = spawn('node', [this.serverPath], {
                stdio: ['pipe', 'pipe', 'pipe']
            });
            
            this.server.stdout.on('data', (data) => this.handleData(data));
            this.server.stderr.on('data', (data) => {
                // console.log('[SERVER LOG]', data.toString().trim());
            });
            
            this.server.on('error', reject);
            this.server.on('exit', (code) => {
                if (code !== 0 && code !== null) {
                    console.log(`Server exited with code ${code}`);
                }
            });
            
            // Wait a bit for server to start
            setTimeout(resolve, 500);
        });
    }
    
    stop() {
        if (this.server) {
            this.server.kill();
        }
    }
    
    handleData(data) {
        this.buffer += data.toString();
        
        while (this.buffer.length > 0) {
            if (this.readingHeader) {
                const headerEnd = this.buffer.indexOf('\r\n\r\n');
                if (headerEnd === -1) break;
                
                const header = this.buffer.substring(0, headerEnd);
                const match = header.match(/Content-Length:\s*(\d+)/i);
                if (match) {
                    this.expectedLength = parseInt(match[1], 10);
                    this.buffer = this.buffer.substring(headerEnd + 4);
                    this.readingHeader = false;
                } else {
                    break;
                }
            } else {
                if (this.buffer.length < this.expectedLength) break;
                
                const message = this.buffer.substring(0, this.expectedLength);
                this.buffer = this.buffer.substring(this.expectedLength);
                this.readingHeader = true;
                
                try {
                    const parsed = JSON.parse(message);
                    this.handleMessage(parsed);
                } catch (e) {
                    console.error('Parse error:', e);
                }
            }
        }
    }
    
    handleMessage(msg) {
        if (msg.type === 'response' && this.pending.has(msg.request_seq)) {
            const { resolve, reject } = this.pending.get(msg.request_seq);
            this.pending.delete(msg.request_seq);
            if (msg.success) {
                resolve(msg);
            } else {
                reject(new Error(msg.message || 'Request failed'));
            }
        } else if (msg.type === 'event') {
            // Store events for later verification
            if (!this.events) this.events = [];
            this.events.push(msg);
        }
    }
    
    sendRequest(command, args = {}) {
        return new Promise((resolve, reject) => {
            const seq = ++this.seq;
            const request = {
                seq,
                type: 'request',
                command,
                arguments: args
            };
            
            const message = JSON.stringify(request);
            const header = `Content-Length: ${Buffer.byteLength(message, 'utf8')}\r\n\r\n`;
            
            this.pending.set(seq, { resolve, reject });
            this.server.stdin.write(header + message);
        });
    }
    
    waitForEvent(eventType, timeout = 5000) {
        return new Promise((resolve, reject) => {
            const checkInterval = setInterval(() => {
                if (this.events) {
                    const idx = this.events.findIndex(e => e.event === eventType);
                    if (idx !== -1) {
                        clearInterval(checkInterval);
                        clearTimeout(timer);
                        const event = this.events[idx];
                        this.events.splice(idx, 1);
                        resolve(event);
                    }
                }
            }, 100);
            
            const timer = setTimeout(() => {
                clearInterval(checkInterval);
                reject(new Error(`Timeout waiting for event: ${eventType}`));
            }, timeout);
        });
    }
}

// Run tests
async function runTests() {
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║     RawrXD DAP Protocol Compliance Test Suite              ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log();
    
    const client = new DAPTestClient(path.join(__dirname, 'mock-dap-server.js'));
    
    try {
        await client.start();
        console.log('✅ Mock DAP Server started');
        console.log();
        
        // Test 1: Initialize
        await test('Protocol Handshake - Initialize', async () => {
            const response = await client.sendRequest('initialize', {});
            assertEqual(response.command, 'initialize', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            assertEqual(response.body.supportsConfigurationDoneRequest, true, 'Should support config done');
            
            const event = await client.waitForEvent('initialized');
            assertEqual(event.event, 'initialized', 'Should receive initialized event');
        });
        
        // Test 2: Configuration Done
        await test('Configuration Done', async () => {
            const response = await client.sendRequest('configurationDone');
            assertEqual(response.command, 'configurationDone', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
        });
        
        // Test 3: Launch
        await test('Process Launch', async () => {
            const response = await client.sendRequest('launch', {
                program: 'd:/rawrxd/Victim.exe'
            });
            assertEqual(response.command, 'launch', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            
            const processEvent = await client.waitForEvent('process');
            assertEqual(processEvent.body.name, 'Victim.exe', 'Process name mismatch');
            
            const stoppedEvent = await client.waitForEvent('stopped');
            assertEqual(stoppedEvent.body.reason, 'entry', 'Should stop at entry');
        });
        
        // Test 4: Set Breakpoints
        await test('Set Breakpoints', async () => {
            const response = await client.sendRequest('setBreakpoints', {
                source: { path: 'd:/rawrxd/src/debugger/Victim.asm' },
                breakpoints: [
                    { line: 25 },
                    { line: 35 },
                    { line: 999 } // Invalid line
                ]
            });
            assertEqual(response.command, 'setBreakpoints', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            assertEqual(response.body.breakpoints.length, 3, 'Should return 3 breakpoints');
            assertEqual(response.body.breakpoints[0].verified, true, 'Line 25 should be verified');
            assertEqual(response.body.breakpoints[1].verified, true, 'Line 35 should be verified');
            assertEqual(response.body.breakpoints[2].verified, false, 'Line 999 should be unverified');
        });
        
        // Test 5: Continue
        await test('Continue Execution', async () => {
            const response = await client.sendRequest('continue', {});
            assertEqual(response.command, 'continue', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            assertEqual(response.body.allThreadsContinued, true, 'All threads should continue');
            
            const event = await client.waitForEvent('continued');
            assertEqual(event.event, 'continued', 'Should receive continued event');
        });
        
        // Test 6: Step Over
        await test('Step Over (Next)', async () => {
            const response = await client.sendRequest('next', { threadId: 1 });
            assertEqual(response.command, 'next', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            
            const event = await client.waitForEvent('stopped');
            assertEqual(event.body.reason, 'step', 'Should stop with step reason');
        });
        
        // Test 7: Stack Trace
        await test('Stack Trace', async () => {
            const response = await client.sendRequest('stackTrace', { threadId: 1 });
            assertEqual(response.command, 'stackTrace', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            assertEqual(response.body.stackFrames.length > 0, true, 'Should have stack frames');
            assertEqual(response.body.stackFrames[0].name, '__bp_entry_point', 'Should have entry point');
        });
        
        // Test 8: Pause
        await test('Pause Execution', async () => {
            const response = await client.sendRequest('pause', { threadId: 1 });
            assertEqual(response.command, 'pause', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            
            const event = await client.waitForEvent('stopped');
            assertEqual(event.body.reason, 'pause', 'Should stop with pause reason');
        });
        
        // Test 9: Disconnect
        await test('Disconnect', async () => {
            const response = await client.sendRequest('disconnect');
            assertEqual(response.command, 'disconnect', 'Command mismatch');
            assertEqual(response.success, true, 'Should succeed');
            
            const event = await client.waitForEvent('terminated');
            assertEqual(event.event, 'terminated', 'Should receive terminated event');
        });
        
    } finally {
        client.stop();
    }
    
    // Print summary
    console.log();
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║     Test Summary                                           ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log();
    console.log(`Total: ${TEST_RESULTS.passed + TEST_RESULTS.failed}`);
    console.log(`✅ Passed: ${TEST_RESULTS.passed}`);
    console.log(`❌ Failed: ${TEST_RESULTS.failed}`);
    console.log();
    
    if (TEST_RESULTS.failed > 0) {
        console.log('Failed tests:');
        TEST_RESULTS.tests.filter(t => t.status === 'FAIL').forEach(t => {
            console.log(`  - ${t.name}`);
        });
        console.log();
    }
    
    if (TEST_RESULTS.failed === 0) {
        console.log('🎉 ALL TESTS PASSED!');
        console.log();
        console.log('Your DAP protocol implementation is compliant.');
        console.log('Next: Build the C++ BeaconDebugger.exe and test with VS Code');
    } else {
        console.log('⚠️  Some tests failed. Review the errors above.');
        process.exit(1);
    }
}

runTests().catch(err => {
    console.error('Test suite error:', err);
    process.exit(1);
});
