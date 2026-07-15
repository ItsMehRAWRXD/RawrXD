// dap-diagnostic.js
// Diagnostic tool for DAP integration issues

const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

const BEACON_PATH = process.argv[2] || 'd:\\rawrxd\\bin\\BeaconDebugger.exe';

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║     RawrXD DAP Integration Diagnostic Tool                 ║');
console.log('╚════════════════════════════════════════════════════════════╝');
console.log();
console.log(`Beacon path: ${BEACON_PATH}`);
console.log();

// Check if file exists
const fs = require('fs');
if (!fs.existsSync(BEACON_PATH)) {
    console.error('❌ ERROR: BeaconDebugger.exe not found!');
    console.error('   Run: verify_integration.bat first');
    process.exit(1);
}

console.log('✅ BeaconDebugger.exe found');
console.log();

// Spawn BeaconDebugger
console.log('🚀 Starting BeaconDebugger in stdio mode...');
console.log('   (Press Ctrl+C to exit)');
console.log();

const beacon = spawn(BEACON_PATH, ['--stdio', '--verbose'], {
    stdio: ['pipe', 'pipe', 'pipe']
});

let messageCount = 0;

// Handle stdout (DAP responses)
beacon.stdout.on('data', (data) => {
    const str = data.toString();
    console.log('📥 FROM SERVER:');
    console.log(str);
    console.log();
});

// Handle stderr (logs)
beacon.stderr.on('data', (data) => {
    console.log('📝 LOG:', data.toString().trim());
});

// Handle exit
beacon.on('exit', (code) => {
    console.log();
    console.log(`⚠️  BeaconDebugger exited with code ${code}`);
    process.exit(code);
});

// Handle errors
beacon.on('error', (err) => {
    console.error();
    console.error('❌ FAILED TO START BeaconDebugger:');
    console.error('   ', err.message);
    console.error();
    console.error('Common causes:');
    console.error('   1. Missing Visual C++ Redistributables');
    console.error('   2. BeaconDebugger.exe is 32-bit but system is 64-bit');
    console.error('   3. Antivirus blocking the executable');
    console.error('   4. Corrupted executable - rebuild with verify_integration.bat');
    process.exit(1);
});

// Create readline interface for user input
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

console.log('══════════════════════════════════════════════════════════════');
console.log('DAP Protocol Test - Send these messages:');
console.log();
console.log('1. Initialize:');
console.log('   {"seq":1,"type":"request","command":"initialize","arguments":{}}');
console.log();
console.log('2. Launch Victim.exe:');
console.log('   {"seq":2,"type":"request","command":"launch","arguments":{"program":"d:/rawrxd/Victim.exe"}}');
console.log();
console.log('3. Configuration Done:');
console.log('   {"seq":3,"type":"request","command":"configurationDone"}');
console.log();
console.log('4. Set Breakpoint:');
console.log('   {"seq":4,"type":"request","command":"setBreakpoints","arguments":{"source":{"path":"d:/rawrxd/src/debugger/Victim.asm"},"breakpoints":[{"line":25}]}}');
console.log();
console.log('5. Continue:');
console.log('   {"seq":5,"type":"request","command":"continue","arguments":{}}');
console.log('══════════════════════════════════════════════════════════════');
console.log();

// Send messages to BeaconDebugger
rl.on('line', (line) => {
    if (line.trim()) {
        messageCount++;
        console.log(`📤 TO SERVER (msg #${messageCount}):`);
        
        // Add Content-Length header for DAP protocol
        const contentLength = Buffer.byteLength(line, 'utf8');
        const dapMessage = `Content-Length: ${contentLength}\r\n\r\n${line}`;
        
        beacon.stdin.write(dapMessage);
        console.log(dapMessage);
        console.log();
    }
});

// Cleanup on exit
process.on('SIGINT', () => {
    console.log();
    console.log('👋 Shutting down...');
    beacon.kill();
    rl.close();
    process.exit(0);
});
