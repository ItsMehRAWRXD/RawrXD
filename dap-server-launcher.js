// dap-server-launcher.js
// Node.js wrapper for BeaconDebugger DAP Server
// This script bridges VS Code's debug adapter protocol to our native DAP server

const { spawn } = require('child_process');
const path = require('path');

// Get the path to the BeaconDebugger executable
const beaconPath = process.argv[2] || path.join(__dirname, 'bin', 'BeaconDebugger.exe');

console.error(`[DAP Launcher] Starting BeaconDebugger: ${beaconPath}`);

// Spawn the BeaconDebugger process with stdio DAP mode
const beacon = spawn(beaconPath, ['--stdio', '--verbose'], {
    stdio: ['pipe', 'pipe', 'pipe']
});

// Forward stdin from VS Code to BeaconDebugger
process.stdin.on('data', (data) => {
    beacon.stdin.write(data);
});

// Forward stdout from BeaconDebugger to VS Code
beacon.stdout.on('data', (data) => {
    process.stdout.write(data);
});

// Forward stderr from BeaconDebugger to VS Code's debug console
beacon.stderr.on('data', (data) => {
    console.error(`[BeaconDebugger] ${data.toString().trim()}`);
});

// Handle process exit
beacon.on('exit', (code) => {
    console.error(`[DAP Launcher] BeaconDebugger exited with code ${code}`);
    process.exit(code);
});

beacon.on('error', (err) => {
    console.error(`[DAP Launcher] Failed to start BeaconDebugger: ${err.message}`);
    process.exit(1);
});

// Handle VS Code disconnect
process.on('disconnect', () => {
    console.error('[DAP Launcher] VS Code disconnected, terminating BeaconDebugger');
    beacon.kill();
});

process.on('SIGTERM', () => {
    beacon.kill();
    process.exit(0);
});
