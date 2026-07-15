// mock-dap-server.js
// Simulates BeaconDebugger DAP protocol for testing
// This validates the protocol layer without requiring C++ build

const readline = require('readline');

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║     RawrXD Mock DAP Server (Protocol Test)                   ║');
console.log('╚════════════════════════════════════════════════════════════╝');
console.log();
console.log('Simulating BeaconDebugger.exe --stdio --verbose');
console.log('Type DAP JSON messages to test the protocol');
console.log();

let seqCounter = 0;
let requestSeq = 0;

function sendDAPMessage(type, data) {
    const message = JSON.stringify({
        seq: ++seqCounter,
        type: type,
        ...data
    });
    const header = `Content-Length: ${Buffer.byteLength(message, 'utf8')}\r\n\r\n`;
    process.stdout.write(header + message);
}

function sendResponse(request_seq, command, body = {}, success = true) {
    sendDAPMessage('response', {
        request_seq: request_seq,
        success: success,
        command: command,
        body: body
    });
}

function sendEvent(event, body = {}) {
    sendDAPMessage('event', {
        event: event,
        body: body
    });
}

// Read buffer for Content-Length framing
let buffer = '';
let expectedLength = 0;
let readingHeader = true;

process.stdin.on('data', (data) => {
    buffer += data.toString();
    
    while (buffer.length > 0) {
        if (readingHeader) {
            const headerEnd = buffer.indexOf('\r\n\r\n');
            if (headerEnd === -1) break;
            
            const header = buffer.substring(0, headerEnd);
            const match = header.match(/Content-Length:\s*(\d+)/i);
            if (match) {
                expectedLength = parseInt(match[1], 10);
                buffer = buffer.substring(headerEnd + 4);
                readingHeader = false;
            } else {
                console.error('Invalid header:', header);
                break;
            }
        } else {
            if (buffer.length < expectedLength) break;
            
            const message = buffer.substring(0, expectedLength);
            buffer = buffer.substring(expectedLength);
            readingHeader = true;
            
            try {
                const request = JSON.parse(message);
                handleRequest(request);
            } catch (e) {
                console.error('Failed to parse JSON:', e.message);
            }
        }
    }
});

function handleRequest(request) {
    requestSeq = request.seq || 0;
    const command = request.command;
    
    console.log(`[RECV] ${command} (seq: ${requestSeq})`);
    
    switch (command) {
        case 'initialize':
            console.log('[HANDLER] Sending capabilities...');
            sendResponse(requestSeq, 'initialize', {
                supportsConfigurationDoneRequest: true,
                supportsHitConditionalBreakpoints: true,
                supportsConditionalBreakpoints: true,
                supportsEvaluateForHovers: false,
                supportsStepBack: false,
                supportsSetVariable: false,
                supportsRestartFrame: false,
                supportsGotoTargetsRequest: false,
                supportsStepInTargetsRequest: false,
                supportsCompletionsRequest: false,
                supportsModulesRequest: false,
                supportsRestartRequest: false,
                supportsExceptionOptions: false,
                supportsValueFormattingOptions: false,
                supportsExceptionInfoRequest: false,
                supportTerminateDebuggee: true,
                supportsDelayedStackTraceFetching: false,
                supportsLoadedSourcesRequest: false,
                supportsLogPoints: false,
                supportsTerminateThreadsRequest: false,
                supportsSetExpression: false,
                supportsTerminateRequest: true,
                supportsDataBreakpoints: false,
                supportsReadMemoryRequest: true,
                supportsWriteMemoryRequest: true,
                supportsDisassembleRequest: true
            });
            
            // Send initialized event
            setTimeout(() => {
                console.log('[EVENT] initialized');
                sendEvent('initialized', {});
            }, 100);
            break;
            
        case 'launch':
            console.log('[HANDLER] Launching process...');
            console.log(`  program: ${request.arguments?.program || 'N/A'}`);
            sendResponse(requestSeq, 'launch');
            
            // Simulate process launch
            setTimeout(() => {
                console.log('[EVENT] process - started');
                sendEvent('process', {
                    name: 'Victim.exe',
                    systemProcessId: 12345,
                    isLocalProcess: true,
                    startMethod: 'launch'
                });
                
                // Simulate stop at entry
                setTimeout(() => {
                    console.log('[EVENT] stopped - entry');
                    sendEvent('stopped', {
                        reason: 'entry',
                        threadId: 1,
                        allThreadsStopped: true
                    });
                }, 500);
            }, 200);
            break;
            
        case 'attach':
            console.log('[HANDLER] Attaching to process...');
            console.log(`  processId: ${request.arguments?.processId || 'N/A'}`);
            sendResponse(requestSeq, 'attach');
            break;
            
        case 'configurationDone':
            console.log('[HANDLER] Configuration done');
            sendResponse(requestSeq, 'configurationDone');
            break;
            
        case 'setBreakpoints':
            console.log('[HANDLER] Setting breakpoints...');
            const breakpoints = (request.arguments?.breakpoints || []).map((bp, i) => {
                const verified = bp.line >= 20 && bp.line <= 60; // Our known lines
                console.log(`  BP ${i}: line ${bp.line} -> ${verified ? 'VERIFIED' : 'UNVERIFIED'}`);
                return {
                    id: i + 1,
                    verified: verified,
                    line: bp.line,
                    message: verified ? undefined : 'Line not found in symbol table'
                };
            });
            sendResponse(requestSeq, 'setBreakpoints', { breakpoints });
            break;
            
        case 'continue':
            console.log('[HANDLER] Continuing execution...');
            sendResponse(requestSeq, 'continue', { allThreadsContinued: true });
            
            setTimeout(() => {
                console.log('[EVENT] continued');
                sendEvent('continued', { threadId: 1, allThreadsContinued: true });
            }, 100);
            break;
            
        case 'next':
            console.log('[HANDLER] Step over...');
            sendResponse(requestSeq, 'next');
            
            setTimeout(() => {
                console.log('[EVENT] stopped - step');
                sendEvent('stopped', { reason: 'step', threadId: 1, allThreadsStopped: true });
            }, 100);
            break;
            
        case 'stepIn':
            console.log('[HANDLER] Step in...');
            sendResponse(requestSeq, 'stepIn');
            
            setTimeout(() => {
                console.log('[EVENT] stopped - step');
                sendEvent('stopped', { reason: 'step', threadId: 1, allThreadsStopped: true });
            }, 100);
            break;
            
        case 'pause':
            console.log('[HANDLER] Pause...');
            sendResponse(requestSeq, 'pause');
            
            setTimeout(() => {
                console.log('[EVENT] stopped - pause');
                sendEvent('stopped', { reason: 'pause', threadId: 1, allThreadsStopped: true });
            }, 100);
            break;
            
        case 'stackTrace':
            console.log('[HANDLER] Getting stack trace...');
            sendResponse(requestSeq, 'stackTrace', {
                stackFrames: [
                    {
                        id: 0,
                        name: '__bp_entry_point',
                        source: { path: 'd:/rawrxd/src/debugger/Victim.asm', name: 'Victim.asm' },
                        line: 25,
                        column: 0
                    },
                    {
                        id: 1,
                        name: 'main',
                        source: { path: 'd:/rawrxd/src/debugger/Victim.asm', name: 'Victim.asm' },
                        line: 20,
                        column: 0
                    }
                ],
                totalFrames: 2
            });
            break;
            
        case 'scopes':
            console.log('[HANDLER] Getting scopes...');
            sendResponse(requestSeq, 'scopes', { scopes: [] });
            break;
            
        case 'variables':
            console.log('[HANDLER] Getting variables...');
            sendResponse(requestSeq, 'variables', { variables: [] });
            break;
            
        case 'evaluate':
            console.log('[HANDLER] Evaluating expression...');
            sendResponse(requestSeq, 'evaluate', {
                result: '<unavailable>',
                type: '',
                variablesReference: 0
            });
            break;
            
        case 'disconnect':
            console.log('[HANDLER] Disconnecting...');
            sendResponse(requestSeq, 'disconnect');
            
            setTimeout(() => {
                console.log('[EVENT] terminated');
                sendEvent('terminated', {});
                process.exit(0);
            }, 100);
            break;
            
        default:
            console.log(`[HANDLER] Unknown command: ${command}`);
            sendResponse(requestSeq, command, {}, false);
    }
}

// Handle exit
process.on('SIGINT', () => {
    console.log();
    console.log('Shutting down mock server...');
    process.exit(0);
});

console.log('Mock server ready. Waiting for DAP messages...');
console.log('(Use dap-diagnostic.js to send test messages)');
console.log();
