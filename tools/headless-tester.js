// ============================================================================
// headless-tester.js - Headless Browser Electron Integration Validator
// Simulates DOM environment and verifies core runtime behavior
// ============================================================================

const fs = require('fs');
const path = require('path');

class HeadlessTester {
    constructor() {
        this.projectRoot = path.join(__dirname, '..');
        this.virtualConsole = [];
        this.failures = [];
    }

    runValidationPass() {
        console.log('=== HeadlessTester: Integration Validation ===\n');

        try {
            this.setupMockEnvironment();
            this.executeBootSequence();
        } catch (e) {
            this.failures.push({ stage: 'BOOT_CRASH', detail: e.message, stack: e.stack });
        }

        this.generateTestReport();
        return this.failures.length === 0;
    }

    setupMockEnvironment() {
        global.window = {};
        global.document = {
            body: { appendChild: (el) => el },
            createElement: (tag) => ({
                id: '', className: '', style: {},
                appendChild: () => {},
                addEventListener: () => {},
                getContext: () => ({
                    fillStyle: '', fillRect: () => {},
                    beginPath: () => {}, moveTo: () => {},
                    lineTo: () => {}, stroke: () => {},
                    closePath: () => {}, fill: () => {},
                    scale: () => {}, font: '', textAlign: '',
                    fillText: () => {}
                })
            }),
            addEventListener: (event, cb) => {
                if (event === 'DOMContentLoaded') this.domCallback = cb;
            },
            querySelectorAll: () => [],
            querySelector: () => null,
            getElementById: () => null,
            head: { appendChild: () => {} }
        };

        global.window.electronAPI = {
            send: (chan, data) => this.virtualConsole.push(`[IPC] ${chan}`),
            on: (chan, cb) => {
                this.virtualConsole.push(`[IPC Sub] ${chan}`);
                return () => {};
            },
            invoke: () => Promise.resolve({}),
            removeAll: () => {}
        };

        global.console.warn = (msg) => this.virtualConsole.push(`[WARN] ${msg}`);
        global.console.error = (msg) => {
            this.virtualConsole.push(`[ERROR] ${msg}`);
            this.failures.push({ stage: 'CONSOLE_ERROR', detail: msg });
        };
        global.console.log = (msg) => this.virtualConsole.push(`[LOG] ${msg}`);
        global.console.info = (msg) => this.virtualConsole.push(`[INFO] ${msg}`);

        global.setTimeout = (fn) => fn();
        global.setInterval = () => ({ unref: () => {} });
        global.clearInterval = () => {};
        global.clearTimeout = () => {};
        global.btoa = (s) => Buffer.from(s).toString('base64');
        global.atob = (s) => Buffer.from(s, 'base64').toString();
        global.performance = { memory: { usedJSHeapSize: 0, totalJSHeapSize: 0 } };
        global.ResizeObserver = class {
            constructor(cb) { this.cb = cb; }
            observe() {}
            disconnect() {}
        };
        global.fetch = () => Promise.resolve({ json: () => Promise.resolve([]) });
        global.localStorage = {
            _data: {},
            getItem: (k) => this._data[k] || null,
            setItem: (k, v) => { this._data[k] = v; },
            removeItem: (k) => { delete this._data[k]; }
        };
        global.Math = Math;
        global.Date = Date;
        global.JSON = JSON;
        global.Error = Error;
        global.Promise = Promise;
        global.Array = Array;
        global.Object = Object;
        global.String = String;
        global.Number = Number;
        global.Map = Map;
        global.Set = Set;
    }

    executeBootSequence() {
        const runtimePath = path.join(this.projectRoot, 'src/core/runtime.js');
        const code = fs.readFileSync(runtimePath, 'utf-8');
        new Function(code)();

        if (!global.window.RawrRuntime) {
            throw new Error('RawrRuntime failed to register on window.');
        }

        const runtime = global.window.RawrRuntime;

        // Test 1: requireElement creates placeholder for missing elements
        const fallback = runtime.requireElement('test-missing-node');
        if (!fallback || fallback.id !== 'test-missing-node') {
            throw new Error('requireElement failed to create placeholder.');
        }
        this.virtualConsole.push('[PASS] requireElement placeholder creation');

        // Test 2: Event publish/subscribe
        let eventReceived = false;
        runtime.subscribe('test:event', (data) => { eventReceived = data === 'test-data'; });
        runtime.publish('test:event', 'test-data');
        if (!eventReceived) {
            throw new Error('Event publish/subscribe failed.');
        }
        this.virtualConsole.push('[PASS] Event publish/subscribe');

        // Test 3: Service registration
        runtime.register('TestService', { name: 'test' });
        const svc = runtime.resolve('TestService');
        if (!svc || svc.name !== 'test') {
            throw new Error('Service registration failed.');
        }
        this.virtualConsole.push('[PASS] Service registration');

        // Test 4: Diagnostics
        const diag = runtime.getDiagnostics();
        if (!diag || !diag.services || !diag.events) {
            throw new Error('Diagnostics failed.');
        }
        this.virtualConsole.push('[PASS] Diagnostics');

        this.virtualConsole.push('[PASS] All core runtime tests passed.');
    }

    generateTestReport() {
        console.log('\n--- CONSOLE TRACE ---');
        this.virtualConsole.forEach(log => console.log(`  ${log}`));

        console.log('\n--- TEST SUMMARY ---');
        if (this.failures.length === 0) {
            console.log('PASS: All validations passed.');
        } else {
            console.error(`FAIL: ${this.failures.length} failures:`);
            this.failures.forEach(f => console.error(`  [${f.stage}] ${f.detail}`));
        }
    }
}

const tester = new HeadlessTester();
const passed = tester.runValidationPass();
process.exit(passed ? 0 : 1);
