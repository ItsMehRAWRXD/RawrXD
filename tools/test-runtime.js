// test-runtime.js - Quick validation of RawrRuntime core
const fs = require('fs');
const code = fs.readFileSync('d:\\rawrxd\\src\\core\\runtime.js', 'utf-8');

// Mock browser environment
global.window = {};
global.document = {
    body: { appendChild: () => {} },
    createElement: () => ({ id: '', className: '', style: {} }),
    addEventListener: () => {},
    getElementById: () => null,
    head: { appendChild: () => {} }
};
global.setTimeout = (fn) => fn();
global.btoa = s => Buffer.from(s).toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString();
global.performance = { memory: { usedJSHeapSize: 0, totalJSHeapSize: 0 } };

// Execute runtime
new Function(code)();

const rt = global.window.RawrRuntime;
if (!rt) { console.error('FAIL: Runtime not registered'); process.exit(1); }

// Test requireElement
const fb = rt.requireElement('test-missing');
if (!fb || fb.id !== 'test-missing') { console.error('FAIL: requireElement'); process.exit(1); }
console.log('PASS: requireElement');

// Test events
let ev = false;
rt.subscribe('test:ev', d => ev = d === 'data');
rt.publish('test:ev', 'data');
if (!ev) { console.error('FAIL: events'); process.exit(1); }
console.log('PASS: events');

// Test services
rt.register('Svc', { x: 1 });
const s = rt.resolve('Svc');
if (!s || s.x !== 1) { console.error('FAIL: services'); process.exit(1); }
console.log('PASS: services');

// Test diagnostics
const d = rt.getDiagnostics();
if (!d || !d.services || !d.events) { console.error('FAIL: diagnostics'); process.exit(1); }
console.log('PASS: diagnostics');

// Test once
let onceFired = 0;
rt.once('test:once', () => onceFired++);
rt.publish('test:once', {});
rt.publish('test:once', {});
if (onceFired !== 1) { console.error('FAIL: once'); process.exit(1); }
console.log('PASS: once');

// Test unsubscribe
let subFired = 0;
const unsub = rt.subscribe('test:unsub', () => subFired++);
rt.publish('test:unsub', {});
unsub();
rt.publish('test:unsub', {});
if (subFired !== 1) { console.error('FAIL: unsubscribe'); process.exit(1); }
console.log('PASS: unsubscribe');

console.log('\nALL TESTS PASSED');
