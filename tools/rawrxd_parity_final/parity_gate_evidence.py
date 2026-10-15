#!/usr/bin/env python3
"""Real-ledger parity gate verification (not a mock of the gate).

Runs rawr_run against a local mock HTTP backend in a PERSISTENT workspace so
the ledger survives, then feeds that ledger to parity_gate.py. Also proves the
gate rejects a missing/invalid ledger and a ledger without VERIFIED_SUCCESS.
"""
import http.server
import json
import pathlib
import shutil
import subprocess
import sys
import threading
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
BIN = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'build' / 'Release' / 'rawr_run.exe'
WS = HERE / 'parity_evidence_ws'

STEPS = [
    {'tool': 'list', 'input': '.'},
    {'tool': 'gash', 'input': 'ctest --test-dir build'},
    {'tool': 'read', 'input': 'main.cpp'},
    {'tool': 'edit', 'input': 'main.cpp\n<<<SEARCH\nreturn 1;\n===REPLACE\nreturn 0;\n>>>'},
    {'tool': 'exec', 'input': 'cmake --build build --config Release'},
    {'tool': 'verify', 'input': 'ctest --test-dir build -C Release --output-on-failure'},
    'FINAL\nRegression repaired; build and CTest receipts recorded.',
]


class Handler(http.server.BaseHTTPRequestHandler):
    turn = 0

    def log_message(self, *a):
        pass

    def do_POST(self):
        size = int(self.headers['Content-Length'])
        data = json.loads(self.rfile.read(size))
        assert data['stream'] is False, 'runner must use nonstreaming JSON'
        assert len(data['messages']) >= 2
        assert 'max_tokens' in data
        assert self.path == '/v1/chat/completions'
        text = STEPS[self.turn]
        self.__class__.turn += 1
        # The mock model replies with the tool call as a JSON *string*, not as a
        # nested JSON object: a real model returns content as text. Without this
        # the runner's parser sees a non-string "content" and correctly rejects
        # it as an empty/incompatible response.
        if isinstance(text, dict):
            text = json.dumps(text)
        body = json.dumps({'choices': [{'message': {'role': 'assistant', 'content': text}}],
                          'usage': {'completion_tokens': 25}}).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    if not BIN.exists():
        print(f'FATAL: binary not found: {BIN}')
        return 1
    if WS.exists():
        shutil.rmtree(WS, ignore_errors=True)
    WS.mkdir(parents=True)

    (WS / 'main.cpp').write_text('int main() { return 1; }\n')
    (WS / 'CMakeLists.txt').write_text(
        'cmake_minimum_required(VERSION 3.20)\n'
        'project(rawr_mock LANGUAGES CXX)\n'
        'enable_testing()\n'
        'add_executable(sanity main.cpp)\n'
        'add_test(NAME sanity COMMAND sanity)\n')

    # Pre-configure the build tree, exactly as the delivered fixture does: the
    # runner's build/verify steps operate on an existing build directory.
    subprocess.run(['cmake', '-S', str(WS), '-B', str(WS / 'build')],
                   check=True, capture_output=True)

    ledger = WS / 'rawr_ledger.jsonl'
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    url = f'http://127.0.0.1:{server.server_port}/v1/chat/completions'
    try:
        proc = subprocess.run([
            str(BIN), 'run', 'mock-coder', 'Repair the failing C++ test and verify.',
            '--url', url, '--workspace', str(WS), '--max-turns', '12', '--ledger', str(ledger),
        ], capture_output=True, text=True, timeout=180)
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=3)

    print('--- runner stdout (tail) ---')
    print('\n'.join(proc.stdout.strip().splitlines()[-6:]))
    print('--- runner exit code:', proc.returncode)
    if proc.returncode != 0:
        print(proc.stderr)
        return 1
    assert 'STATUS=VERIFIED_SUCCESS' in proc.stdout, proc.stdout
    assert 'return 0;' in (WS / 'main.cpp').read_text()
    assert ledger.exists(), 'ledger file was not written'

    # --- the real gate on the real ledger ---
    print('--- parity_gate.py on the real ledger ---')
    gate = subprocess.run([sys.executable, str(HERE / 'parity_gate.py'), str(ledger),
                           '--min-tasks', '1'], capture_output=True, text=True)
    print(gate.stdout)
    if gate.returncode != 0:
        print(gate.stderr)
        return 1

    report = json.loads(gate.stdout)
    assert report['pass'] is True, report
    counts = report['results'][0]['counts']
    for kind in ('START', 'MODEL', 'TOOL_verify', 'TOOL_exec', 'TOOL_edit', 'VERIFIED_SUCCESS'):
        assert counts.get(kind), f'ledger missing {kind}: {counts}'

    # --- negative controls: the gate must REJECT, not rubber-stamp ---
    neg = []
    r = subprocess.run([sys.executable, str(HERE / 'parity_gate.py'),
                        str(WS / 'does_not_exist.jsonl')], capture_output=True, text=True)
    neg.append(('missing ledger', r.returncode != 0))

    bad = WS / 'bad_unverified.jsonl'
    events = [json.loads(l) for l in ledger.read_text().splitlines() if l.strip()]
    for e in events:
        if e['kind'] == 'VERIFIED_SUCCESS':
            e['kind'] = 'COMPLETED_UNVERIFIED'
    bad.write_text('\n'.join(json.dumps(e) for e in events) + '\n')
    r = subprocess.run([sys.executable, str(HERE / 'parity_gate.py'), str(bad), '--min-tasks', '1'],
                       capture_output=True, text=True)
    neg.append(('no VERIFIED_SUCCESS', r.returncode != 0))

    empty = WS / 'empty.jsonl'
    empty.write_text('')
    r = subprocess.run([sys.executable, str(HERE / 'parity_gate.py'), str(empty), '--min-tasks', '1'],
                       capture_output=True, text=True)
    neg.append(('empty ledger', r.returncode != 0))

    print('--- gate negative controls ---')
    for name, ok in neg:
        print(f'  {"PASS" if ok else "FAIL"}: rejected {name}')
    if not all(ok for _, ok in neg):
        return 1

    print('\nPARITY_GATE_EVIDENCE PASS: real ledger accepted, bad ledgers rejected')
    print(f'  ledger: {ledger}')
    print(f'  counts: {counts}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
