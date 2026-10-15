#!/usr/bin/env python3
"""Standard-library test fixture; the production runner has no Python dependency.
Exercises actual local HTTP adapters, invalid gash rejection, file patch, build,
CTest verification, and on-disk evidence without requiring a real LLM.
"""
import http.server
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading

HERE = pathlib.Path(__file__).resolve().parent
BIN = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / 'rawr_run_linux'
STEPS = [
    {'tool': 'list', 'input': '.'},
    {'tool': 'gash', 'input': 'ctest --test-dir build'},
    {'tool': 'read', 'input': 'main.cpp'},
    {'tool': 'edit', 'input': 'main.cpp\n<<<SEARCH\nreturn 1;\n===REPLACE\nreturn 0;\n>>>'},
    # --config/-C are ignored by single-config generators (Makefile/Ninja) and
    # required by multi-config ones (Visual Studio). Without them the default
    # generator on Windows builds Debug and ctest reports "Test not available
    # without configuration", so the verify step can never succeed.
    {'tool': 'exec', 'input': 'cmake --build build --config Release'},
    {'tool': 'verify', 'input': 'ctest --test-dir build -C Release --output-on-failure'},
    'FINAL\nCorrected the regression and obtained a clean build and CTest receipt.',
]

class Handler(http.server.BaseHTTPRequestHandler):
    turn = 0
    backend = 'deep2'

    def log_message(self, *a):
        pass

    def do_POST(self):
        size = int(self.headers['Content-Length'])
        data = json.loads(self.rfile.read(size))
        assert data['stream'] is False, 'runner must use nonstreaming JSON'
        assert len(data['messages']) >= 2
        if self.backend == 'ollama':
            assert 'num_ctx' in data['options']
            assert self.path == '/api/chat'
        else:
            assert 'max_tokens' in data
            assert self.path == '/v1/chat/completions'
        text = STEPS[self.turn]
        self.__class__.turn += 1
        if isinstance(text, dict):
            text = json.dumps(text)
        if self.backend == 'ollama':
            answer = {'message': {'role': 'assistant', 'content': text}, 'eval_count': 25, 'done': True}
        else:
            answer = {'choices': [{'message': {'role': 'assistant', 'content': text}}], 'usage': {'completion_tokens': 25}}
        body = json.dumps(answer).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def exercise(backend):
    Handler.turn = 0
    Handler.backend = backend
    with tempfile.TemporaryDirectory(prefix='rawr_e2e_') as temp:
        root = pathlib.Path(temp)
        (root / 'main.cpp').write_text('int main() { return 1; }\n')
        (root / 'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.20)\nproject(rawr_mock LANGUAGES CXX)\nenable_testing()\nadd_executable(sanity main.cpp)\nadd_test(NAME sanity COMMAND sanity)\n')
        subprocess.run(['cmake', '-S', str(root), '-B', str(root / 'build')], check=True, capture_output=True)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        url = f'http://127.0.0.1:{server.server_port}/' + ('api/chat' if backend == 'ollama' else 'v1/chat/completions')
        try:
            proc = subprocess.run([
                str(BIN), 'run', 'mock-coder', 'Repair the failing C++ test and verify.',
                '--backend', backend, '--url', url, '--workspace', str(root), '--max-turns', '12',
            ], capture_output=True, text=True, timeout=90)
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=3)
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr)
            raise AssertionError(f'{backend}: exit {proc.returncode}')
        assert 'STATUS=VERIFIED_SUCCESS' in proc.stdout, proc.stdout
        assert 'return 0;' in (root / 'main.cpp').read_text()
        logs = list(root.glob('rawr_task_*.jsonl'))
        assert len(logs) == 1, logs
        events = [json.loads(line) for line in logs[0].read_text().splitlines()]
        assert any(x['kind'] == 'REJECT' and 'gash' in x['detail'] for x in events)
        assert any(x['kind'] == 'TOOL_verify' and x['ok'] for x in events)
        print(f'E2E_{backend.upper()} PASS: tool rejection, edit, build, verify, ledger, HTTP schema')

if __name__ == '__main__':
    exercise('deep2')
    exercise('ollama')
