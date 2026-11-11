#!/usr/bin/env python3
"""
RawrXD Live Dashboard Server
Real-time test execution and results visualization
"""

import os
import sys
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading

# Global state
TEST_STATE = {
    'running': False,
    'last_results': None,
    'history': [],
    'current_category': None
}

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging
        pass
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        
        if path == '/':
            self.serve_dashboard()
        elif path == '/api/status':
            self.serve_status()
        elif path == '/api/results':
            self.serve_results()
        elif path == '/api/history':
            self.serve_history()
        elif path == '/api/run':
            category = query.get('category', ['all'])[0]
            self.run_tests(category)
        elif path == '/api/baseline':
            self.serve_baseline()
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RawrXD Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 20px;
        }
        .header {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { color: #58a6ff; }
        .status { display: flex; gap: 20px; }
        .status-item {
            background: #21262d;
            padding: 10px 20px;
            border-radius: 8px;
            text-align: center;
        }
        .status-item .value {
            font-size: 24px;
            font-weight: bold;
        }
        .status-item .label {
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
        }
        .pass { color: #3fb950; }
        .fail { color: #f85149; }
        .warn { color: #f0883e; }
        
        .controls {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .controls h3 { margin-bottom: 15px; }
        .btn-group { display: flex; gap: 10px; flex-wrap: wrap; }
        button {
            background: #238636;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover { background: #2ea043; }
        button:disabled {
            background: #484f58;
            cursor: not-allowed;
        }
        button.secondary {
            background: #1f6feb;
        }
        button.secondary:hover {
            background: #388bfd;
        }
        
        .results {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
            min-height: 300px;
        }
        .results h3 { margin-bottom: 15px; }
        
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 10px;
        }
        .test-item {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .test-item.pass { border-left: 3px solid #238636; }
        .test-item.fail { border-left: 3px solid #da3633; }
        .test-item.running { border-left: 3px solid #f0883e; }
        
        .test-status {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }
        .test-status.pass { background: #238636; }
        .test-status.fail { background: #da3633; }
        .test-status.running { 
            background: #f0883e;
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .test-info { flex: 1; }
        .test-name { font-weight: 500; }
        .test-category { font-size: 12px; color: #8b949e; }
        .test-time { font-size: 12px; color: #8b949e; }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #21262d;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 20px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #238636, #2ea043);
            border-radius: 4px;
            transition: width 0.3s;
        }
        
        .console {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            max-height: 200px;
            overflow-y: auto;
        }
        .console-line {
            margin: 2px 0;
            color: #8b949e;
        }
        .console-line.success { color: #3fb950; }
        .console-line.error { color: #f85149; }
        .console-line.info { color: #58a6ff; }
        
        #spinner {
            display: none;
            margin-left: 10px;
        }
        .running #spinner {
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔬 RawrXD Live Dashboard</h1>
            <p style="color: #8b949e; margin-top: 5px;">Real-time test execution and monitoring</p>
        </div>
        <div class="status">
            <div class="status-item">
                <div class="value" id="total-tests">-</div>
                <div class="label">Total</div>
            </div>
            <div class="status-item">
                <div class="value pass" id="passed-tests">-</div>
                <div class="label">Passed</div>
            </div>
            <div class="status-item">
                <div class="value fail" id="failed-tests">-</div>
                <div class="label">Failed</div>
            </div>
        </div>
    </div>
    
    <div class="controls">
        <h3>Run Tests</h3>
        <div class="btn-group">
            <button onclick="runTests('all')" id="btn-all">
                Run All <span id="spinner">⏳</span>
            </button>
            <button onclick="runTests('cpu')" class="secondary">CPU</button>
            <button onclick="runTests('kernels')" class="secondary">Kernels</button>
            <button onclick="runTests('regression')" class="secondary">Regression</button>
            <button onclick="runTests('performance')" class="secondary">Performance</button>
            <button onclick="loadResults()" style="background: #6e7681;">Refresh</button>
        </div>
        <div class="progress-bar" style="margin-top: 15px; display: none;" id="progress-container">
            <div class="progress-fill" id="progress-fill" style="width: 0%;"></div>
        </div>
    </div>
    
    <div class="results">
        <h3>Test Results <span id="last-updated" style="font-size: 12px; color: #8b949e; float: right;"></span></h3>
        <div class="test-grid" id="test-grid">
            <p style="color: #8b949e; text-align: center; padding: 40px;">
                Click "Run All" to execute tests
            </p>
        </div>
    </div>
    
    <div class="console" id="console">
        <div class="console-line info">Dashboard ready. Waiting for commands...</div>
    </div>
    
    <script>
        let isRunning = false;
        
        function log(message, type = 'info') {
            const console = document.getElementById('console');
            const line = document.createElement('div');
            line.className = `console-line ${type}`;
            line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
            console.appendChild(line);
            console.scrollTop = console.scrollHeight;
        }
        
        async function runTests(category) {
            if (isRunning) return;
            
            isRunning = true;
            document.body.classList.add('running');
            document.getElementById('progress-container').style.display = 'block';
            document.getElementById('progress-fill').style.width = '0%';
            
            log(`Starting ${category} tests...`, 'info');
            
            try {
                const response = await fetch(`/api/run?category=${category}`);
                const results = await response.json();
                
                displayResults(results);
                log(`Tests complete: ${results.passed}/${results.total} passed`, 
                    results.failed === 0 ? 'success' : 'error');
            } catch (err) {
                log(`Error: ${err.message}`, 'error');
            } finally {
                isRunning = false;
                document.body.classList.remove('running');
                document.getElementById('progress-container').style.display = 'none';
            }
        }
        
        function displayResults(results) {
            document.getElementById('total-tests').textContent = results.total;
            document.getElementById('passed-tests').textContent = results.passed;
            document.getElementById('failed-tests').textContent = results.failed;
            document.getElementById('last-updated').textContent = 
                'Last updated: ' + new Date().toLocaleTimeString();
            
            const grid = document.getElementById('test-grid');
            grid.innerHTML = '';
            
            if (results.results) {
                results.results.forEach(test => {
                    const item = document.createElement('div');
                    item.className = `test-item ${test.status.toLowerCase()}`;
                    item.innerHTML = `
                        <div class="test-status ${test.status.toLowerCase()}">
                            ${test.status === 'PASS' ? '✓' : test.status === 'FAIL' ? '✗' : '○'}
                        </div>
                        <div class="test-info">
                            <div class="test-name">${test.test}</div>
                            <div class="test-category">${test.category}</div>
                        </div>
                        <div class="test-time">${test.elapsed_ms.toFixed(1)}ms</div>
                    `;
                    grid.appendChild(item);
                });
            }
        }
        
        async function loadResults() {
            try {
                const response = await fetch('/api/results');
                const results = await response.json();
                if (results) {
                    displayResults(results);
                }
            } catch (err) {
                log('No previous results found', 'info');
            }
        }
        
        // Load results on startup
        loadResults();
        
        // Auto-refresh every 30 seconds
        setInterval(loadResults, 30000);
    </script>
</body>
</html>'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_status(self):
        status = {
            'running': TEST_STATE['running'],
            'timestamp': datetime.now().isoformat(),
            'last_results': TEST_STATE['last_results']
        }
        self.send_json(status)
    
    def serve_results(self):
        self.send_json(TEST_STATE['last_results'])
    
    def serve_history(self):
        self.send_json(TEST_STATE['history'])
    
    def serve_baseline(self):
        try:
            with open('reports/baseline.json', 'r') as f:
                baseline = json.load(f)
            self.send_json(baseline)
        except:
            self.send_json({'error': 'No baseline found'})
    
    def run_tests(self, category):
        if TEST_STATE['running']:
            self.send_json({'error': 'Tests already running'})
            return
        
        TEST_STATE['running'] = True
        TEST_STATE['current_category'] = category
        
        def execute():
            try:
                script_dir = Path(__file__).parent
                result = subprocess.run(
                    [sys.executable, 'run_parallel.py', '--category', category],
                    capture_output=True,
                    text=True,
                    cwd=script_dir
                )
                
                # Parse results from JSON output
                reports_dir = script_dir / 'reports'
                latest = reports_dir / 'latest.json'
                if latest.exists():
                    with open(latest, 'r') as f:
                        TEST_STATE['last_results'] = json.load(f)
                        TEST_STATE['history'].append({
                            'timestamp': datetime.now().isoformat(),
                            'category': category,
                            'results': TEST_STATE['last_results']
                        })
            finally:
                TEST_STATE['running'] = False
                TEST_STATE['current_category'] = None
        
        thread = threading.Thread(target=execute)
        thread.start()
        
        self.send_json({'status': 'started', 'category': category})
    
    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())


def main():
    import argparse
    parser = argparse.ArgumentParser(description='RawrXD Dashboard Server')
    parser.add_argument('--port', '-p', type=int, default=8080, help='Port to run server on')
    parser.add_argument('--host', '-h', default='localhost', help='Host to bind to')
    args = parser.parse_args()
    
    server = HTTPServer((args.host, args.port), DashboardHandler)
    
    print(f"RawrXD Dashboard Server")
    print(f"=" * 60)
    print(f"Server running at http://{args.host}:{args.port}")
    print(f"Press Ctrl+C to stop")
    print(f"=" * 60)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
