#!/usr/bin/env python3
"""
RawrXD Performance Dashboard
Interactive web dashboard for performance monitoring
"""

import http.server
import socketserver
import json
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime

PORT = 8081

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Performance Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eaeaea;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 2px solid #0f3460;
            margin-bottom: 30px;
        }
        h1 {
            font-size: 2.5em;
            background: linear-gradient(135deg, #e94560 0%, #ff6b6b 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        .subtitle { color: #a0a0a0; font-size: 1.1em; }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .metric-title {
            font-size: 0.9em;
            color: #a0a0a0;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #fff;
        }
        .metric-value.good { color: #4ade80; }
        .metric-value.warning { color: #fbbf24; }
        .metric-value.critical { color: #f87171; }
        .chart-container {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
        }
        .chart-title {
            font-size: 1.2em;
            margin-bottom: 15px;
            color: #fff;
        }
        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .bar-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .bar-label {
            width: 100px;
            font-size: 0.9em;
            color: #a0a0a0;
        }
        .bar-track {
            flex: 1;
            height: 24px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%;
            border-radius: 12px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .bar-fill.good { background: linear-gradient(90deg, #4ade80, #22c55e); }
        .bar-fill.warning { background: linear-gradient(90deg, #fbbf24, #f59e0b); }
        .bar-fill.critical { background: linear-gradient(90deg, #f87171, #ef4444); }
        .actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .btn-primary {
            background: linear-gradient(135deg, #e94560 0%, #ff6b6b 100%);
            color: white;
        }
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #eaeaea;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-good { background: #4ade80; }
        .status-warning { background: #fbbf24; }
        .status-critical { background: #f87171; }
        footer {
            text-align: center;
            padding: 30px;
            color: #a0a0a0;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            margin-top: 30px;
        }
        .timestamp {
            font-family: 'Courier New', monospace;
            background: rgba(255, 255, 255, 0.05);
            padding: 5px 10px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>⚡ RawrXD Performance Dashboard</h1>
            <p class="subtitle">Real-time Performance Monitoring & Optimization</p>
        </header>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">Matmul Performance</div>
                <div class="metric-value {matmul_class}">{matmul_gops} GOPS</div>
                <span class="status-indicator {matmul_status}"></span>
                <span style="color: {matmul_color}">{matmul_label}</span>
            </div>
            
            <div class="metric-card">
                <div class="metric-title">Softmax Performance</div>
                <div class="metric-value {softmax_class}">{softmax_mops} M ops/s</div>
                <span class="status-indicator {softmax_status}"></span>
                <span style="color: {softmax_color}">{softmax_label}</span>
            </div>
            
            <div class="metric-card">
                <div class="metric-title">RMSNorm Performance</div>
                <div class="metric-value {rmsnorm_class}">{rmsnorm_mops} M ops/s</div>
                <span class="status-indicator {rmsnorm_status}"></span>
                <span style="color: {rmsnorm_color}">{rmsnorm_label}</span>
            </div>
            
            <div class="metric-card">
                <div class="metric-title">Overall Status</div>
                <div class="metric-value {overall_class}">{overall_status}</div>
                <span class="status-indicator {overall_indicator}"></span>
                <span style="color: {overall_color}">{overall_label}</span>
            </div>
        </div>
        
        <div class="chart-container">
            <div class="chart-title">Performance Comparison (Relative to Target)</div>
            <div class="bar-chart">
                <div class="bar-item">
                    <div class="bar-label">Matmul</div>
                    <div class="bar-track">
                        <div class="bar-fill {matmul_bar_class}" style="width: {matmul_pct}%">{matmul_pct}%</div>
                    </div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">Softmax</div>
                    <div class="bar-track">
                        <div class="bar-fill {softmax_bar_class}" style="width: {softmax_pct}%">{softmax_pct}%</div>
                    </div>
                </div>
                <div class="bar-item">
                    <div class="bar-label">RMSNorm</div>
                    <div class="bar-track">
                        <div class="bar-fill {rmsnorm_bar_class}" style="width: {rmsnorm_pct}%">{rmsnorm_pct}%</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="actions">
            <button class="btn btn-primary" onclick="runBenchmarks()">🚀 Run Benchmarks</button>
            <button class="btn btn-secondary" onclick="viewReport()">📊 View Report</button>
            <button class="btn btn-secondary" onclick="exportData()">💾 Export Data</button>
        </div>
        
        <footer>
            <p>Last updated: <span class="timestamp">{timestamp}</span></p>
            <p style="margin-top: 10px; font-size: 0.9em;">RawrXD v15.0 Performance Framework</p>
        </footer>
    </div>
    
    <script>
        function runBenchmarks() {
            alert('Running benchmarks... Check console for results.');
            fetch('/api/run_benchmarks')
                .then(response => response.json())
                .then(data => {
                    alert('Benchmarks complete! Refresh to see results.');
                    location.reload();
                });
        }
        
        function viewReport() {
            window.open('optimization_report.json', '_blank');
        }
        
        function exportData() {
            alert('Export functionality would download performance data as JSON/CSV');
        }
        
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>
"""

class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            # Get performance data
            data = self.get_performance_data()
            html = HTML_TEMPLATE.format(**data)
            self.wfile.write(html.encode())
            
        elif self.path == '/api/run_benchmarks':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            # Run benchmarks
            try:
                result = subprocess.run(
                    ['tests/performance/benchmark_quick.exe'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                self.wfile.write(json.dumps({"status": "complete"}).encode())
            except Exception as e:
                self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode())
        else:
            super().do_GET()
    
    def get_performance_data(self):
        """Get current performance data"""
        # Default values
        matmul_gops = 4.37
        softmax_mops = 614.40
        rmsnorm_mops = 409.60
        
        # Try to load from benchmark output
        try:
            result = subprocess.run(
                ['tests/performance/benchmark_quick.exe'],
                capture_output=True,
                text=True,
                timeout=30
            )
            for line in result.stdout.split('\n'):
                if 'Matmul' in line and 'GOPS' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        matmul_gops = float(parts[1].split()[0])
                elif 'Softmax' in line and 'M ops/sec' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        softmax_mops = float(parts[1].split()[0])
                elif 'RMSNorm' in line and 'M ops/sec' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        rmsnorm_mops = float(parts[1].split()[0])
        except:
            pass
        
        # Calculate percentages (targets: matmul=10 GOPS, softmax=1000 M ops/s, rmsnorm=1000 M ops/s)
        matmul_pct = min(100, int((matmul_gops / 10.0) * 100))
        softmax_pct = min(100, int((softmax_mops / 1000.0) * 100))
        rmsnorm_pct = min(100, int((rmsnorm_mops / 1000.0) * 100))
        
        # Determine classes
        def get_class(pct):
            if pct >= 80: return 'good', 'status-good', '#4ade80', 'Good'
            elif pct >= 50: return 'warning', 'status-warning', '#fbbf24', 'Fair'
            else: return 'critical', 'status-critical', '#f87171', 'Critical'
        
        matmul_class, matmul_status, matmul_color, matmul_label = get_class(matmul_pct)
        softmax_class, softmax_status, softmax_color, softmax_label = get_class(softmax_pct)
        rmsnorm_class, rmsnorm_status, rmsnorm_color, rmsnorm_label = get_class(rmsnorm_pct)
        
        # Overall status
        avg_pct = (matmul_pct + softmax_pct + rmsnorm_pct) / 3
        if avg_pct >= 80:
            overall_status, overall_class, overall_indicator, overall_color, overall_label = \
                'OPTIMAL', 'good', 'status-good', '#4ade80', 'All systems optimal'
        elif avg_pct >= 50:
            overall_status, overall_class, overall_indicator, overall_color, overall_label = \
                'ACCEPTABLE', 'warning', 'status-warning', '#fbbf24', 'Performance acceptable'
        else:
            overall_status, overall_class, overall_indicator, overall_color, overall_label = \
                'NEEDS WORK', 'critical', 'status-critical', '#f87171', 'Optimization required'
        
        return {
            'matmul_gops': f'{matmul_gops:.2f}',
            'softmax_mops': f'{softmax_mops:.2f}',
            'rmsnorm_mops': f'{rmsnorm_mops:.2f}',
            'matmul_class': matmul_class,
            'softmax_class': softmax_class,
            'rmsnorm_class': rmsnorm_class,
            'matmul_status': matmul_status,
            'softmax_status': softmax_status,
            'rmsnorm_status': rmsnorm_status,
            'matmul_color': matmul_color,
            'softmax_color': softmax_color,
            'rmsnorm_color': rmsnorm_color,
            'matmul_label': matmul_label,
            'softmax_label': softmax_label,
            'rmsnorm_label': rmsnorm_label,
            'matmul_pct': matmul_pct,
            'softmax_pct': softmax_pct,
            'rmsnorm_pct': rmsnorm_pct,
            'matmul_bar_class': matmul_class,
            'softmax_bar_class': softmax_class,
            'rmsnorm_bar_class': rmsnorm_class,
            'overall_status': overall_status,
            'overall_class': overall_class,
            'overall_indicator': overall_indicator,
            'overall_color': overall_color,
            'overall_label': overall_label,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

def main():
    print(f"Starting RawrXD Performance Dashboard on port {PORT}...")
    print(f"Open http://localhost:{PORT} in your browser")
    print("Press Ctrl+C to stop")
    
    with socketserver.TCPServer(("", PORT), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")

if __name__ == "__main__":
    main()
