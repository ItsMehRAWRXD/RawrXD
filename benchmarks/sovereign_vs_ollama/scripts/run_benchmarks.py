#!/usr/bin/env python3
"""
Batch 6: Benchmark Automation Script

Automates benchmark execution with:
- Environment setup
- Backend health checks
- Result collection
- Report generation
- Notification on failure

Usage:
    python run_benchmarks.py --mode standard --backend sovereign
    python run_benchmarks.py --mode quick --notify slack
    python run_benchmarks.py --mode stress --parallel
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.error


class Colors:
    """Terminal colors for output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class BenchmarkRunner:
    """Main benchmark orchestration class"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)
        self.start_time = None
        self.end_time = None
        
    def run(self) -> int:
        """Execute benchmark suite and return exit code"""
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}RawrXD Benchmark Suite Automation{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        self.start_time = time.time()
        
        try:
            # Setup phase
            if not self._setup():
                return 1
            
            # Health check phase
            if not self._health_check():
                return 1
            
            # Run benchmarks
            results = self._run_benchmarks()
            
            # Process results
            self._process_results(results)
            
            # Cleanup
            self._cleanup()
            
            self.end_time = time.time()
            
            # Print summary
            self._print_summary(results)
            
            # Notify if configured
            if self.config.get('notify'):
                self._notify(results)
            
            return 0 if results.get('success', False) else 1
            
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}Benchmark run interrupted by user{Colors.ENDC}")
            return 130
        except Exception as e:
            print(f"\n{Colors.FAIL}Error: {e}{Colors.ENDC}")
            return 1
    
    def _setup(self) -> bool:
        """Setup environment and validate configuration"""
        print(f"{Colors.OKBLUE}[SETUP]{Colors.ENDC} Validating configuration...")
        
        # Check benchmark executable exists
        exe = self.config.get('executable', './benchmark_runner')
        if not Path(exe).exists():
            print(f"{Colors.FAIL}Benchmark executable not found: {exe}{Colors.ENDC}")
            return False
        
        # Create results directory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.run_dir = self.results_dir / f"run_{timestamp}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} Results directory: {self.run_dir}")
        return True
    
    def _health_check(self) -> bool:
        """Check backend health"""
        backend = self.config.get('backend', 'sovereign')
        
        if backend == 'sovereign':
            url = self.config.get('sovereign_url', 'http://localhost:8080')
        elif backend == 'ollama':
            url = self.config.get('ollama_url', 'http://localhost:11434')
        else:
            print(f"{Colors.WARNING}Unknown backend: {backend}, skipping health check{Colors.ENDC}")
            return True
        
        print(f"{Colors.OKBLUE}[HEALTH]{Colors.ENDC} Checking {backend} at {url}...")
        
        max_retries = 30
        for i in range(max_retries):
            try:
                urllib.request.urlopen(f"{url}/health", timeout=5)
                print(f"{Colors.OKGREEN}✓{Colors.ENDC} {backend} is healthy")
                return True
            except urllib.error.URLError:
                if i < max_retries - 1:
                    print(f"  Waiting... ({i+1}/{max_retries})")
                    time.sleep(2)
                else:
                    print(f"{Colors.FAIL}✗{Colors.ENDC} {backend} health check failed")
                    return False
        
        return False
    
    def _run_benchmarks(self) -> Dict:
        """Execute benchmark suite"""
        mode = self.config.get('mode', 'standard')
        backend = self.config.get('backend', 'sovereign')
        
        print(f"\n{Colors.OKBLUE}[RUN]{Colors.ENDC} Executing {mode} benchmarks...")
        print(f"{Colors.OKBLUE}[RUN]{Colors.ENDC} Backend: {backend}\n")
        
        # Build command
        cmd = [
            self.config.get('executable', './benchmark_runner'),
            f'--mode', mode,
            f'--backend', backend,
            f'--output-json', str(self.run_dir / 'results.json'),
            f'--output-junit', str(self.run_dir / 'junit.xml'),
        ]
        
        # Add optional arguments
        if self.config.get('compare_baseline'):
            baseline = self.config.get('baseline_file', 'baseline.json')
            if Path(baseline).exists():
                cmd.extend(['--compare-baseline', baseline])
        
        if self.config.get('timeout'):
            cmd.extend(['--timeout', str(self.config['timeout'])])
        
        if self.config.get('verbose'):
            cmd.append('--verbose')
        
        # Execute
        print(f"Command: {' '.join(cmd)}\n")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('timeout', 3600)
            )
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            
            # Load results
            results_file = self.run_dir / 'results.json'
            if results_file.exists():
                with open(results_file) as f:
                    results = json.load(f)
            else:
                results = {
                    'success': result.returncode == 0,
                    'error': 'No results file generated'
                }
            
            results['exit_code'] = result.returncode
            return results
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}Benchmark timed out{Colors.ENDC}")
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            print(f"{Colors.FAIL}Failed to run benchmarks: {e}{Colors.ENDC}")
            return {'success': False, 'error': str(e)}
    
    def _process_results(self, results: Dict):
        """Process and analyze benchmark results"""
        print(f"\n{Colors.OKBLUE}[PROCESS]{Colors.ENDC} Analyzing results...")
        
        # Generate HTML report
        html_report = self.run_dir / 'report.html'
        self._generate_html_report(results, html_report)
        
        # Generate markdown summary
        md_summary = self.run_dir / 'summary.md'
        self._generate_markdown_summary(results, md_summary)
        
        print(f"{Colors.OKGREEN}✓{Colors.ENDC} Reports generated")
    
    def _generate_html_report(self, results: Dict, output: Path):
        """Generate HTML dashboard"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Benchmark Results - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #333; color: white; padding: 20px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .metric {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .passed {{ color: green; }}
        .failed {{ color: red; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #333; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>RawrXD Benchmark Results</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <div class="metric">
            <h3>Total</h3>
            <p>{results.get('summary', {}).get('total_benchmarks', 0)}</p>
        </div>
        <div class="metric">
            <h3>Passed</h3>
            <p class="passed">{results.get('summary', {}).get('passed', 0)} ✅</p>
        </div>
        <div class="metric">
            <h3>Failed</h3>
            <p class="failed">{results.get('summary', {}).get('failed', 0)} {'❌' if results.get('summary', {}).get('failed', 0) > 0 else ''}</p>
        </div>
    </div>
    
    <h2>Benchmark Details</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Tier</th>
            <th>Status</th>
            <th>Duration</th>
        </tr>
"""
        
        for bench in results.get('benchmarks', []):
            status = '✅ PASSED' if bench.get('passed') else '❌ FAILED'
            html += f"""
        <tr>
            <td>{bench.get('name', 'Unknown')}</td>
            <td>{bench.get('tier', 'N/A')}</td>
            <td>{status}</td>
            <td>{bench.get('duration_seconds', 0):.2f}s</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        
        with open(output, 'w') as f:
            f.write(html)
    
    def _generate_markdown_summary(self, results: Dict, output: Path):
        """Generate markdown summary"""
        summary = f"""# Benchmark Results Summary

**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Mode**: {self.config.get('mode', 'standard')}
**Backend**: {self.config.get('backend', 'sovereign')}

## Summary

| Metric | Value |
|--------|-------|
| Total Benchmarks | {results.get('summary', {}).get('total_benchmarks', 0)} |
| Passed | {results.get('summary', {}).get('passed', 0)} ✅ |
| Failed | {results.get('summary', {}).get('failed', 0)} |
| Success Rate | {results.get('summary', {}).get('success_rate', 0):.1f}% |
| Duration | {results.get('summary', {}).get('total_duration_seconds', 0):.2f}s |

## Results

| Benchmark | Tier | Status | Duration |
|-----------|------|--------|----------|
"""
        
        for bench in results.get('benchmarks', []):
            status = '✅ PASS' if bench.get('passed') else '❌ FAIL'
            summary += f"| {bench.get('name')} | {bench.get('tier')} | {status} | {bench.get('duration_seconds', 0):.2f}s |\n"
        
        with open(output, 'w') as f:
            f.write(summary)
    
    def _cleanup(self):
        """Cleanup temporary files"""
        pass  # Keep results for analysis
    
    def _print_summary(self, results: Dict):
        """Print final summary"""
        duration = self.end_time - self.start_time if self.end_time else 0
        
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}Benchmark Summary{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        summary = results.get('summary', {})
        print(f"  Total Benchmarks: {summary.get('total_benchmarks', 0)}")
        print(f"  Passed: {Colors.OKGREEN}{summary.get('passed', 0)}{Colors.ENDC}")
        print(f"  Failed: {Colors.FAIL}{summary.get('failed', 0)}{Colors.ENDC}")
        print(f"  Duration: {duration:.2f}s")
        
        if results.get('success'):
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}✓ All benchmarks passed{Colors.ENDC}")
        else:
            print(f"\n{Colors.FAIL}{Colors.BOLD}✗ Some benchmarks failed{Colors.ENDC}")
        
        print(f"\n{Colors.OKBLUE}Results saved to: {self.run_dir}{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    def _notify(self, results: Dict):
        """Send notification"""
        notify_type = self.config.get('notify')
        
        if notify_type == 'slack':
            self._notify_slack(results)
        elif notify_type == 'discord':
            self._notify_discord(results)
    
    def _notify_slack(self, results: Dict):
        """Send Slack notification with benchmark results"""
        webhook = os.environ.get('SLACK_WEBHOOK_URL')
        if not webhook:
            return
        
        summary = results.get('summary', {})
        total = summary.get('total', 0)
        passed = summary.get('passed', 0)
        failed = summary.get('failed', 0)
        duration = summary.get('duration_seconds', 0)
        
        # Build Slack message payload
        color = "good" if failed == 0 else "danger" if failed == total else "warning"
        status_emoji = "✅" if failed == 0 else "❌"
        
        payload = {
            "attachments": [{
                "color": color,
                "title": f"{status_emoji} Benchmark Run Complete",
                "fields": [
                    {"title": "Total", "value": str(total), "short": True},
                    {"title": "Passed", "value": str(passed), "short": True},
                    {"title": "Failed", "value": str(failed), "short": True},
                    {"title": "Duration", "value": f"{duration:.1f}s", "short": True}
                ],
                "footer": "RawrXD Benchmark Suite",
                "ts": int(time.time())
            }]
        }
        
        try:
            req = urllib.request.Request(
                webhook,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"{Colors.OKBLUE}[NOTIFY]{Colors.ENDC} Slack notification sent")
                else:
                    print(f"{Colors.WARNING}[NOTIFY]{Colors.ENDC} Slack notification failed: {response.status}")
        except urllib.error.URLError as e:
            print(f"{Colors.WARNING}[NOTIFY]{Colors.ENDC} Failed to send Slack notification: {e}")
    
    def _notify_discord(self, results: Dict):
        """Send Discord notification with benchmark results"""
        webhook = os.environ.get('DISCORD_WEBHOOK_URL')
        if not webhook:
            return
        
        summary = results.get('summary', {})
        total = summary.get('total', 0)
        passed = summary.get('passed', 0)
        failed = summary.get('failed', 0)
        duration = summary.get('duration_seconds', 0)
        
        # Build Discord embed
        color = 0x00ff00 if failed == 0 else 0xff0000 if failed == total else 0xffa500
        
        payload = {
            "embeds": [{
                "title": "Benchmark Run Complete",
                "color": color,
                "fields": [
                    {"name": "Total", "value": str(total), "inline": True},
                    {"name": "Passed", "value": str(passed), "inline": True},
                    {"name": "Failed", "value": str(failed), "inline": True},
                    {"name": "Duration", "value": f"{duration:.1f}s", "inline": True}
                ],
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }]
        }
        
        try:
            req = urllib.request.Request(
                webhook,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 204:
                    print(f"{Colors.OKBLUE}[NOTIFY]{Colors.ENDC} Discord notification sent")
                else:
                    print(f"{Colors.WARNING}[NOTIFY]{Colors.ENDC} Discord notification failed: {response.status}")
        except urllib.error.URLError as e:
            print(f"{Colors.WARNING}[NOTIFY]{Colors.ENDC} Failed to send Discord notification: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='RawrXD Benchmark Suite Automation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --mode quick
  %(prog)s --mode standard --backend ollama
  %(prog)s --mode stress --timeout 7200
  %(prog)s --mode ci --notify slack
        """
    )
    
    parser.add_argument('--mode', choices=['quick', 'standard', 'stress', 'ci'],
                       default='standard', help='Benchmark mode')
    parser.add_argument('--backend', choices=['sovereign', 'ollama'],
                       default='sovereign', help='Backend to test')
    parser.add_argument('--executable', default='./benchmark_runner',
                       help='Path to benchmark executable')
    parser.add_argument('--timeout', type=int, default=3600,
                       help='Timeout in seconds')
    parser.add_argument('--compare-baseline', action='store_true',
                       help='Compare against baseline')
    parser.add_argument('--baseline-file', default='baseline.json',
                       help='Baseline results file')
    parser.add_argument('--notify', choices=['slack', 'discord'],
                       help='Send notification on completion')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    config = vars(args)
    runner = BenchmarkRunner(config)
    exit_code = runner.run()
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
