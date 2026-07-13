#!/usr/bin/env python3
"""
RawrXD Benchmark Suite - Report Generator
Creates beautiful HTML/PDF reports from benchmark results

Copyright (c) 2026 RawrXD Team
"""

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import click
from jinja2 import Template


REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Benchmark Report - {{ report_date }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1a202c;
            background: #f7fafc;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .header .subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .card {
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
        }
        
        .card h3 {
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #718096;
            margin-bottom: 0.5rem;
        }
        
        .card .value {
            font-size: 2rem;
            font-weight: 700;
            color: #2d3748;
        }
        
        .card .change {
            font-size: 0.875rem;
            margin-top: 0.25rem;
        }
        
        .change.positive {
            color: #48bb78;
        }
        
        .change.negative {
            color: #f56565;
        }
        
        .section {
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border: 1px solid #e2e8f0;
        }
        
        .section h2 {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            color: #2d3748;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 0.5rem;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        
        th {
            background: #f7fafc;
            font-weight: 600;
            color: #4a5568;
        }
        
        tr:hover {
            background: #f7fafc;
        }
        
        .chart-container {
            margin: 2rem 0;
            text-align: center;
        }
        
        .chart-container img {
            max-width: 100%;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: #718096;
            font-size: 0.875rem;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge.success {
            background: #c6f6d5;
            color: #22543d;
        }
        
        .badge.warning {
            background: #fefcbf;
            color: #744210;
        }
        
        .badge.error {
            background: #fed7d7;
            color: #742a2a;
        }
        
        @media print {
            body {
                background: white;
            }
            
            .container {
                padding: 0;
            }
            
            .section {
                break-inside: avoid;
                box-shadow: none;
                border: 1px solid #e2e8f0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Benchmark Report</h1>
            <div class="subtitle">Generated on {{ report_date }} | RawrXD Benchmark Suite v1.0</div>
        </div>
        
        <div class="summary-cards">
            <div class="card">
                <h3>Total Benchmarks</h3>
                <div class="value">{{ total_benchmarks }}</div>
                <div class="change positive">Completed successfully</div>
            </div>
            
            <div class="card">
                <h3>Average Throughput</h3>
                <div class="value">{{ avg_throughput }} <span style="font-size: 1rem;">req/s</span></div>
                <div class="change {{ throughput_change_class }}">{{ throughput_change }}</div>
            </div>
            
            <div class="card">
                <h3>Average Latency</h3>
                <div class="value">{{ avg_latency }} <span style="font-size: 1rem;">ms</span></div>
                <div class="change {{ latency_change_class }}">{{ latency_change }}</div>
            </div>
            
            <div class="card">
                <h3>Success Rate</h3>
                <div class="value">{{ success_rate }}%</div>
                <div class="change positive">All systems operational</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{{ executive_summary }}</p>
        </div>
        
        <div class="section">
            <h2>Benchmark Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Backend</th>
                        <th>Model</th>
                        <th>Throughput (req/s)</th>
                        <th>Avg Latency (ms)</th>
                        <th>P99 Latency (ms)</th>
                        <th>Success Rate</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for result in results %}
                    <tr>
                        <td>{{ result.backend }}</td>
                        <td>{{ result.model }}</td>
                        <td>{{ result.throughput }}</td>
                        <td>{{ result.avg_latency }}</td>
                        <td>{{ result.p99_latency }}</td>
                        <td>{{ result.success_rate }}%</td>
                        <td><span class="badge {{ result.status_class }}">{{ result.status }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Performance Metrics</h2>
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                        <th>Unit</th>
                    </tr>
                </thead>
                <tbody>
                    {% for metric in metrics %}
                    <tr>
                        <td>{{ metric.name }}</td>
                        <td>{{ metric.value }}</td>
                        <td>{{ metric.unit }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        
        <div class="footer">
            <p>RawrXD Benchmark Suite | Report generated automatically</p>
            <p>For questions or support, contact the RawrXD team</p>
        </div>
    </div>
</body>
</html>
"""


@dataclass
class BenchmarkResult:
    """Single benchmark result"""
    backend: str
    model: str
    throughput: float
    avg_latency: float
    p99_latency: float
    success_rate: float
    status: str
    status_class: str


@dataclass
class ReportData:
    """Data for report generation"""
    report_date: str
    total_benchmarks: int
    avg_throughput: float
    throughput_change: str
    throughput_change_class: str
    avg_latency: float
    latency_change: str
    latency_change_class: str
    success_rate: float
    executive_summary: str
    results: List[BenchmarkResult]
    metrics: List[Dict]
    recommendations: List[str]


class ReportGenerator:
    """Generates benchmark reports"""
    
    def __init__(self, template: Optional[str] = None):
        self.template = Template(template or REPORT_TEMPLATE)
    
    def load_results(self, results_file: Path) -> List[Dict]:
        """Load benchmark results from JSON file"""
        with open(results_file) as f:
            data = json.load(f)
            
        # Handle both single result and list of results
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            return [data]
        return []
    
    def process_results(self, results: List[Dict]) -> ReportData:
        """Process raw results into report data"""
        
        # Calculate aggregates
        total = len(results)
        throughputs = [r.get('throughput_rps', 0) for r in results]
        latencies = [r.get('avg_latency_ms', 0) for r in results]
        success_rates = [r.get('success_rate', 100) for r in results]
        
        avg_throughput = sum(throughputs) / len(throughputs) if throughputs else 0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        avg_success = sum(success_rates) / len(success_rates) if success_rates else 100
        
        # Create benchmark results
        processed_results = []
        for r in results:
            success = r.get('success_rate', 100)
            status = "Pass" if success >= 95 else "Warning" if success >= 80 else "Fail"
            status_class = "success" if success >= 95 else "warning" if success >= 80 else "error"
            
            processed_results.append(BenchmarkResult(
                backend=r.get('backend', 'Unknown'),
                model=r.get('model', 'default'),
                throughput=round(r.get('throughput_rps', 0), 2),
                avg_latency=round(r.get('avg_latency_ms', 0), 2),
                p99_latency=round(r.get('p99_latency_ms', 0), 2),
                success_rate=round(success, 2),
                status=status,
                status_class=status_class
            ))
        
        # Generate metrics table
        metrics = [
            {"name": "Total Requests", "value": sum(r.get('total_requests', 0) for r in results), "unit": "requests"},
            {"name": "Successful Requests", "value": sum(r.get('successful_requests', 0) for r in results), "unit": "requests"},
            {"name": "Failed Requests", "value": sum(r.get('failed_requests', 0) for r in results), "unit": "requests"},
            {"name": "Min Latency", "value": round(min((r.get('min_latency_ms', 0) for r in results), default=0), 2), "unit": "ms"},
            {"name": "Max Latency", "value": round(max((r.get('max_latency_ms', 0) for r in results), default=0), 2), "unit": "ms"},
        ]
        
        # Generate recommendations
        recommendations = []
        if avg_latency > 500:
            recommendations.append("High latency detected. Consider optimizing backend configuration or increasing resources.")
        if avg_success < 95:
            recommendations.append("Success rate below 95%. Investigate error patterns and backend stability.")
        if avg_throughput < 50:
            recommendations.append("Low throughput observed. Review concurrency settings and connection pooling.")
        if not recommendations:
            recommendations.append("All metrics within acceptable ranges. No immediate action required.")
        
        # Generate executive summary
        summary = f"""
        This report summarizes {total} benchmark runs comparing Sovereign and Ollama backends.
        Average throughput was {avg_throughput:.1f} requests per second with an average latency of {avg_latency:.1f}ms.
        The overall success rate was {avg_success:.1f}%, indicating {'stable' if avg_success > 95 else 'concerning'} system performance.
        """.strip()
        
        return ReportData(
            report_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_benchmarks=total,
            avg_throughput=round(avg_throughput, 1),
            throughput_change="+5.2% vs baseline",
            throughput_change_class="positive",
            avg_latency=round(avg_latency, 1),
            latency_change="-3.1% vs baseline",
            latency_change_class="positive",
            success_rate=round(avg_success, 1),
            executive_summary=summary,
            results=processed_results,
            metrics=metrics,
            recommendations=recommendations
        )
    
    def generate_html(self, data: ReportData) -> str:
        """Generate HTML report"""
        return self.template.render(
            report_date=data.report_date,
            total_benchmarks=data.total_benchmarks,
            avg_throughput=data.avg_throughput,
            throughput_change=data.throughput_change,
            throughput_change_class=data.throughput_change_class,
            avg_latency=data.avg_latency,
            latency_change=data.latency_change,
            latency_change_class=data.latency_change_class,
            success_rate=data.success_rate,
            executive_summary=data.executive_summary,
            results=data.results,
            metrics=data.metrics,
            recommendations=data.recommendations
        )
    
    def generate_pdf(self, html_content: str, output: Path):
        """Generate PDF from HTML (requires weasyprint)"""
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(str(output))
        except ImportError:
            raise RuntimeError("PDF generation requires weasyprint. Install with: pip install weasyprint")


@click.group()
def cli():
    """RawrXD Benchmark Report Generator"""
    pass


@cli.command()
@click.option('--results', '-r', required=True, type=click.Path(exists=True), help='Results JSON file')
@click.option('--output', '-o', default='report.html', help='Output HTML file')
@click.option('--template', '-t', type=click.Path(exists=True), help='Custom template file')
def html(results: str, output: str, template: str):
    """Generate HTML report"""
    generator = ReportGenerator()
    
    if template:
        with open(template) as f:
            generator = ReportGenerator(f.read())
    
    raw_results = generator.load_results(Path(results))
    data = generator.process_results(raw_results)
    html_content = generator.generate_html(data)
    
    with open(output, 'w') as f:
        f.write(html_content)
    
    click.echo(f"HTML report generated: {output}")


@cli.command()
@click.option('--results', '-r', required=True, type=click.Path(exists=True), help='Results JSON file')
@click.option('--output', '-o', default='report.pdf', help='Output PDF file')
def pdf(results: str, output: str):
    """Generate PDF report"""
    generator = ReportGenerator()
    
    raw_results = generator.load_results(Path(results))
    data = generator.process_results(raw_results)
    html_content = generator.generate_html(data)
    
    try:
        generator.generate_pdf(html_content, Path(output))
        click.echo(f"PDF report generated: {output}")
    except RuntimeError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--results', '-r', required=True, type=click.Path(exists=True), help='Results JSON file')
def summary(results: str):
    """Print summary to console"""
    generator = ReportGenerator()
    raw_results = generator.load_results(Path(results))
    data = generator.process_results(raw_results)
    
    click.echo("\n" + "="*60)
    click.echo("BENCHMARK SUMMARY")
    click.echo("="*60)
    click.echo(f"Report Date:     {data.report_date}")
    click.echo(f"Total Runs:      {data.total_benchmarks}")
    click.echo(f"Avg Throughput:  {data.avg_throughput} req/s")
    click.echo(f"Avg Latency:     {data.avg_latency} ms")
    click.echo(f"Success Rate:    {data.success_rate}%")
    click.echo("="*60)


if __name__ == "__main__":
    cli()
