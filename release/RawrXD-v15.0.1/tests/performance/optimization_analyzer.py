#!/usr/bin/env python3
"""
RawrXD Performance Optimization Analyzer
Identifies bottlenecks and suggests optimizations
"""

import json
import sys
from pathlib import Path
from datetime import datetime

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text):
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}{text.center(70)}{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*70}{Colors.RESET}\n")

def print_section(text):
    print(f"\n{Colors.CYAN}▶ {text}{Colors.RESET}")

def print_success(text):
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_error(text):
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

class OptimizationAnalyzer:
    def __init__(self):
        self.benchmarks = {}
        self.recommendations = []
        
    def load_benchmarks(self):
        """Load benchmark results"""
        print_section("Loading Benchmark Data")
        
        # Check for perf_results.json
        perf_file = Path("tests/performance/perf_results.json")
        if perf_file.exists():
            try:
                with open(perf_file) as f:
                    self.benchmarks = json.load(f)
                print_success(f"Loaded {len(self.benchmarks)} benchmark results")
            except Exception as e:
                print_warning(f"Could not load perf_results.json: {e}")
        else:
            print_warning("No perf_results.json found, using defaults")
            self.benchmarks = {
                "matmul": {"gops": 4.37, "status": "baseline"},
                "softmax": {"ops_per_sec": 614400000, "status": "baseline"},
                "rmsnorm": {"ops_per_sec": 409600000, "status": "baseline"}
            }
    
    def analyze_matmul(self):
        """Analyze matmul performance"""
        print_section("Analyzing Matrix Multiplication")
        
        matmul = self.benchmarks.get("matmul", {})
        gops = matmul.get("gops", 0)
        
        print_info(f"Current performance: {gops:.2f} GOPS")
        
        # Analysis
        if gops < 1.0:
            print_error("CRITICAL: Matmul performance is very low")
            self.recommendations.append({
                "kernel": "matmul",
                "priority": "CRITICAL",
                "issue": "Performance below 1 GOPS",
                "suggestions": [
                    "Enable compiler optimizations (-O3 -march=native)",
                    "Use AVX2 intrinsics for vectorization",
                    "Implement cache blocking (tiling)",
                    "Consider using BLAS library (OpenBLAS, MKL)",
                    "Profile memory access patterns"
                ]
            })
        elif gops < 5.0:
            print_warning("Matmul performance could be improved")
            self.recommendations.append({
                "kernel": "matmul",
                "priority": "HIGH",
                "issue": "Performance below 5 GOPS",
                "suggestions": [
                    "Add AVX2/AVX-512 vectorization",
                    "Optimize loop ordering for cache efficiency",
                    "Consider loop unrolling",
                    "Profile with VTune or perf"
                ]
            })
        else:
            print_success("Matmul performance is good")
    
    def analyze_softmax(self):
        """Analyze softmax performance"""
        print_section("Analyzing Softmax")
        
        softmax = self.benchmarks.get("softmax", {})
        ops_per_sec = softmax.get("ops_per_sec", 0)
        
        print_info(f"Current performance: {ops_per_sec/1e6:.2f} M ops/sec")
        
        # Analysis
        if ops_per_sec < 100000000:  # 100M ops/sec
            print_error("CRITICAL: Softmax performance is very low")
            self.recommendations.append({
                "kernel": "softmax",
                "priority": "CRITICAL",
                "issue": "Performance below 100M ops/sec",
                "suggestions": [
                    "Vectorize with AVX2 (_mm256_* intrinsics)",
                    "Use fast approximations for exp()",
                    "Consider numerical stability optimizations",
                    "Batch processing for multiple vectors"
                ]
            })
        elif ops_per_sec < 500000000:  # 500M ops/sec
            print_warning("Softmax performance could be improved")
            self.recommendations.append({
                "kernel": "softmax",
                "priority": "MEDIUM",
                "issue": "Performance below 500M ops/sec",
                "suggestions": [
                    "Add SIMD vectorization",
                    "Optimize memory access patterns",
                    "Consider fused operations"
                ]
            })
        else:
            print_success("Softmax performance is good")
    
    def analyze_rmsnorm(self):
        """Analyze RMSNorm performance"""
        print_section("Analyzing RMSNorm")
        
        rmsnorm = self.benchmarks.get("rmsnorm", {})
        ops_per_sec = rmsnorm.get("ops_per_sec", 0)
        
        print_info(f"Current performance: {ops_per_sec/1e6:.2f} M ops/sec")
        
        # Analysis
        if ops_per_sec < 100000000:
            print_error("CRITICAL: RMSNorm performance is very low")
            self.recommendations.append({
                "kernel": "rmsnorm",
                "priority": "CRITICAL",
                "issue": "Performance below 100M ops/sec",
                "suggestions": [
                    "Vectorize sum of squares with AVX2",
                    "Use fast reciprocal square root",
                    "Fuse operations to reduce memory passes",
                    "Consider in-place computation"
                ]
            })
        elif ops_per_sec < 400000000:
            print_warning("RMSNorm performance could be improved")
            self.recommendations.append({
                "kernel": "rmsnorm",
                "priority": "MEDIUM",
                "issue": "Performance below 400M ops/sec",
                "suggestions": [
                    "Add SIMD vectorization",
                    "Optimize sqrt computation",
                    "Profile memory bandwidth usage"
                ]
            })
        else:
            print_success("RMSNorm performance is good")
    
    def generate_optimization_plan(self):
        """Generate optimization plan"""
        print_section("Optimization Plan")
        
        if not self.recommendations:
            print_success("No critical optimizations needed!")
            return
        
        # Sort by priority
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        print(f"\nFound {len(self.recommendations)} optimization opportunities:\n")
        
        for i, rec in enumerate(self.recommendations, 1):
            color = Colors.RED if rec["priority"] == "CRITICAL" else \
                    Colors.YELLOW if rec["priority"] == "HIGH" else \
                    Colors.BLUE
            
            print(f"{color}[{rec['priority']}] {rec['kernel']}{Colors.RESET}")
            print(f"  Issue: {rec['issue']}")
            print(f"  Suggestions:")
            for suggestion in rec["suggestions"]:
                print(f"    • {suggestion}")
            print()
    
    def generate_report(self):
        """Generate JSON report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "benchmarks": self.benchmarks,
            "recommendations": self.recommendations,
            "summary": {
                "total_recommendations": len(self.recommendations),
                "critical": len([r for r in self.recommendations if r["priority"] == "CRITICAL"]),
                "high": len([r for r in self.recommendations if r["priority"] == "HIGH"]),
                "medium": len([r for r in self.recommendations if r["priority"] == "MEDIUM"])
            }
        }
        
        report_file = Path("optimization_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print_success(f"Report saved to: {report_file}")
        return report_file
    
    def run_analysis(self):
        """Run complete analysis"""
        print_header("RawrXD Performance Optimization Analyzer")
        
        self.load_benchmarks()
        self.analyze_matmul()
        self.analyze_softmax()
        self.analyze_rmsnorm()
        self.generate_optimization_plan()
        
        report_file = self.generate_report()
        
        print_header("Analysis Complete")
        
        if self.recommendations:
            critical = len([r for r in self.recommendations if r["priority"] == "CRITICAL"])
            if critical > 0:
                print_error(f"{critical} CRITICAL optimizations needed")
                print_info("Review optimization_report.json for details")
            else:
                print_warning(f"{len(self.recommendations)} optimizations suggested")
                print_info("See optimization_report.json for details")
        else:
            print_success("All kernels performing well!")
        
        return len([r for r in self.recommendations if r["priority"] == "CRITICAL"]) == 0

def main():
    analyzer = OptimizationAnalyzer()
    success = analyzer.run_analysis()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
