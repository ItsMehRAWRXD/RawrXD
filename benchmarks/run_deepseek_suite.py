#!/usr/bin/env python3
"""
DeepSeek 671B Benchmark Suite Runner

Runs comprehensive benchmarks across different configurations:
- Quantization levels (Q2_K, Q3_K, Q4_K_M, Q5_K_M, Q8_0)
- GPU layer offloading (0, 10, 20, 40, 61 layers)
- Batch sizes (1, 4, 8)
- Prompt lengths (512, 2048, 4096)

Generates comparative reports showing TPS improvements.
"""

import subprocess
import json
import os
import sys
import time
import statistics
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import argparse

@dataclass
class BenchmarkConfig:
    """Configuration for a single benchmark run"""
    quantization: str
    gpu_layers: int
    batch_size: int
    prompt_tokens: int
    generated_tokens: int
    backend: str  # "cpu", "vulkan", "cuda", "rocm"
    
    def name(self) -> str:
        return f"{self.quantization}_gpu{self.gpu_layers}_{self.backend}"

@dataclass
class BenchmarkResult:
    """Results from a benchmark run"""
    config: BenchmarkConfig
    prompt_tps: float
    generation_tps: float
    first_token_latency_ms: float
    avg_token_latency_ms: float
    total_time_ms: float
    router_time_ms: float
    expert_time_ms: float
    expert_load_balance: float
    peak_ram_gb: float
    peak_vram_gb: float
    
    # Derived metrics
    speedup_vs_baseline: float = 1.0
    tokens_per_joule: float = 0.0

class DeepSeekBenchmarkSuite:
    """Manages benchmark execution and reporting"""
    
    def __init__(self, output_dir: Path = Path("benchmark_results")):
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
        self.results: List[BenchmarkResult] = []
        
    def run_benchmark(self, config: BenchmarkConfig, 
                       model_path: str,
                       iterations: int = 3) -> Optional[BenchmarkResult]:
        """Run a single benchmark configuration multiple times"""
        
        print(f"\n{'='*60}")
        print(f"Running: {config.name()}")
        print(f"  Quantization: {config.quantization}")
        print(f"  GPU Layers: {config.gpu_layers}")
        print(f"  Backend: {config.backend}")
        print(f"  Prompt: {config.prompt_tokens} tokens")
        print(f"  Generation: {config.generated_tokens} tokens")
        print(f"  Iterations: {iterations}")
        print(f"{'='*60}\n")
        
        # Build command
        cmd = [
            "./deepseek_671b_benchmark",
            str(config.prompt_tokens),
            str(config.generated_tokens),
            str(self.output_dir / f"{config.name()}.json")
        ]
        
        # Set environment variables for configuration
        env = os.environ.copy()
        env["RAWRXD_QUANT"] = config.quantization
        env["RAWRXD_GPU_LAYERS"] = str(config.gpu_layers)
        env["RAWRXD_BACKEND"] = config.backend
        
        results = []
        
        for i in range(iterations):
            print(f"  Iteration {i+1}/{iterations}...")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=600  # 10 minute timeout
                )
                
                if result.returncode != 0:
                    print(f"    FAILED: {result.stderr}")
                    continue
                
                # Parse results from JSON output
                output_file = self.output_dir / f"{config.name()}.json"
                if output_file.exists():
                    with open(output_file) as f:
                        data = json.load(f)
                    
                    metrics = data.get("metrics", {})
                    results.append(BenchmarkResult(
                        config=config,
                        prompt_tps=metrics.get("prompt_tps", 0),
                        generation_tps=metrics.get("generation_tps", 0),
                        first_token_latency_ms=metrics.get("first_token_latency_ms", 0),
                        avg_token_latency_ms=metrics.get("avg_token_latency_ms", 0),
                        total_time_ms=metrics.get("total_time_ms", 0),
                        router_time_ms=metrics.get("router_time_ms", 0),
                        expert_time_ms=metrics.get("expert_time_ms", 0),
                        expert_load_balance=metrics.get("expert_load_balance", 0),
                        peak_ram_gb=metrics.get("peak_ram_gb", 0),
                        peak_vram_gb=metrics.get("peak_vram_gb", 0)
                    ))
                    
            except subprocess.TimeoutExpired:
                print(f"    TIMEOUT after 600s")
            except Exception as e:
                print(f"    ERROR: {e}")
        
        if not results:
            return None
        
        # Average results across iterations
        return BenchmarkResult(
            config=config,
            prompt_tps=statistics.mean([r.prompt_tps for r in results]),
            generation_tps=statistics.mean([r.generation_tps for r in results]),
            first_token_latency_ms=statistics.mean([r.first_token_latency_ms for r in results]),
            avg_token_latency_ms=statistics.mean([r.avg_token_latency_ms for r in results]),
            total_time_ms=statistics.mean([r.total_time_ms for r in results]),
            router_time_ms=statistics.mean([r.router_time_ms for r in results]),
            expert_time_ms=statistics.mean([r.expert_time_ms for r in results]),
            expert_load_balance=statistics.mean([r.expert_load_balance for r in results]),
            peak_ram_gb=max([r.peak_ram_gb for r in results]),
            peak_vram_gb=max([r.peak_vram_gb for r in results])
        )
    
    def run_quantization_comparison(self, model_path: str) -> None:
        """Compare different quantization levels"""
        
        print("\n" + "="*60)
        print("QUANTIZATION COMPARISON")
        print("="*60)
        
        quantizations = ["Q2_K", "Q3_K", "Q4_K_M", "Q5_K_M", "Q8_0"]
        
        for quant in quantizations:
            config = BenchmarkConfig(
                quantization=quant,
                gpu_layers=0,  # CPU only for fair comparison
                batch_size=1,
                prompt_tokens=512,
                generated_tokens=128,
                backend="cpu"
            )
            
            result = self.run_benchmark(config, model_path, iterations=3)
            if result:
                self.results.append(result)
    
    def run_gpu_offload_comparison(self, model_path: str) -> None:
        """Compare GPU layer offloading"""
        
        print("\n" + "="*60)
        print("GPU OFFLOAD COMPARISON")
        print("="*60)
        
        gpu_layers_list = [0, 10, 20, 40, 61]  # 61 = all layers
        
        for gpu_layers in gpu_layers_list:
            config = BenchmarkConfig(
                quantization="Q4_K_M",
                gpu_layers=gpu_layers,
                batch_size=1,
                prompt_tokens=2048,
                generated_tokens=512,
                backend="vulkan"  # or "cuda", "rocm"
            )
            
            result = self.run_benchmark(config, model_path, iterations=3)
            if result:
                self.results.append(result)
    
    def run_backend_comparison(self, model_path: str) -> None:
        """Compare different backends"""
        
        print("\n" + "="*60)
        print("BACKEND COMPARISON")
        print("="*60)
        
        backends = ["cpu", "vulkan"]  # Add "cuda", "rocm" if available
        
        for backend in backends:
            config = BenchmarkConfig(
                quantization="Q4_K_M",
                gpu_layers=40 if backend != "cpu" else 0,
                batch_size=1,
                prompt_tokens=2048,
                generated_tokens=512,
                backend=backend
            )
            
            result = self.run_benchmark(config, model_path, iterations=3)
            if result:
                self.results.append(result)
    
    def calculate_speedups(self) -> None:
        """Calculate speedup vs baseline"""
        
        # Find baseline (CPU Q4_K_M)
        baseline = None
        for r in self.results:
            if r.config.backend == "cpu" and r.config.quantization == "Q4_K_M":
                baseline = r
                break
        
        if not baseline:
            return
        
        for r in self.results:
            if r.config != baseline.config:
                r.speedup_vs_baseline = r.generation_tps / baseline.generation_tps
    
    def generate_report(self) -> None:
        """Generate comprehensive benchmark report"""
        
        self.calculate_speedups()
        
        report_file = self.output_dir / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(report_file, 'w') as f:
            f.write("# DeepSeek 671B MoE Benchmark Report\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Configurations Tested:** {len(self.results)}\n\n")
            
            # Summary table
            f.write("## Summary\n\n")
            f.write("| Configuration | Prompt TPS | Gen TPS | First Token | Speedup | RAM (GB) |\n")
            f.write("|--------------|------------|---------|-------------|---------|----------|\n")
            
            for r in sorted(self.results, key=lambda x: x.generation_tps, reverse=True):
                config_str = f"{r.config.quantization} {r.config.backend}"
                if r.config.gpu_layers > 0:
                    config_str += f" GPU{r.config.gpu_layers}"
                
                f.write(f"| {config_str} | {r.prompt_tps:.1f} | {r.generation_tps:.1f} | "
                       f"{r.first_token_latency_ms:.1f}ms | {r.speedup_vs_baseline:.2f}x | "
                       f"{r.peak_ram_gb:.1f} |\n")
            
            f.write("\n## Detailed Results\n\n")
            
            for r in self.results:
                f.write(f"### {r.config.name()}\n\n")
                f.write(f"- **Quantization:** {r.config.quantization}\n")
                f.write(f"- **GPU Layers:** {r.config.gpu_layers}\n")
                f.write(f"- **Backend:** {r.config.backend}\n")
                f.write(f"- **Prompt TPS:** {r.prompt_tps:.2f}\n")
                f.write(f"- **Generation TPS:** {r.generation_tps:.2f}\n")
                f.write(f"- **First Token Latency:** {r.first_token_latency_ms:.2f} ms\n")
                f.write(f"- **Avg Token Latency:** {r.avg_token_latency_ms:.2f} ms\n")
                f.write(f"- **Router Time:** {r.router_time_ms:.2f} ms\n")
                f.write(f"- **Expert Time:** {r.expert_time_ms:.2f} ms\n")
                f.write(f"- **Expert Load Balance:** {r.expert_load_balance:.4f}\n")
                f.write(f"- **Peak RAM:** {r.peak_ram_gb:.2f} GB\n")
                f.write(f"- **Peak VRAM:** {r.peak_vram_gb:.2f} GB\n")
                f.write(f"- **Speedup vs Baseline:** {r.speedup_vs_baseline:.2f}x\n\n")
            
            # MoE Analysis
            f.write("## MoE Analysis\n\n")
            f.write("### Expert Utilization\n\n")
            f.write("The DeepSeek 671B model uses sparse MoE with:\n")
            f.write(f"- **Total Experts:** 256 per layer\n")
            f.write(f"- **Active Experts:** 8 per token (top-k)\n")
            f.write(f"- **Sparsity:** {((256-8)/256)*100:.1f}%\n\n")
            
            f.write("### Load Balance\n\n")
            f.write("Load balance measured by Gini coefficient (0=perfect, 1=worst):\n\n")
            
            for r in self.results:
                f.write(f"- **{r.config.name()}:** {r.expert_load_balance:.4f}\n")
            
            f.write("\n## Conclusions\n\n")
            
            # Find best configuration
            if self.results:
                best = max(self.results, key=lambda x: x.generation_tps)
                f.write(f"**Best Configuration:** {best.config.name()}\n")
                f.write(f"- Generation TPS: {best.generation_tps:.2f}\n")
                f.write(f"- Speedup vs CPU baseline: {best.speedup_vs_baseline:.2f}x\n\n")
            
            f.write("### Recommendations\n\n")
            f.write("1. **For maximum throughput:** Use GPU offloading with Q4_K_M quantization\n")
            f.write("2. **For memory efficiency:** Use Q2_K or Q3_K quantization\n")
            f.write("3. **For quality:** Use Q5_K_M or Q8_0 quantization\n")
            f.write("4. **MoE efficiency:** Ensure router overhead stays below 10% of total time\n")
        
        print(f"\nReport saved to: {report_file}")
        
        # Also save JSON
        json_file = self.output_dir / f"benchmark_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_file, 'w') as f:
            results_dict = []
            for r in self.results:
                data = asdict(r)
                data['config'] = asdict(r.config)
                results_dict.append(data)
            json.dump(results_dict, f, indent=2)
        
        print(f"Results saved to: {json_file}")

def main():
    parser = argparse.ArgumentParser(description="DeepSeek 671B Benchmark Suite")
    parser.add_argument("--model", type=str, default="deepseek-671b-q4.gguf",
                       help="Path to model file")
    parser.add_argument("--quant-comparison", action="store_true",
                       help="Run quantization comparison")
    parser.add_argument("--gpu-comparison", action="store_true",
                       help="Run GPU offloading comparison")
    parser.add_argument("--backend-comparison", action="store_true",
                       help="Run backend comparison")
    parser.add_argument("--full-suite", action="store_true",
                       help="Run full benchmark suite")
    parser.add_argument("--output-dir", type=str, default="benchmark_results",
                       help="Output directory for results")
    
    args = parser.parse_args()
    
    suite = DeepSeekBenchmarkSuite(Path(args.output_dir))
    
    if args.full_suite or not any([args.quant_comparison, args.gpu_comparison, args.backend_comparison]):
        print("Running full benchmark suite...")
        suite.run_quantization_comparison(args.model)
        suite.run_gpu_offload_comparison(args.model)
        suite.run_backend_comparison(args.model)
    else:
        if args.quant_comparison:
            suite.run_quantization_comparison(args.model)
        if args.gpu_comparison:
            suite.run_gpu_offload_comparison(args.model)
        if args.backend_comparison:
            suite.run_backend_comparison(args.model)
    
    suite.generate_report()
    
    print("\n" + "="*60)
    print("BENCHMARK SUITE COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
