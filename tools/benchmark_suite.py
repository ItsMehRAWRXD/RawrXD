#!/usr/bin/env python3
"""
RawrXD Comprehensive Benchmark Suite

Advanced benchmarking tool for measuring LLM inference performance
across multiple dimensions: throughput, latency, memory, and scalability.

Usage:
    python benchmark_suite.py --url http://localhost:8080 --model llama-7b
    python benchmark_suite.py --suite all --duration 300
    python benchmark_suite.py --compare models.txt
"""

import argparse
import asyncio
import json
import statistics
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple
import aiohttp
import numpy as np
from datetime import datetime
import csv


@dataclass
class BenchmarkConfig:
    """Benchmark configuration."""
    url: str
    model: str
    num_requests: int = 100
    concurrency: int = 10
    prompt_length: int = 512
    max_tokens: int = 128
    warmup: int = 5
    duration: Optional[int] = None  # Duration in seconds (overrides num_requests)


@dataclass
class LatencyMetrics:
    """Latency measurement results."""
    mean: float
    median: float
    p50: float
    p90: float
    p95: float
    p99: float
    min: float
    max: float
    std: float


@dataclass
class ThroughputMetrics:
    """Throughput measurement results."""
    requests_per_second: float
    tokens_per_second: float
    total_tokens: int
    total_requests: int


@dataclass
class MemoryMetrics:
    """Memory usage results."""
    peak_memory_mb: float
    avg_memory_mb: float
    gpu_memory_mb: Optional[float]
    cache_usage_mb: float


@dataclass
class BenchmarkResult:
    """Complete benchmark results."""
    name: str
    timestamp: str
    config: BenchmarkConfig
    latency: LatencyMetrics
    throughput: ThroughputMetrics
    memory: Optional[MemoryMetrics]
    success_rate: float
    errors: List[str]
    raw_data: List[Dict]


class RawrXDBenchmark:
    """Comprehensive benchmark runner."""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.results: List[Dict] = []
        self.errors: List[str] = []
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=120)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def _generate_prompt(self, length: int) -> str:
        """Generate a test prompt of specified length."""
        words = [
            "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog",
            "machine", "learning", "artificial", "intelligence", "neural",
            "network", "deep", "model", "training", "inference", "token"
        ]
        prompt = ""
        while len(prompt) < length:
            prompt += " ".join(words) + " "
        return prompt[:length]
    
    async def _make_request(self, prompt: str) -> Optional[Dict]:
        """Make a single inference request."""
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "max_tokens": self.config.max_tokens,
            "temperature": 0.7,
            "stream": False
        }
        
        start_time = time.perf_counter()
        
        try:
            async with self.session.post(
                f"{self.config.url}/v1/completions",
                json=payload
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    self.errors.append(f"HTTP {response.status}: {error_text}")
                    return None
                
                data = await response.json()
                end_time = time.perf_counter()
                
                latency_ms = (end_time - start_time) * 1000
                tokens_generated = data.get('usage', {}).get('completion_tokens', 0)
                
                return {
                    'latency_ms': latency_ms,
                    'tokens_generated': tokens_generated,
                    'tokens_per_second': tokens_generated / (latency_ms / 1000) if latency_ms > 0 else 0,
                    'success': True
                }
                
        except Exception as e:
            self.errors.append(str(e))
            return None
    
    async def _worker(self, queue: asyncio.Queue, progress: asyncio.Event):
        """Worker coroutine to process requests."""
        while True:
            try:
                prompt = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if progress.is_set():
                    break
                continue
            
            result = await self._make_request(prompt)
            if result:
                self.results.append(result)
            queue.task_done()
    
    async def run_latency_benchmark(self) -> BenchmarkResult:
        """Run latency-focused benchmark."""
        print(f"\n{'='*60}")
        print("LATENCY BENCHMARK")
        print(f"{'='*60}")
        print(f"Configuration:")
        print(f"  URL: {self.config.url}")
        print(f"  Model: {self.config.model}")
        print(f"  Requests: {self.config.num_requests}")
        print(f"  Concurrency: {self.config.concurrency}")
        print(f"  Prompt Length: {self.config.prompt_length}")
        print(f"  Max Tokens: {self.config.max_tokens}")
        
        # Warmup
        if self.config.warmup > 0:
            print(f"\nWarming up with {self.config.warmup} requests...")
            warmup_prompt = self._generate_prompt(self.config.prompt_length)
            for _ in range(self.config.warmup):
                await self._make_request(warmup_prompt)
        
        # Main benchmark
        print(f"\nRunning benchmark...")
        self.results = []
        
        queue = asyncio.Queue(maxsize=self.config.concurrency * 2)
        progress = asyncio.Event()
        
        # Start workers
        workers = [
            asyncio.create_task(self._worker(queue, progress))
            for _ in range(self.config.concurrency)
        ]
        
        # Queue requests
        prompts = [
            self._generate_prompt(self.config.prompt_length)
            for _ in range(self.config.num_requests)
        ]
        
        start_time = time.perf_counter()
        
        for prompt in prompts:
            await queue.put(prompt)
        
        # Wait for completion
        await queue.join()
        progress.set()
        await asyncio.gather(*workers, return_exceptions=True)
        
        end_time = time.perf_counter()
        
        return self._analyze_results("Latency Benchmark", start_time, end_time)
    
    async def run_throughput_benchmark(self) -> BenchmarkResult:
        """Run throughput-focused benchmark."""
        print(f"\n{'='*60}")
        print("THROUGHPUT BENCHMARK")
        print(f"{'='*60}")
        
        # Use higher concurrency for throughput test
        original_concurrency = self.config.concurrency
        self.config.concurrency = max(self.config.concurrency * 2, 20)
        
        result = await self.run_latency_benchmark()
        
        self.config.concurrency = original_concurrency
        result.name = "Throughput Benchmark"
        
        return result
    
    async def run_stress_test(self) -> BenchmarkResult:
        """Run stress test for duration."""
        if not self.config.duration:
            print("Error: Duration required for stress test")
            return None
        
        print(f"\n{'='*60}")
        print(f"STRESS TEST ({self.config.duration}s)")
        print(f"{'='*60}")
        
        self.results = []
        start_time = time.perf_counter()
        end_time = start_time + self.config.duration
        
        async def stress_worker():
            prompt = self._generate_prompt(self.config.prompt_length)
            while time.perf_counter() < end_time:
                result = await self._make_request(prompt)
                if result:
                    self.results.append(result)
        
        # Run stress workers
        await asyncio.gather(*[
            stress_worker()
            for _ in range(self.config.concurrency)
        ])
        
        actual_end_time = time.perf_counter()
        return self._analyze_results("Stress Test", start_time, actual_end_time)
    
    def _analyze_results(self, name: str, start_time: float, end_time: float) -> BenchmarkResult:
        """Analyze benchmark results."""
        duration = end_time - start_time
        
        if not self.results:
            print("\nNo successful requests!")
            return BenchmarkResult(
                name=name,
                timestamp=datetime.now().isoformat(),
                config=self.config,
                latency=LatencyMetrics(0, 0, 0, 0, 0, 0, 0, 0, 0),
                throughput=ThroughputMetrics(0, 0, 0, 0),
                memory=None,
                success_rate=0.0,
                errors=self.errors,
                raw_data=[]
            )
        
        # Calculate latency metrics
        latencies = [r['latency_ms'] for r in self.results]
        latency = LatencyMetrics(
            mean=statistics.mean(latencies),
            median=statistics.median(latencies),
            p50=np.percentile(latencies, 50),
            p90=np.percentile(latencies, 90),
            p95=np.percentile(latencies, 95),
            p99=np.percentile(latencies, 99),
            min=min(latencies),
            max=max(latencies),
            std=statistics.stdev(latencies) if len(latencies) > 1 else 0
        )
        
        # Calculate throughput metrics
        total_tokens = sum(r['tokens_generated'] for r in self.results)
        throughput = ThroughputMetrics(
            requests_per_second=len(self.results) / duration,
            tokens_per_second=total_tokens / duration,
            total_tokens=total_tokens,
            total_requests=len(self.results)
        )
        
        # Calculate success rate
        success_rate = len(self.results) / self.config.num_requests * 100
        
        result = BenchmarkResult(
            name=name,
            timestamp=datetime.now().isoformat(),
            config=self.config,
            latency=latency,
            throughput=throughput,
            memory=None,  # Would need server metrics
            success_rate=success_rate,
            errors=self.errors,
            raw_data=self.results
        )
        
        self._print_results(result)
        return result
    
    def _print_results(self, result: BenchmarkResult):
        """Print benchmark results."""
        print(f"\n{'='*60}")
        print("RESULTS")
        print(f"{'='*60}")
        
        print(f"\nLatency (ms):")
        print(f"  Mean:   {result.latency.mean:.2f}")
        print(f"  Median: {result.latency.median:.2f}")
        print(f"  P50:    {result.latency.p50:.2f}")
        print(f"  P90:    {result.latency.p90:.2f}")
        print(f"  P95:    {result.latency.p95:.2f}")
        print(f"  P99:    {result.latency.p99:.2f}")
        print(f"  Min:    {result.latency.min:.2f}")
        print(f"  Max:    {result.latency.max:.2f}")
        print(f"  Std:    {result.latency.std:.2f}")
        
        print(f"\nThroughput:")
        print(f"  Requests/sec: {result.throughput.requests_per_second:.2f}")
        print(f"  Tokens/sec:   {result.throughput.tokens_per_second:.2f}")
        print(f"  Total tokens: {result.throughput.total_tokens}")
        
        print(f"\nSuccess Rate: {result.success_rate:.1f}%")
        if result.errors:
            print(f"Errors: {len(result.errors)}")
    
    def save_results(self, result: BenchmarkResult, filename: str):
        """Save results to JSON file."""
        data = asdict(result)
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\nResults saved to {filename}")
    
    def export_csv(self, result: BenchmarkResult, filename: str):
        """Export raw data to CSV."""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['latency_ms', 'tokens_generated', 'tokens_per_second'])
            for row in result.raw_data:
                writer.writerow([
                    row['latency_ms'],
                    row['tokens_generated'],
                    row['tokens_per_second']
                ])
        print(f"Raw data exported to {filename}")


async def main():
    parser = argparse.ArgumentParser(
        description="RawrXD Comprehensive Benchmark Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url http://localhost:8080 --model llama-7b
  %(prog)s --suite all --duration 300
  %(prog)s --compare models.txt --output results.json
        """
    )
    
    parser.add_argument('--url', default='http://localhost:8080',
                       help='RawrXD server URL')
    parser.add_argument('--model', default='llama-7b',
                       help='Model to benchmark')
    parser.add_argument('--requests', type=int, default=100,
                       help='Number of requests')
    parser.add_argument('--concurrency', type=int, default=10,
                       help='Concurrent requests')
    parser.add_argument('--prompt-len', type=int, default=512,
                       help='Prompt length')
    parser.add_argument('--max-tokens', type=int, default=128,
                       help='Max tokens to generate')
    parser.add_argument('--warmup', type=int, default=5,
                       help='Warmup requests')
    parser.add_argument('--duration', type=int,
                       help='Test duration in seconds (for stress test)')
    parser.add_argument('--suite', choices=['latency', 'throughput', 'stress', 'all'],
                       default='latency', help='Benchmark suite to run')
    parser.add_argument('--output', default='benchmark_results.json',
                       help='Output file for results')
    parser.add_argument('--csv', help='Export raw data to CSV')
    
    args = parser.parse_args()
    
    config = BenchmarkConfig(
        url=args.url,
        model=args.model,
        num_requests=args.requests,
        concurrency=args.concurrency,
        prompt_length=args.prompt_len,
        max_tokens=args.max_tokens,
        warmup=args.warmup,
        duration=args.duration
    )
    
    async with RawrXDBenchmark(config) as benchmark:
        results = []
        
        if args.suite in ['latency', 'all']:
            result = await benchmark.run_latency_benchmark()
            results.append(result)
        
        if args.suite in ['throughput', 'all']:
            result = await benchmark.run_throughput_benchmark()
            results.append(result)
        
        if args.suite in ['stress', 'all'] and args.duration:
            result = await benchmark.run_stress_test()
            if result:
                results.append(result)
        
        # Save results
        if len(results) == 1:
            benchmark.save_results(results[0], args.output)
            if args.csv:
                benchmark.export_csv(results[0], args.csv)
        else:
            # Save multiple results
            data = {'benchmarks': [asdict(r) for r in results]}
            with open(args.output, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"\nAll results saved to {args.output}")


if __name__ == '__main__':
    asyncio.run(main())
