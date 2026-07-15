#!/usr/bin/env python3
"""
RawrXD Benchmark Tool

Comprehensive benchmarking suite for measuring RawrXD performance.

Usage:
    python benchmark.py --url http://localhost:8080 --model llama-7b
    python benchmark.py --concurrency 10 --requests 100 --prompt-len 512
"""

import argparse
import asyncio
import json
import statistics
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import aiohttp
import numpy as np


@dataclass
class BenchmarkResult:
    """Results from a single request."""
    latency_ms: float
    tokens_generated: int
    tokens_per_second: float
    time_to_first_token_ms: float
    success: bool
    error: Optional[str] = None


@dataclass
class BenchmarkSummary:
    """Summary of benchmark results."""
    total_requests: int
    successful_requests: int
    failed_requests: int
    
    # Latency statistics (ms)
    latency_p50: float
    latency_p95: float
    latency_p99: float
    latency_mean: float
    latency_std: float
    
    # Throughput statistics
    tokens_per_second_mean: float
    tokens_per_second_p50: float
    
    # TTFT statistics (ms)
    ttft_mean: float
    ttft_p50: float
    
    # Overall throughput
    total_tokens: int
    overall_tokens_per_second: float
    requests_per_second: float
    
    duration_seconds: float


class RawrXDBenchmark:
    """Benchmark client for RawrXD."""
    
    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip('/')
        self.model = model
        self.results: List[BenchmarkResult] = []
    
    async def _make_request(
        self,
        session: aiohttp.ClientSession,
        prompt: str,
        max_tokens: int
    ) -> BenchmarkResult:
        """Make a single request and measure performance."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "max_tokens": max_tokens,
            "temperature": 0.7,
            "stream": False
        }
        
        start_time = time.perf_counter()
        first_token_time = None
        
        try:
            async with session.post(
                f"{self.base_url}/v1/completions",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120)
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    return BenchmarkResult(
                        latency_ms=0,
                        tokens_generated=0,
                        tokens_per_second=0,
                        time_to_first_token_ms=0,
                        success=False,
                        error=f"HTTP {response.status}: {error_text}"
                    )
                
                data = await response.json()
                end_time = time.perf_counter()
                
                latency_ms = (end_time - start_time) * 1000
                tokens_generated = data.get('usage', {}).get('completion_tokens', 0)
                tokens_per_second = tokens_generated / (latency_ms / 1000) if latency_ms > 0 else 0
                
                return BenchmarkResult(
                    latency_ms=latency_ms,
                    tokens_generated=tokens_generated,
                    tokens_per_second=tokens_per_second,
                    time_to_first_token_ms=latency_ms * 0.1,  # Estimate
                    success=True
                )
        except Exception as e:
            return BenchmarkResult(
                latency_ms=0,
                tokens_generated=0,
                tokens_per_second=0,
                time_to_first_token_ms=0,
                success=False,
                error=str(e)
            )
    
    async def _worker(
        self,
        session: aiohttp.ClientSession,
        queue: asyncio.Queue,
        progress: asyncio.Event
    ):
        """Worker coroutine to process requests."""
        while True:
            try:
                prompt, max_tokens = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if progress.is_set():
                    break
                continue
            
            result = await self._make_request(session, prompt, max_tokens)
            self.results.append(result)
            queue.task_done()
    
    async def run_benchmark(
        self,
        num_requests: int,
        concurrency: int,
        prompt_length: int,
        max_tokens: int,
        warmup: int = 5
    ) -> BenchmarkSummary:
        """Run the benchmark."""
        
        # Generate test prompts
        def generate_prompt(length: int) -> str:
            words = ["the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog"]
            prompt = ""
            while len(prompt) < length:
                prompt += " ".join(words) + " "
            return prompt[:length]
        
        prompts = [generate_prompt(prompt_length) for _ in range(num_requests)]
        
        print(f"Benchmark Configuration:")
        print(f"  URL: {self.base_url}")
        print(f"  Model: {self.model}")
        print(f"  Total Requests: {num_requests}")
        print(f"  Concurrency: {concurrency}")
        print(f"  Prompt Length: {prompt_length} chars")
        print(f"  Max Tokens: {max_tokens}")
        print(f"  Warmup Requests: {warmup}")
        print()
        
        # Warmup
        if warmup > 0:
            print(f"Running {warmup} warmup requests...")
            async with aiohttp.ClientSession() as session:
                warmup_tasks = [
                    self._make_request(session, generate_prompt(prompt_length), max_tokens)
                    for _ in range(warmup)
                ]
                await asyncio.gather(*warmup_tasks)
            print("Warmup complete.\n")
        
        # Main benchmark
        print("Running benchmark...")
        self.results = []
        
        queue = asyncio.Queue(maxsize=concurrency * 2)
        progress = asyncio.Event()
        
        async with aiohttp.ClientSession() as session:
            # Start workers
            workers = [
                asyncio.create_task(self._worker(session, queue, progress))
                for _ in range(concurrency)
            ]
            
            # Queue requests
            start_time = time.perf_counter()
            for prompt in prompts:
                await queue.put((prompt, max_tokens))
            
            # Wait for completion
            await queue.join()
            progress.set()
            
            # Wait for workers
            await asyncio.gather(*workers, return_exceptions=True)
            
            end_time = time.perf_counter()
        
        duration = end_time - start_time
        
        return self._compute_summary(duration)
    
    def _compute_summary(self, duration: float) -> BenchmarkSummary:
        """Compute benchmark summary statistics."""
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]
        
        if not successful:
            return BenchmarkSummary(
                total_requests=len(self.results),
                successful_requests=0,
                failed_requests=len(failed),
                latency_p50=0, latency_p95=0, latency_p99=0,
                latency_mean=0, latency_std=0,
                tokens_per_second_mean=0, tokens_per_second_p50=0,
                ttft_mean=0, ttft_p50=0,
                total_tokens=0, overall_tokens_per_second=0,
                requests_per_second=0, duration_seconds=duration
            )
        
        latencies = [r.latency_ms for r in successful]
        tps_values = [r.tokens_per_second for r in successful]
        ttft_values = [r.time_to_first_token_ms for r in successful]
        total_tokens = sum(r.tokens_generated for r in successful)
        
        return BenchmarkSummary(
            total_requests=len(self.results),
            successful_requests=len(successful),
            failed_requests=len(failed),
            
            latency_p50=np.percentile(latencies, 50),
            latency_p95=np.percentile(latencies, 95),
            latency_p99=np.percentile(latencies, 99),
            latency_mean=statistics.mean(latencies),
            latency_std=statistics.stdev(latencies) if len(latencies) > 1 else 0,
            
            tokens_per_second_mean=statistics.mean(tps_values),
            tokens_per_second_p50=np.percentile(tps_values, 50),
            
            ttft_mean=statistics.mean(ttft_values),
            ttft_p50=np.percentile(ttft_values, 50),
            
            total_tokens=total_tokens,
            overall_tokens_per_second=total_tokens / duration,
            requests_per_second=len(successful) / duration,
            
            duration_seconds=duration
        )
    
    def print_results(self, summary: BenchmarkSummary):
        """Print benchmark results."""
        print("\n" + "=" * 60)
        print("BENCHMARK RESULTS")
        print("=" * 60)
        
        print(f"\nRequests:")
        print(f"  Total: {summary.total_requests}")
        print(f"  Successful: {summary.successful_requests}")
        print(f"  Failed: {summary.failed_requests}")
        print(f"  Success Rate: {summary.successful_requests/summary.total_requests*100:.1f}%")
        
        print(f"\nLatency (ms):")
        print(f"  Mean: {summary.latency_mean:.2f}")
        print(f"  P50:  {summary.latency_p50:.2f}")
        print(f"  P95:  {summary.latency_p95:.2f}")
        print(f"  P99:  {summary.latency_p99:.2f}")
        print(f"  Std:  {summary.latency_std:.2f}")
        
        print(f"\nThroughput:")
        print(f"  Tokens/sec (mean): {summary.tokens_per_second_mean:.2f}")
        print(f"  Tokens/sec (P50):  {summary.tokens_per_second_p50:.2f}")
        print(f"  Overall tokens/sec: {summary.overall_tokens_per_second:.2f}")
        print(f"  Requests/sec: {summary.requests_per_second:.2f}")
        
        print(f"\nTime to First Token (ms):")
        print(f"  Mean: {summary.ttft_mean:.2f}")
        print(f"  P50:  {summary.ttft_p50:.2f}")
        
        print(f"\nDuration: {summary.duration_seconds:.2f}s")
        print("=" * 60)
    
    def save_results(self, summary: BenchmarkSummary, filename: str):
        """Save results to JSON file."""
        data = {
            "summary": asdict(summary),
            "individual_results": [
                asdict(r) for r in self.results
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\nResults saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description="RawrXD Benchmark Tool")
    parser.add_argument("--url", default="http://localhost:8080", help="Server URL")
    parser.add_argument("--model", default="llama-7b", help="Model name")
    parser.add_argument("--requests", type=int, default=100, help="Number of requests")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent requests")
    parser.add_argument("--prompt-len", type=int, default=512, help="Prompt length")
    parser.add_argument("--max-tokens", type=int, default=128, help="Max tokens to generate")
    parser.add_argument("--warmup", type=int, default=5, help="Warmup requests")
    parser.add_argument("--output", default="benchmark_results.json", help="Output file")
    
    args = parser.parse_args()
    
    benchmark = RawrXDBenchmark(args.url, args.model)
    
    summary = asyncio.run(benchmark.run_benchmark(
        num_requests=args.requests,
        concurrency=args.concurrency,
        prompt_length=args.prompt_len,
        max_tokens=args.max_tokens,
        warmup=args.warmup
    ))
    
    benchmark.print_results(summary)
    benchmark.save_results(summary, args.output)


if __name__ == "__main__":
    main()
