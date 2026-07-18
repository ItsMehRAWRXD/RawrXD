#!/usr/bin/env python3
"""
RawrXD Benchmark Suite - Distributed Load Generator
Supports horizontal scaling across multiple nodes

Copyright (c) 2026 RawrXD Team
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import aiohttp
import click

# Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class LoadConfig:
    """Configuration for load generation"""
    target_url: str
    duration_seconds: int
    requests_per_second: float
    concurrency: int
    payload_size: int = 1024
    ramp_up_seconds: int = 10
    cooldown_seconds: int = 5


@dataclass
class LoadMetrics:
    """Metrics collected during load test"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')
    max_latency_ms: float = 0.0
    latency_histogram: Dict[str, int] = None
    status_codes: Dict[int, int] = None
    errors: Dict[str, int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    
    def __post_init__(self):
        if self.latency_histogram is None:
            self.latency_histogram = {
                "0-10": 0, "10-50": 0, "50-100": 0,
                "100-250": 0, "250-500": 0, "500+": 0
            }
        if self.status_codes is None:
            self.status_codes = {}
        if self.errors is None:
            self.errors = {}
    
    def add_latency(self, latency_ms: float):
        """Add a latency sample"""
        self.total_latency_ms += latency_ms
        self.min_latency_ms = min(self.min_latency_ms, latency_ms)
        self.max_latency_ms = max(self.max_latency_ms, latency_ms)
        
        # Update histogram
        if latency_ms < 10:
            self.latency_histogram["0-10"] += 1
        elif latency_ms < 50:
            self.latency_histogram["10-50"] += 1
        elif latency_ms < 100:
            self.latency_histogram["50-100"] += 1
        elif latency_ms < 250:
            self.latency_histogram["100-250"] += 1
        elif latency_ms < 500:
            self.latency_histogram["250-500"] += 1
        else:
            self.latency_histogram["500+"] += 1
    
    def add_status_code(self, code: int):
        """Add a status code"""
        self.status_codes[code] = self.status_codes.get(code, 0) + 1
    
    def add_error(self, error: str):
        """Add an error"""
        self.errors[error] = self.errors.get(error, 0) + 1
    
    @property
    def avg_latency_ms(self) -> float:
        """Calculate average latency"""
        if self.successful_requests == 0:
            return 0.0
        return self.total_latency_ms / self.successful_requests
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100
    
    @property
    def throughput_rps(self) -> float:
        """Calculate throughput"""
        if not self.start_time or not self.end_time:
            return 0.0
        start = datetime.fromisoformat(self.start_time)
        end = datetime.fromisoformat(self.end_time)
        duration = (end - start).total_seconds()
        if duration == 0:
            return 0.0
        return self.total_requests / duration


class LoadGenerator:
    """Generates load against a target endpoint"""
    
    def __init__(self, config: LoadConfig):
        self.config = config
        self.metrics = LoadMetrics()
        self._stop_event = asyncio.Event()
        self._semaphore = asyncio.Semaphore(config.concurrency)
    
    async def generate_payload(self) -> dict:
        """Generate request payload"""
        return {
            "timestamp": datetime.now().isoformat(),
            "payload": "x" * self.config.payload_size,
            "load_test": True
        }
    
    async def make_request(
        self,
        session: aiohttp.ClientSession,
        endpoint: str
    ) -> Tuple[bool, float, Optional[int], Optional[str]]:
        """Make a single request"""
        start_time = time.time()
        
        try:
            async with self._semaphore:
                payload = await self.generate_payload()
                
                async with session.post(
                    endpoint,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    await response.read()
                    
                    latency_ms = (time.time() - start_time) * 1000
                    success = 200 <= response.status < 300
                    
                    return success, latency_ms, response.status, None
                    
        except asyncio.TimeoutError:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, None, "timeout"
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return False, latency_ms, None, str(e)
    
    async def worker(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        rate_limiter: 'RateLimiter'
    ):
        """Worker coroutine"""
        while not self._stop_event.is_set():
            await rate_limiter.acquire()
            
            success, latency, status, error = await self.make_request(
                session, endpoint
            )
            
            self.metrics.total_requests += 1
            
            if success:
                self.metrics.successful_requests += 1
                self.metrics.add_latency(latency)
                if status:
                    self.metrics.add_status_code(status)
            else:
                self.metrics.failed_requests += 1
                if error:
                    self.metrics.add_error(error)
                if status:
                    self.metrics.add_status_code(status)
    
    async def run(self) -> LoadMetrics:
        """Run the load test"""
        logger.info(f"Starting load test against {self.config.target_url}")
        logger.info(f"Duration: {self.config.duration_seconds}s, "
                   f"RPS: {self.config.requests_per_second}, "
                   f"Concurrency: {self.config.concurrency}")
        
        self.metrics.start_time = datetime.now().isoformat()
        
        # Determine endpoint
        endpoint = urljoin(self.config.target_url, "/api/generate")
        
        # Create rate limiter
        rate_limiter = RateLimiter(self.config.requests_per_second)
        
        # Create session
        connector = aiohttp.TCPConnector(
            limit=self.config.concurrency * 2,
            limit_per_host=self.config.concurrency
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Start workers
            workers = [
                asyncio.create_task(
                    self.worker(session, endpoint, rate_limiter)
                )
                for _ in range(self.config.concurrency)
            ]
            
            # Run for specified duration
            await asyncio.sleep(self.config.duration_seconds)
            
            # Signal stop
            self._stop_event.set()
            
            # Wait for workers to complete
            await asyncio.gather(*workers, return_exceptions=True)
        
        self.metrics.end_time = datetime.now().isoformat()
        
        logger.info("Load test completed")
        return self.metrics


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, rate: float):
        self.rate = rate
        self.tokens = rate
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire a token"""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class DistributedLoadGenerator:
    """Coordinates load generation across multiple nodes"""
    
    def __init__(self, nodes: List[str]):
        self.nodes = nodes
        self.results: Dict[str, LoadMetrics] = {}
    
    async def start_remote_load(
        self,
        node: str,
        config: LoadConfig
    ) -> LoadMetrics:
        """Start load generation on remote node"""
        # In a real implementation, this would use SSH or an agent
        # For now, simulate remote execution
        logger.info(f"Starting load on node: {node}")
        
        generator = LoadGenerator(config)
        return await generator.run()
    
    async def run_distributed(
        self,
        config: LoadConfig
    ) -> Dict[str, LoadMetrics]:
        """Run load test across all nodes"""
        tasks = [
            self.start_remote_load(node, config)
            for node in self.nodes
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for node, result in zip(self.nodes, results):
            if isinstance(result, Exception):
                logger.error(f"Node {node} failed: {result}")
            else:
                self.results[node] = result
        
        return self.results
    
    def aggregate_results(self) -> Dict:
        """Aggregate results from all nodes"""
        if not self.results:
            return {}
        
        total_requests = sum(r.total_requests for r in self.results.values())
        total_success = sum(r.successful_requests for r in self.results.values())
        total_failed = sum(r.failed_requests for r in self.results.values())
        total_latency = sum(r.total_latency_ms for r in self.results.values())
        
        # Aggregate histograms
        combined_histogram = {}
        for metrics in self.results.values():
            for bucket, count in metrics.latency_histogram.items():
                combined_histogram[bucket] = (
                    combined_histogram.get(bucket, 0) + count
                )
        
        # Aggregate status codes
        combined_status = {}
        for metrics in self.results.values():
            for code, count in metrics.status_codes.items():
                combined_status[code] = combined_status.get(code, 0) + count
        
        return {
            "nodes": len(self.results),
            "total_requests": total_requests,
            "successful_requests": total_success,
            "failed_requests": total_failed,
            "success_rate": (total_success / total_requests * 100) if total_requests > 0 else 0,
            "avg_latency_ms": (total_latency / total_success) if total_success > 0 else 0,
            "throughput_rps": sum(r.throughput_rps for r in self.results.values()),
            "latency_histogram": combined_histogram,
            "status_codes": combined_status,
            "node_details": {
                node: asdict(metrics) for node, metrics in self.results.items()
            }
        }


@click.group()
def cli():
    """RawrXD Distributed Load Generator"""
    pass


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--duration', '-d', default=60, help='Test duration in seconds')
@click.option('--rps', '-r', default=100.0, help='Requests per second')
@click.option('--concurrency', '-c', default=10, help='Concurrent connections')
@click.option('--output', '-o', help='Output file for results')
def single(target: str, duration: int, rps: float, concurrency: int, output: str):
    """Run load test from single node"""
    config = LoadConfig(
        target_url=target,
        duration_seconds=duration,
        requests_per_second=rps,
        concurrency=concurrency
    )
    
    generator = LoadGenerator(config)
    metrics = asyncio.run(generator.run())
    
    # Print results
    print("\n" + "="*60)
    print("LOAD TEST RESULTS")
    print("="*60)
    print(f"Total Requests:     {metrics.total_requests}")
    print(f"Successful:         {metrics.successful_requests}")
    print(f"Failed:             {metrics.failed_requests}")
    print(f"Success Rate:       {metrics.success_rate:.2f}%")
    print(f"Avg Latency:        {metrics.avg_latency_ms:.2f}ms")
    print(f"Min Latency:        {metrics.min_latency_ms:.2f}ms")
    print(f"Max Latency:        {metrics.max_latency_ms:.2f}ms")
    print(f"Throughput:         {metrics.throughput_rps:.2f} req/s")
    print("\nLatency Distribution:")
    for bucket, count in metrics.latency_histogram.items():
        percentage = (count / metrics.successful_requests * 100) if metrics.successful_requests > 0 else 0
        print(f"  {bucket:10s} ms: {count:6d} ({percentage:5.1f}%)")
    print("\nStatus Codes:")
    for code, count in sorted(metrics.status_codes.items()):
        print(f"  HTTP {code}: {count}")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(asdict(metrics), f, indent=2)
        print(f"\nResults saved to: {output}")


@cli.command()
@click.option('--nodes', '-n', required=True, help='Comma-separated list of nodes')
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--duration', '-d', default=60, help='Test duration in seconds')
@click.option('--rps', '-r', default=100.0, help='Requests per second per node')
@click.option('--concurrency', '-c', default=10, help='Concurrent connections per node')
@click.option('--output', '-o', help='Output file for results')
def distributed(nodes: str, target: str, duration: int, rps: float, concurrency: int, output: str):
    """Run distributed load test across multiple nodes"""
    node_list = [n.strip() for n in nodes.split(',')]
    
    config = LoadConfig(
        target_url=target,
        duration_seconds=duration,
        requests_per_second=rps,
        concurrency=concurrency
    )
    
    generator = DistributedLoadGenerator(node_list)
    asyncio.run(generator.run_distributed(config))
    
    results = generator.aggregate_results()
    
    # Print results
    print("\n" + "="*60)
    print("DISTRIBUTED LOAD TEST RESULTS")
    print("="*60)
    print(f"Nodes:              {results['nodes']}")
    print(f"Total Requests:     {results['total_requests']}")
    print(f"Successful:         {results['successful_requests']}")
    print(f"Failed:             {results['failed_requests']}")
    print(f"Success Rate:       {results['success_rate']:.2f}%")
    print(f"Avg Latency:        {results['avg_latency_ms']:.2f}ms")
    print(f"Total Throughput:   {results['throughput_rps']:.2f} req/s")
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output}")


@cli.command()
@click.option('--target', '-t', required=True, help='Target URL')
@click.option('--start-rps', '-s', default=10, help='Starting RPS')
@click.option('--max-rps', '-m', default=1000, help='Maximum RPS')
@click.option('--step', default=10, help='RPS increment step')
@click.option('--duration', '-d', default=30, help='Duration per step')
@click.option('--output', '-o', help='Output file for results')
def ramp(target: str, start_rps: int, max_rps: int, step: int, duration: int, output: str):
    """Run ramp-up test to find breaking point"""
    print(f"Starting ramp-up test: {start_rps} -> {max_rps} RPS")
    
    results = []
    current_rps = start_rps
    
    while current_rps <= max_rps:
        print(f"\nTesting at {current_rps} RPS...")
        
        config = LoadConfig(
            target_url=target,
            duration_seconds=duration,
            requests_per_second=current_rps,
            concurrency=min(current_rps, 100)
        )
        
        generator = LoadGenerator(config)
        metrics = asyncio.run(generator.run())
        
        result = {
            "target_rps": current_rps,
            "actual_rps": metrics.throughput_rps,
            "success_rate": metrics.success_rate,
            "avg_latency_ms": metrics.avg_latency_ms,
            "p99_latency_ms": metrics.max_latency_ms
        }
        results.append(result)
        
        print(f"  Actual: {result['actual_rps']:.1f} RPS, "
              f"Success: {result['success_rate']:.1f}%, "
              f"Latency: {result['avg_latency_ms']:.1f}ms")
        
        # Stop if success rate drops below 95%
        if result['success_rate'] < 95:
            print(f"\nBreaking point found at ~{current_rps} RPS")
            break
        
        current_rps += step
    
    # Save results
    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output}")


if __name__ == "__main__":
    cli()
