#!/usr/bin/env python3
"""
RawrXD Benchmark Suite - REST API Server
Provides HTTP endpoints for remote benchmark control and monitoring

Copyright (c) 2026 RawrXD Team
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from aiohttp import web
import aiohttp_cors

# Configuration
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8888
BENCHMARK_DIR = Path("/opt/rawrxd/benchmarks")
LOG_DIR = Path("/var/log/rawrxd")
DATA_DIR = Path("/var/lib/rawrxd")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "api_server.log")
    ]
)
logger = logging.getLogger(__name__)

# In-memory storage for active benchmarks
active_benchmarks: Dict[str, Dict] = {}
benchmark_history: List[Dict] = []


class BenchmarkManager:
    """Manages benchmark execution and monitoring"""
    
    def __init__(self):
        self.active_processes: Dict[str, asyncio.subprocess.Process] = {}
    
    async def start_benchmark(
        self,
        benchmark_id: str,
        backend: str,
        duration: int,
        workers: int,
        model: Optional[str] = None
    ) -> Dict:
        """Start a new benchmark"""
        
        cmd = [
            str(BENCHMARK_DIR / "bin" / "integrated_benchmark_runner"),
            "--backend", backend,
            "--duration", str(duration),
            "--parallel", str(workers),
            "--output", str(DATA_DIR / "results" / f"{benchmark_id}.json"),
            "--format", "json"
        ]
        
        if model:
            cmd.extend(["--model", model])
        
        logger.info(f"Starting benchmark {benchmark_id}: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self.active_processes[benchmark_id] = process
            
            active_benchmarks[benchmark_id] = {
                "id": benchmark_id,
                "backend": backend,
                "duration": duration,
                "workers": workers,
                "model": model,
                "status": "running",
                "start_time": datetime.now().isoformat(),
                "pid": process.pid
            }
            
            # Start monitoring task
            asyncio.create_task(self._monitor_benchmark(benchmark_id, process))
            
            return {
                "success": True,
                "benchmark_id": benchmark_id,
                "status": "started"
            }
            
        except Exception as e:
            logger.error(f"Failed to start benchmark: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _monitor_benchmark(
        self,
        benchmark_id: str,
        process: asyncio.subprocess.Process
    ):
        """Monitor benchmark process and capture output"""
        stdout, stderr = await process.communicate()
        
        returncode = process.returncode
        
        if benchmark_id in active_benchmarks:
            active_benchmarks[benchmark_id]["status"] = (
                "completed" if returncode == 0 else "failed"
            )
            active_benchmarks[benchmark_id]["returncode"] = returncode
            active_benchmarks[benchmark_id]["end_time"] = datetime.now().isoformat()
            
            if stdout:
                active_benchmarks[benchmark_id]["stdout"] = stdout.decode()
            if stderr:
                active_benchmarks[benchmark_id]["stderr"] = stderr.decode()
            
            # Move to history
            benchmark_history.append(active_benchmarks[benchmark_id].copy())
            del active_benchmarks[benchmark_id]
        
        if benchmark_id in self.active_processes:
            del self.active_processes[benchmark_id]
    
    async def stop_benchmark(self, benchmark_id: str) -> Dict:
        """Stop a running benchmark"""
        if benchmark_id not in self.active_processes:
            return {
                "success": False,
                "error": "Benchmark not found or not running"
            }
        
        process = self.active_processes[benchmark_id]
        
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=5.0)
            
            if benchmark_id in active_benchmarks:
                active_benchmarks[benchmark_id]["status"] = "stopped"
                active_benchmarks[benchmark_id]["end_time"] = datetime.now().isoformat()
            
            return {
                "success": True,
                "benchmark_id": benchmark_id,
                "status": "stopped"
            }
            
        except asyncio.TimeoutError:
            process.kill()
            return {
                "success": True,
                "benchmark_id": benchmark_id,
                "status": "killed"
            }
    
    def get_status(self, benchmark_id: Optional[str] = None) -> Dict:
        """Get benchmark status"""
        if benchmark_id:
            if benchmark_id in active_benchmarks:
                return active_benchmarks[benchmark_id]
            for hist in benchmark_history:
                if hist["id"] == benchmark_id:
                    return hist
            return {"error": "Benchmark not found"}
        
        return {
            "active": list(active_benchmarks.values()),
            "history": benchmark_history[-50:]  # Last 50
        }


# Initialize manager
benchmark_manager = BenchmarkManager()


# API Handlers
async def health_check(request: web.Request) -> web.Response:
    """Health check endpoint"""
    return web.json_response({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })


async def start_benchmark_handler(request: web.Request) -> web.Response:
    """Start a new benchmark"""
    try:
        data = await request.json()
        
        benchmark_id = data.get("id", f"bench_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        backend = data.get("backend", "sovereign")
        duration = data.get("duration", 60)
        workers = data.get("workers", 8)
        model = data.get("model")
        
        result = await benchmark_manager.start_benchmark(
            benchmark_id, backend, duration, workers, model
        )
        
        return web.json_response(result)
        
    except Exception as e:
        logger.error(f"Error starting benchmark: {e}")
        return web.json_response(
            {"success": False, "error": str(e)},
            status=500
        )


async def stop_benchmark_handler(request: web.Request) -> web.Response:
    """Stop a running benchmark"""
    benchmark_id = request.match_info.get("id")
    
    if not benchmark_id:
        return web.json_response(
            {"success": False, "error": "Benchmark ID required"},
            status=400
        )
    
    result = await benchmark_manager.stop_benchmark(benchmark_id)
    return web.json_response(result)


async def get_benchmark_status(request: web.Request) -> web.Response:
    """Get benchmark status"""
    benchmark_id = request.match_info.get("id")
    status = benchmark_manager.get_status(benchmark_id)
    return web.json_response(status)


async def list_benchmarks(request: web.Request) -> web.Response:
    """List all benchmarks"""
    status = benchmark_manager.get_status()
    return web.json_response(status)


async def get_results(request: web.Request) -> web.Response:
    """Get benchmark results"""
    benchmark_id = request.match_info.get("id")
    
    result_file = DATA_DIR / "results" / f"{benchmark_id}.json"
    
    if not result_file.exists():
        return web.json_response(
            {"error": "Results not found"},
            status=404
        )
    
    try:
        with open(result_file) as f:
            results = json.load(f)
        return web.json_response(results)
    except Exception as e:
        return web.json_response(
            {"error": f"Failed to read results: {e}"},
            status=500
        )


async def get_metrics(request: web.Request) -> web.Response:
    """Get current metrics"""
    # Read from metrics directory
    metrics_dir = DATA_DIR / "metrics"
    
    metrics = {
        "timestamp": datetime.now().isoformat(),
        "system": {},
        "benchmarks": {
            "active": len(active_benchmarks),
            "total": len(benchmark_history) + len(active_benchmarks)
        }
    }
    
    # Try to read latest system metrics
    try:
        latest_system = sorted(metrics_dir.glob("system_*.json"))[-1]
        with open(latest_system) as f:
            metrics["system"] = json.load(f)
    except (IndexError, FileNotFoundError):
        pass
    
    return web.json_response(metrics)


async def get_backends(request: web.Request) -> web.Response:
    """Get backend status"""
    backends = {
        "sovereign": {
            "url": "http://localhost:8080",
            "status": "unknown"
        },
        "ollama": {
            "url": "http://localhost:11434",
            "status": "unknown"
        }
    }
    
    # Check Sovereign
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://localhost:8080/api/health",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                backends["sovereign"]["status"] = (
                    "healthy" if resp.status == 200 else "unhealthy"
                )
    except Exception:
        backends["sovereign"]["status"] = "unreachable"
    
    # Check Ollama
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://localhost:11434/api/tags",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                backends["ollama"]["status"] = (
                    "healthy" if resp.status == 200 else "unhealthy"
                )
    except Exception:
        backends["ollama"]["status"] = "unreachable"
    
    return web.json_response(backends)


async def get_config(request: web.Request) -> web.Response:
    """Get current configuration"""
    config_file = Path("/etc/rawrxd/benchmark.conf")
    
    config = {}
    if config_file.exists():
        # Simple config parser
        current_section = None
        with open(config_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                    config[current_section] = {}
                elif '=' in line and current_section:
                    key, value = line.split('=', 1)
                    config[current_section][key.strip()] = value.strip()
    
    return web.json_response(config)


# Create application
app = web.Application()

# Setup CORS
cors = aiohttp_cors.setup(app, defaults={
    "*": aiohttp_cors.ResourceOptions(
        allow_credentials=True,
        expose_headers="*",
        allow_headers="*",
        allow_methods="*"
    )
})

# Routes
routes = [
    web.get("/api/health", health_check),
    web.post("/api/benchmarks/start", start_benchmark_handler),
    web.post("/api/benchmarks/{id}/stop", stop_benchmark_handler),
    web.get("/api/benchmarks", list_benchmarks),
    web.get("/api/benchmarks/{id}", get_benchmark_status),
    web.get("/api/benchmarks/{id}/results", get_results),
    web.get("/api/metrics", get_metrics),
    web.get("/api/backends", get_backends),
    web.get("/api/config", get_config),
]

# Add routes with CORS
for route in routes:
    cors.add(app.router.add_route(route.method, route.path, route.handler))

# Static files for dashboard
app.router.add_static("/dashboard", Path(__file__).parent / "dashboard")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="RawrXD Benchmark API Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"Starting API server on {args.host}:{args.port}")
    
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
