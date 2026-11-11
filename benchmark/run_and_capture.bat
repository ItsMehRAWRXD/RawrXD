@echo off
cd /d d:\src\benchmark

echo Running benchmark...
standalone_bench.exe > benchmark_results.txt 2>&1

echo Benchmark complete. Results saved to benchmark_results.txt
