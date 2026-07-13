# RawrXD Benchmark Suite - Performance Tuning & Optimization Guide

## Table of Contents
1. [Overview](#overview)
2. [System-Level Optimizations](#system-level-optimizations)
3. [Benchmark Configuration Tuning](#benchmark-configuration-tuning)
4. [Backend-Specific Optimizations](#backend-specific-optimizations)
5. [Network Optimization](#network-optimization)
6. [Memory Management](#memory-management)
7. [CPU Optimization](#cpu-optimization)
8. [Storage Optimization](#storage-optimization)
9. [Monitoring & Profiling](#monitoring--profiling)
10. [Troubleshooting Performance Issues](#troubleshooting-performance-issues)

---

## Overview

This guide provides comprehensive performance tuning recommendations for the RawrXD Benchmark Suite. Following these guidelines can improve benchmark throughput by 20-50% and reduce latency variability.

### Performance Targets

| Metric | Baseline | Optimized | Improvement |
|--------|----------|-----------|-------------|
| Throughput (req/s) | 100 | 150+ | 50% |
| P99 Latency | 500ms | 250ms | 50% |
| CPU Utilization | 60% | 80% | +33% |
| Memory Efficiency | 70% | 85% | +21% |

---

## System-Level Optimizations

### 1. CPU Governor Settings

Set CPU governor to `performance` mode:

```bash
# For Intel/AMD CPUs
sudo cpupower frequency-set -g performance

# Or via sysfs (all cores)
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance | sudo tee $cpu
done
```

### 2. Disable CPU Frequency Scaling

```bash
# Disable Intel P-State
sudo modprobe -r intel_pstate
sudo modprobe intel_pstate disable=1

# Disable AMD P-State (if applicable)
echo passive | sudo tee /sys/devices/system/cpu/amd_pstate/status
```

### 3. Process Priority

Run benchmarks with elevated priority:

```bash
# Using nice (lower niceness = higher priority)
sudo nice -n -10 ./integrated_benchmark_runner

# Using chrt for real-time scheduling
sudo chrt -f 99 ./integrated_benchmark_runner
```

### 4. NUMA Optimization

For multi-socket systems:

```bash
# Pin to specific NUMA node
numactl --cpunodebind=0 --membind=0 ./integrated_benchmark_runner

# Interleave memory across all nodes
numactl --interleave=all ./integrated_benchmark_runner
```

### 5. Kernel Parameters

Add to `/etc/sysctl.conf`:

```bash
# Network optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 30000
net.ipv4.tcp_congestion_control = bbr

# Virtual memory
vm.swappiness = 10
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10

# File system
fs.file-max = 2097152
fs.nr_open = 2097152
```

Apply changes:
```bash
sudo sysctl -p
```

---

## Benchmark Configuration Tuning

### 1. Connection Pool Sizing

Edit `benchmark.conf`:

```ini
[http_client]
# For low latency (< 10ms): connection_pool_size = 10-20
# For medium latency (10-100ms): connection_pool_size = 50-100
# For high latency (> 100ms): connection_pool_size = 100-200
connection_pool_size = 50

# Keep-alive timeout (seconds)
keep_alive_timeout = 30

# Connection timeout (seconds)
connect_timeout = 5
```

### 2. Parallel Workers

Optimal worker count depends on backend capacity:

```ini
[benchmark]
# Rule of thumb: workers = 2 * CPU cores for CPU-bound backends
# For I/O bound: workers = 4-8 * CPU cores
parallel_workers = 8

# For high-throughput testing
# parallel_workers = 16
```

### 3. Iteration Count

Balance statistical significance with time:

```ini
[benchmark]
# Minimum for statistical validity
min_iterations = 30

# Recommended for production benchmarks
iterations = 100

# For high-confidence results
# iterations = 1000

# Warmup iterations (exclude from results)
warmup_iterations = 10
```

### 4. Timeout Configuration

```ini
[benchmark]
# Request timeout (seconds)
# Increase for slow backends
request_timeout = 30

# Total benchmark timeout (minutes)
benchmark_timeout = 60
```

---

## Backend-Specific Optimizations

### Sovereign Backend

#### 1. Model Loading

```bash
# Pre-load models to avoid cold-start latency
curl -X POST http://localhost:8080/api/load \
  -H "Content-Type: application/json" \
  -d '{"model": "your-model-name"}'
```

#### 2. Batch Size Tuning

```ini
[sovereign]
# Increase batch size for higher throughput
# Decrease for lower latency
batch_size = 8

# Max tokens per request
max_tokens = 2048
```

#### 3. GPU Memory Management

```bash
# Set GPU memory fraction
export CUDA_MEMORY_FRACTION=0.9

# Enable memory growth
export TF_FORCE_GPU_ALLOW_GROWTH=true
```

### Ollama Backend

#### 1. Model Pre-loading

```bash
# Pull and keep model in memory
ollama pull your-model

# Keep model loaded (disable auto-unload)
ollama serve &
export OLLAMA_KEEP_ALIVE=24h
```

#### 2. Concurrent Requests

```ini
[ollama]
# Ollama handles concurrency internally
# Tune based on available GPU memory
concurrent_requests = 4
```

#### 3. Quantization Settings

```bash
# Use appropriate quantization for your hardware
# q4_0 = fastest, lowest quality
# q8_0 = balanced
# f16 = best quality, slowest
ollama run model:q8_0
```

---

## Network Optimization

### 1. TCP Tuning

```bash
# Increase TCP buffer sizes
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
```

### 2. Network Interface Tuning

```bash
# Disable offloading (for low-latency)
sudo ethtool -K eth0 tso off gso off gro off

# Set ring buffer sizes
sudo ethtool -G eth0 rx 4096 tx 4096
```

### 3. Localhost Optimization

When benchmarking localhost:

```bash
# Use Unix domain sockets if supported
# Edit benchmark.conf:
[backend]
sovereign_socket = /tmp/sovereign.sock
ollama_socket = /tmp/ollama.sock
```

### 4. DNS Resolution

```bash
# Cache DNS locally
sudo apt-get install nscd
sudo systemctl enable nscd

# Or use local DNS cache
sudo apt-get install dnsmasq
```

---

## Memory Management

### 1. Huge Pages

Enable huge pages for better memory performance:

```bash
# Check current huge pages
cat /proc/meminfo | grep Huge

# Allocate huge pages (requires reboot)
echo 1024 | sudo tee /proc/sys/vm/nr_hugepages

# Or persistent in /etc/sysctl.conf:
vm.nr_hugepages = 1024
```

### 2. Memory Locking

Prevent swapping of benchmark process:

```bash
# Using ulimit
ulimit -l unlimited

# Or in systemd service:
[Service]
MemoryMax=16G
MemorySwapMax=0
```

### 3. Transparent Huge Pages

```bash
# Check current setting
cat /sys/kernel/mm/transparent_hugepage/enabled

# Enable if not already
echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
```

### 4. Benchmark Memory Settings

```ini
[benchmark]
# Pre-allocate memory to avoid allocation overhead
preallocate_memory = true
memory_pool_size_mb = 1024

# Garbage collection tuning (if applicable)
gc_interval_seconds = 60
```

---

## CPU Optimization

### 1. CPU Affinity

Pin benchmark to specific cores:

```bash
# Pin to cores 0-3
taskset -c 0-3 ./integrated_benchmark_runner

# Pin to specific cores (avoid hyperthreading pairs)
taskset -c 0,2,4,6 ./integrated_benchmark_runner
```

### 2. Disable Hyperthreading (if needed)

```bash
# Check hyperthreading status
cat /sys/devices/system/cpu/smt/active

# Disable (requires root)
echo off | sudo tee /sys/devices/system/cpu/smt/control
```

### 3. CPU Isolation

Isolate CPUs for benchmark use:

```bash
# Add to kernel boot parameters
isolcpus=4-7 nohz_full=4-7 rcu_nocbs=4-7

# Then pin benchmark to isolated cores
taskset -c 4-7 ./integrated_benchmark_runner
```

### 4. IRQ Affinity

Move interrupts away from benchmark cores:

```bash
# Move all IRQs to CPU 0
for irq in /proc/irq/*/smp_affinity; do
    echo 1 | sudo tee $irq
done
```

---

## Storage Optimization

### 1. Results Directory

Place results on fast storage:

```ini
[paths]
# Use tmpfs for ultra-fast results (data lost on reboot)
results_dir = /dev/shm/rawrxd_results

# Or use NVMe SSD
results_dir = /mnt/nvme/rawrxd/results
```

### 2. Log Rotation

Prevent disk I/O from logging:

```ini
[logging]
# Log to memory buffer
buffer_size_mb = 100
flush_interval_seconds = 60

# Or disable logging for max performance
enabled = false
```

### 3. Filesystem Tuning

```bash
# Mount with noatime for better performance
sudo mount -o remount,noatime /

# Or in /etc/fstab:
UUID=xxx / ext4 noatime,nodiratime,errors=remount-ro 0 1
```

---

## Monitoring & Profiling

### 1. Real-time Monitoring

```bash
# Start monitoring daemon
./scripts/monitor.sh daemon &

# View current status
./scripts/monitor.sh status
```

### 2. Performance Profiling

```bash
# CPU profiling
perf record -g ./integrated_benchmark_runner
perf report

# Memory profiling
valgrind --tool=massif ./integrated_benchmark_runner

# Network profiling
tcpdump -i lo -w benchmark.pcap
```

### 3. Metrics Collection

```bash
# Export metrics for analysis
./scripts/monitor.sh export json 1h > metrics.json

# Generate Prometheus metrics
curl http://localhost:9090/metrics
```

### 4. Alerting Thresholds

```ini
[monitoring]
# Alert when P99 latency exceeds threshold
latency_p99_threshold_ms = 500

# Alert on error rate
error_rate_threshold_percent = 1.0

# Alert on throughput drop
throughput_drop_threshold_percent = 20
```

---

## Troubleshooting Performance Issues

### Issue: High Latency Variability

**Symptoms:** Large standard deviation in latency measurements

**Solutions:**
1. Increase warmup iterations: `--warmup 50`
2. Disable CPU frequency scaling
3. Pin to isolated cores
4. Check for background processes: `top`, `htop`
5. Verify no swap usage: `free -h`

### Issue: Low Throughput

**Symptoms:** Requests per second below expected

**Solutions:**
1. Increase parallel workers: `--parallel 16`
2. Check backend capacity (may be saturated)
3. Enable connection pooling
4. Tune TCP settings
5. Verify network bandwidth: `iperf3`

### Issue: Connection Timeouts

**Symptoms:** Frequent timeout errors

**Solutions:**
1. Increase timeout values
2. Check backend health: `curl http://localhost:8080/api/health`
3. Verify network connectivity: `ping`, `traceroute`
4. Check firewall rules: `iptables -L`
5. Increase connection pool size

### Issue: Memory Leaks

**Symptoms:** Memory usage grows over time

**Solutions:**
1. Run with valgrind: `valgrind --leak-check=full`
2. Check for unclosed connections
3. Verify proper cleanup in callbacks
4. Limit result history size
5. Enable automatic cleanup

### Issue: High CPU Usage

**Symptoms:** CPU at 100%, system unresponsive

**Solutions:**
1. Reduce parallel workers
2. Enable CPU throttling
3. Check for infinite loops in code
4. Profile to find hotspots: `perf top`
5. Consider distributed benchmarking

---

## Quick Reference

### Essential Commands

```bash
# Quick performance test
./integrated_benchmark_runner --mode quick

# Full benchmark with monitoring
./scripts/monitor.sh daemon &
./integrated_benchmark_runner --iterations 1000 --parallel 16

# Compare backends
./integrated_benchmark_runner --mode comparison

# Generate performance report
./scripts/run_performance_benchmarks.sh --mode full
```

### Configuration Checklist

- [ ] CPU governor set to performance
- [ ] Network buffers increased
- [ ] Connection pool sized appropriately
- [ ] Parallel workers tuned for hardware
- [ ] Timeouts configured for backend latency
- [ ] Results directory on fast storage
- [ ] Logging configured for production
- [ ] Monitoring daemon running
- [ ] Alerts configured
- [ ] Backups scheduled

### Performance Validation

```bash
# Verify optimizations are active
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor  # Should be "performance"
cat /proc/sys/net/core/rmem_max  # Should be 134217728
free -h | grep Swap  # Should show minimal swap usage

# Run validation benchmark
./integrated_benchmark_runner --category core --iterations 100
```

---

## Additional Resources

- [HTTP Client API Documentation](http_client_api.md)
- [Backend Adapter Guide](backend_adapter_guide.md)
- [Configuration Reference](configuration_reference.md)
- [Troubleshooting Guide](troubleshooting.md)

---

*Last Updated: 2026-07-13*
*Version: 1.0.0*
