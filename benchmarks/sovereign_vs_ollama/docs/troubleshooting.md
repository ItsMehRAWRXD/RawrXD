# Troubleshooting Guide

## Overview

This guide helps diagnose and resolve common issues when using the RawrXD Benchmark Suite with real backends.

## Quick Diagnostics

### Check Backend Health

```bash
# Sovereign
curl http://localhost:8080/api/health

# Ollama
curl http://localhost:11434/api/tags
```

### Verify Network Connectivity

```bash
# Test Sovereign
ping localhost:8080

# Test Ollama
ping localhost:11434
```

### Run Quick Test

```bash
# Run smoke test
./integrated_benchmark_runner --category smoke --verbose
```

## Common Issues

### Issue: Connection Refused

**Symptoms:**
```
Error: Failed to connect to localhost:8080
Error: Connection refused
```

**Causes:**
1. Backend not running
2. Wrong endpoint URL
3. Firewall blocking connection
4. Port already in use

**Solutions:**

```bash
# 1. Check if backend is running
# For Sovereign:
ps aux | grep sovereign

# For Ollama:
ps aux | grep ollama
ollama list

# 2. Start the backend
# Sovereign:
./sovereign_server --port 8080

# Ollama:
ollama serve

# 3. Check port availability
netstat -tlnp | grep 8080
netstat -tlnp | grep 11434

# 4. Verify endpoint URL
./benchmark_runner --endpoint http://127.0.0.1:8080
```

### Issue: Model Not Found

**Symptoms:**
```
Error: Model not found: phi-3-mini-Q4
Error: Failed to load model
```

**Solutions:**

```bash
# For Ollama:
# List available models
ollama list

# Pull the model
ollama pull phi3:mini

# Verify model is available
ollama run phi3:mini "Hello"

# For Sovereign:
# Check model path in configuration
cat config.json | grep model_path

# Verify model file exists
ls -la /path/to/model.gguf
```

### Issue: High Latency

**Symptoms:**
```
Latency: 15000ms (expected: ~500ms)
Throughput: 2 TPS (expected: ~50 TPS)
```

**Causes:**
1. GPU not being used
2. Insufficient memory
3. Thermal throttling
4. Background processes

**Solutions:**

```cpp
// Check resource usage
ResourceMetrics metrics = backend->GetResourceUsage();
std::cout << "GPU: " << metrics.gpu_percent << "%" << std::endl;
std::cout << "VRAM: " << metrics.vram_mb << " MB" << std::endl;
```

```bash
# Check GPU usage (NVIDIA)
nvidia-smi

# Check GPU usage (AMD)
rocm-smi

# Check system resources
top
htop

# Check for thermal throttling
# Linux:
cat /sys/class/thermal/thermal_zone*/temp

# Windows:
# Use HWiNFO or similar tool
```

**Configuration Fixes:**

```cpp
// Ensure GPU is enabled
BenchmarkConfig config;
config.gpu_backend = "vulkan";  // or "cuda", "metal"
config.gpu_layers = 99;  // Use all GPU layers

// Reduce load
config.max_tokens = 256;  // Reduce token count
config.threads = 8;       // Reduce thread count
```

### Issue: Request Timeouts

**Symptoms:**
```
Error: Request timed out
Error: Read timeout
```

**Solutions:**

```cpp
// Increase timeouts
HttpClient client;
client.SetDefaultTimeout(
    10000,  // connect_timeout_ms (increased from 5000)
    60000,  // read_timeout_ms (increased from 30000)
    120000  // total_timeout_ms (increased from 60000)
);
```

```bash
# Via environment
export RAWRXD_BENCHMARK_CONNECT_TIMEOUT_MS=10000
export RAWRXD_BENCHMARK_READ_TIMEOUT_MS=60000
```

### Issue: Out of Memory

**Symptoms:**
```
Error: Out of memory
Error: Cannot allocate memory
Segmentation fault
```

**Solutions:**

```cpp
// Reduce memory usage
BenchmarkConfig config;
config.context_length = 2048;  // Reduce from 4096
config.gpu_layers = 20;        // Reduce GPU layers
config.max_tokens = 128;       // Reduce max tokens
```

```bash
# Monitor memory
free -h
vmstat 1

# Clear caches (Linux)
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches

# Check swap usage
swapon -s
```

### Issue: Validation Failures

**Symptoms:**
```
[WARNING] Success rate below threshold: 85%
[ERROR] Latency above expected range
[WARNING] High outlier percentage: 15%
```

**Solutions:**

```cpp
// Disable strict validation
BenchmarkConfig config;
config.enable_validation = true;
config.fail_on_validation_error = false;  // Continue despite errors

// Increase warmup runs
config.warmup_runs = 20;  // Increase from 10

// Increase measured runs
config.measured_runs = 100;  // Increase from 50
```

```bash
# Run with relaxed validation
./benchmark_runner --warmup-runs 20 --measured-runs 100
```

### Issue: Backend Crashes

**Symptoms:**
```
Error: Backend process terminated unexpectedly
Error: Connection reset by peer
```

**Solutions:**

```cpp
// Add retry logic
HttpClient client;
client.SetRetryPolicy(5, 2000, true);  // 5 retries, 2s base delay

// Check backend health before operations
if (!backend->HealthCheck()) {
    std::cerr << "Backend not healthy, attempting restart..." << std::endl;
    backend->Shutdown();
    backend->Initialize(config);
}
```

```bash
# Check backend logs
# Sovereign:
tail -f /var/log/sovereign.log

# Ollama:
journalctl -u ollama -f

# Check for crashes
dmesg | grep -i error
```

### Issue: Incorrect Results

**Symptoms:**
```
Results differ significantly from baseline
Statistical comparison shows regression
```

**Solutions:**

```cpp
// Verify configuration matches baseline
ConfigurationManager::Print(config);

// Check for environmental changes
// - Different hardware
// - Different model version
// - Background processes

// Re-establish baseline
BaselineManager baseline_mgr;
baseline_mgr.Initialize("baselines.json", BaselineConfig{});
baseline_mgr.EstablishBaseline("benchmark_id", results);
```

## Backend-Specific Issues

### Sovereign Issues

#### SEG Not Available

```cpp
// Check if SEG is supported
if (!backend->SupportsSEG()) {
    std::cerr << "SEG not available" << std::endl;
    return;
}

// Enable SEG in config
BenchmarkConfig config;
config.enable_seg = true;
```

#### Agent Spawn Failures

```cpp
// Check agent capabilities
auto* sovereign = dynamic_cast<SovereignBackendAdapter*>(backend.get());
if (sovereign) {
    auto health = sovereign->HealthCheck();
    if (!health) {
        std::cerr << "Sovereign not healthy" << std::endl;
    }
}
```

### Ollama Issues

#### Model Loading Slow

```bash
# Pre-load model
ollama run phi3:mini "Hello" &amp;&amp; exit

# Or use API to load
 curl http://localhost:11434/api/generate -d '{
   "model": "phi3:mini",
   "prompt": "",
   "stream": false
 }'
```

#### GPU Not Used

```bash
# Check Ollama GPU settings
ollama --version

# Set GPU layers via environment
export OLLAMA_GPU_LAYERS=99

# Or in modelfile
FROM phi3:mini
PARAMETER num_gpu 99
```

## Network Issues

### DNS Resolution Failures

```bash
# Test DNS resolution
nslookup localhost
dig localhost

# Use IP address instead
./benchmark_runner --endpoint http://127.0.0.1:8080
```

### Proxy Issues

```bash
# Check proxy settings
echo $http_proxy
echo $https_proxy

# Disable proxy for local connections
export no_proxy=localhost,127.0.0.1

# Or unset
unset http_proxy
unset https_proxy
```

## Performance Issues

### Low Throughput

**Diagnostic Steps:**

```cpp
// Check actual vs expected throughput
BenchmarkResult result = RunBenchmark(config);
double actual_tps = result.throughput.mean;
double expected_tps = 50.0;  // Expected TPS

if (actual_tps < expected_tps * 0.5) {
    std::cerr << "Throughput significantly lower than expected" << std::endl;
    
    // Check for bottlenecks
    ResourceMetrics metrics = backend->GetResourceUsage();
    if (metrics.cpu_percent > 90) {
        std::cerr << "CPU bottleneck detected" << std::endl;
    }
    if (metrics.gpu_percent < 50) {
        std::cerr << "GPU underutilized" << std::endl;
    }
}
```

**Solutions:**

```bash
# Enable performance mode (Linux)
cpupower frequency-set -g performance

# Set process priority
nice -n -10 ./benchmark_runner

# Disable CPU frequency scaling
# (Requires root)
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### High Variance

```cpp
// Check coefficient of variation
StatisticalMetrics metrics = result.latency;
double cv = metrics.stddev / metrics.mean;

if (cv > 0.1) {  // > 10% CV
    std::cerr << "High variance detected (CV=" << cv << ")" << std::endl;
    
    // Possible causes:
    // - Background processes
    // - Thermal throttling
    // - Memory pressure
    // - Network congestion
}
```

## Debugging Tools

### Enable Debug Logging

```cpp
// Set verbose mode
BenchmarkConfig config;
config.verbose = true;

// Or via environment
setenv("RAWRXD_BENCHMARK_VERBOSE", "1", 1);
```

### HTTP Client Debugging

```cpp
HttpClient client;
client.Initialize();

// Enable statistics tracking
client.ResetStats();

// ... make requests ...

// Print statistics
auto stats = client.GetStats();
std::cout << "Total: " << stats.total_requests << std::endl;
std::cout << "Success: " << stats.successful_requests << std::endl;
std::cout << "Failed: " << stats.failed_requests << std::endl;
std::cout << "Retried: " << stats.retried_requests << std::endl;
```

### Validation Debugging

```cpp
// Run validation and print all results
auto validations = ResultValidator::ValidateResult(result);
ResultValidator::PrintResults(validations);

// Check specific issues
bool has_errors = ResultValidator::HasErrors(validations);
int warning_count = ResultValidator::CountBySeverity(
    validations, ValidationSeverity::WARNING
);
```

## Getting Help

### Collect Diagnostic Information

```bash
# Run diagnostic script
./scripts/collect_diagnostics.sh

# Or manually collect:
# 1. System information
uname -a
lscpu
nvidia-smi  # or rocm-smi

# 2. Backend status
curl http://localhost:8080/api/health
curl http://localhost:11434/api/tags

# 3. Configuration
./benchmark_runner --help
cat benchmark.conf

# 4. Logs
tail -n 100 /var/log/sovereign.log
tail -n 100 ~/.ollama/logs/server.log

# 5. Test results
./benchmark_runner --verbose 2>&amp;1 | tee benchmark.log
```

### Report Issues

When reporting issues, include:

1. **System Information:**
   - OS version
   - CPU model
   - GPU model
   - RAM amount

2. **Backend Information:**
   - Backend type (Sovereign/Ollama)
   - Version
   - Model name

3. **Configuration:**
   - Config file contents
   - Command-line arguments
   - Environment variables

4. **Error Messages:**
   - Full error output
   - Stack traces (if available)
   - Log files

5. **Diagnostic Output:**
   - Health check results
   - Resource usage
   - Test results

## See Also

- [HTTP Client API](http_client_api.md)
- [Backend Adapter Guide](backend_adapter_guide.md)
- [Configuration Reference](configuration_reference.md)
- [Benchmark Runner Guide](benchmark_runner_guide.md)
