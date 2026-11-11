# RawrXD Sovereign Inferencer - Troubleshooting Guide
## Phase S.5: Common issues and resolution steps

---

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Startup Failures](#startup-failures)
3. [Performance Issues](#performance-issues)
4. [Memory Issues](#memory-issues)
5. [GPU/Vulkan Issues](#gpuvulkan-issues)
6. [Network Issues](#network-issues)
7. [Model Loading Issues](#model-loading-issues)
8. [Inference Errors](#inference-errors)
9. [Cluster Issues](#cluster-issues)
10. [Security Issues](#security-issues)

---

## Installation Issues

### Issue: CMake configuration fails

**Symptoms:**
```
CMake Error: Could not find Vulkan
CMake Error: OpenSSL not found
```

**Resolution:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y libvulkan-dev libssl-dev cmake build-essential

# CentOS/RHEL/Fedora
sudo dnf install vulkan-loader-devel openssl-devel cmake gcc-c++

# macOS
brew install vulkan-loader openssl cmake

# Windows (vcpkg)
vcpkg install vulkan openssl --triplet x64-windows
```

### Issue: Compilation errors

**Symptoms:**
```
error: 'std::optional' has not been declared
error: use of deleted function
```

**Resolution:**
```bash
# Check compiler version (need C++17)
gcc --version  # Need 7+
clang --version  # Need 5+

# Set compiler explicitly
export CC=/usr/bin/gcc-11
export CXX=/usr/bin/g++-11

# Reconfigure
cmake .. -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX
```

---

## Startup Failures

### Issue: Service fails to start

**Symptoms:**
```
Failed to start RawrXD Inference Server
Exit code: 1
```

**Diagnostic Steps:**
```bash
# Check logs
journalctl -u rawrxd -n 50 --no-pager

# Check configuration
rawrxd-cli config validate

# Check permissions
ls -la /var/lib/rawrxd/
ls -la /var/log/rawrxd/

# Check port availability
netstat -tlnp | grep 8080
ss -tlnp | grep 8080
```

**Resolution:**
```bash
# Fix permissions
sudo chown -R rawrxd:rawrxd /var/lib/rawrxd
sudo chown -R rawrxd:rawrxd /var/log/rawrxd

# Clear stale PID file
sudo rm /var/run/rawrxd/rawrxd.pid

# Reset to default config
sudo cp /etc/rawrxd/config.yaml.default /etc/rawrxd/config.yaml
```

### Issue: Port already in use

**Symptoms:**
```
bind: Address already in use
```

**Resolution:**
```bash
# Find process using port
sudo lsof -i :8080
sudo netstat -tlnp | grep 8080

# Kill process
sudo kill -9 <PID>

# Or change port in config
rawrxd-cli config set server.port 8081
```

---

## Performance Issues

### Issue: High latency

**Symptoms:**
- p99 latency > 500ms
- User complaints about slow responses

**Diagnostic Steps:**
```bash
# Check current metrics
rawrxd-cli metrics --latency

# Identify bottlenecks
rawrxd-cli diagnose --performance

# Check resource usage
top -p $(pgrep rawrxd)
nvidia-smi

# Review slow queries
rawrxd-cli logs --slow-queries --since "1 hour ago"
```

**Resolution:**
```bash
# Enable batching
rawrxd-cli config set inference.batch_size 8

# Increase workers
rawrxd-cli config set inference.worker_threads 16

# Enable caching
rawrxd-cli config set cache.enabled true

# Scale horizontally
kubectl scale deployment rawrxd-server --replicas=5
```

### Issue: Low throughput

**Symptoms:**
- Requests per second below target
- Queue buildup

**Resolution:**
```bash
# Check batch size
rawrxd-cli config get inference.batch_size

# Optimize for throughput
rawrxd-cli config set inference.optimize_for throughput

# Enable request coalescing
rawrxd-cli config set inference.coalesce_requests true

# Check GPU utilization
nvidia-smi dmon -s u
```

---

## Memory Issues

### Issue: Out of memory errors

**Symptoms:**
```
std::bad_alloc
Killed process (OOM)
```

**Diagnostic Steps:**
```bash
# Check memory usage
free -h
cat /proc/meminfo

# Check RawrXD memory
rawrxd-cli metrics --memory

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full rawrxd-server
```

**Resolution:**
```bash
# Reduce batch size
rawrxd-cli config set inference.batch_size 4

# Limit model cache
rawrxd-cli config set cache.max_size_gb 4

# Enable memory optimization
rawrxd-cli config set memory.optimize true

# Add swap (temporary fix)
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### Issue: Memory leaks

**Symptoms:**
- Memory usage grows over time
- Service restart fixes temporarily

**Resolution:**
```bash
# Enable memory profiling
rawrxd-cli config set profiling.memory.enabled true

# Set memory limits
rawrxd-cli config set memory.max_usage_gb 16

# Enable automatic restart on high memory
rawrxd-cli config set memory.auto_restart_threshold_gb 14

# Check for circular references
rawrxd-cli diagnose --memory-leaks
```

---

## GPU/Vulkan Issues

### Issue: GPU not detected

**Symptoms:**
```
No Vulkan devices found
GPU acceleration disabled
```

**Diagnostic Steps:**
```bash
# Check Vulkan installation
vulkaninfo | grep "deviceName"
vkvia  # Vulkan installation analyzer

# Check GPU
lspci | grep -i nvidia
nvidia-smi

# Check drivers
modinfo nvidia
cat /proc/driver/nvidia/version
```

**Resolution:**
```bash
# Install Vulkan loader
sudo apt-get install vulkan-tools libvulkan1

# Update GPU drivers
# Ubuntu
sudo ubuntu-drivers autoinstall

# Or download from NVIDIA
wget https://us.download.nvidia.com/.../NVIDIA-Linux-x86_64-xxx.xx.run
sudo sh NVIDIA-Linux-x86_64-xxx.xx.run

# Verify
vulkaninfo | head -20
```

### Issue: Vulkan errors

**Symptoms:**
```
VK_ERROR_DEVICE_LOST
VK_ERROR_OUT_OF_DEVICE_MEMORY
```

**Resolution:**
```bash
# Reduce GPU memory usage
rawrxd-cli config set gpu.memory_fraction 0.8

# Enable memory defragmentation
rawrxd-cli config set gpu.defrag.enabled true

# Clear GPU cache
rawrxd-cli gpu clear-cache

# Check for GPU errors
sudo dmesg | grep -i nvidia
sudo cat /var/log/Xorg.0.log | grep -i vulkan
```

---

## Network Issues

### Issue: Connection refused

**Symptoms:**
```
curl: (7) Failed to connect
Connection refused
```

**Resolution:**
```bash
# Check if service is listening
netstat -tlnp | grep rawrxd
ss -tlnp | grep rawrxd

# Check firewall
sudo iptables -L | grep 8080
sudo ufw status

# Test locally
curl http://localhost:8080/health

# Check SELinux (if enabled)
getenforce
sudo setenforce 0  # Temporary disable
```

### Issue: TLS/SSL errors

**Symptoms:**
```
SSL certificate verify failed
TLS handshake failed
```

**Resolution:**
```bash
# Check certificate
openssl x509 -in /etc/rawrxd/certs/tls.crt -text -noout
openssl verify -CAfile /etc/rawrxd/certs/ca.crt /etc/rawrxd/certs/tls.crt

# Check certificate expiration
echo | openssl s_client -servername localhost -connect localhost:8443 2>/dev/null | openssl x509 -noout -dates

# Regenerate certificates
rawrxd-cli security generate-certs --self-signed

# Update certificate bundle
sudo update-ca-certificates
```

---

## Model Loading Issues

### Issue: Model fails to load

**Symptoms:**
```
Failed to load model: file not found
Model format not supported
```

**Diagnostic Steps:**
```bash
# Check model path
ls -la /var/lib/rawrxd/models/
rawrxd-cli models list

# Verify model format
file /var/lib/rawrxd/models/*.gguf

# Check model compatibility
rawrxd-cli models validate --model /path/to/model.gguf
```

**Resolution:**
```bash
# Download model
rawrxd-cli models download --model llama-2-7b --source huggingface

# Convert model format
rawrxd-cli models convert --input model.bin --output model.gguf

# Fix permissions
sudo chown -R rawrxd:rawrxd /var/lib/rawrxd/models

# Clear model cache
rawrxd-cli cache clear --type model
```

### Issue: Model quantization errors

**Symptoms:**
```
Quantization failed
Unsupported quantization type
```

**Resolution:**
```bash
# Check supported formats
rawrxd-cli models list-formats

# Re-quantize with supported format
rawrxd-cli models quantize --input model.gguf --output model-q4.gguf --type Q4_0

# Verify quantization
rawrxd-cli models info model-q4.gguf
```

---

## Inference Errors

### Issue: Inference timeout

**Symptoms:**
```
Request timeout
Context deadline exceeded
```

**Resolution:**
```bash
# Increase timeout
rawrxd-cli config set inference.timeout 60s

# Check for stuck requests
rawrxd-cli requests list --status processing

# Cancel stuck requests
rawrxd-cli requests cancel --all --status processing

# Enable request queue monitoring
rawrxd-cli config set queue.monitoring.enabled true
```

### Issue: Invalid input errors

**Symptoms:**
```
Invalid input format
Input too long
```

**Resolution:**
```bash
# Check input limits
rawrxd-cli config get inference.max_input_tokens
rawrxd-cli config get inference.max_output_tokens

# Increase limits if needed
rawrxd-cli config set inference.max_input_tokens 4096

# Validate input format
rawrxd-cli validate --input-file request.json
```

---

## Cluster Issues

### Issue: Node not joining cluster

**Symptoms:**
```
Failed to join cluster
Node unreachable
```

**Resolution:**
```bash
# Check network connectivity
ping <cluster-node-ip>
telnet <cluster-node-ip> 7946

# Check cluster token
rawrxd-cli cluster status

# Rejoin cluster
rawrxd-cli cluster leave
rawrxd-cli cluster join --token <token> --address <cluster-ip>

# Check firewall between nodes
sudo iptables -L -n | grep 7946
```

### Issue: Split brain

**Symptoms:**
- Multiple nodes think they are leader
- Inconsistent state across nodes

**Resolution:**
```bash
# Check cluster health
rawrxd-cli cluster health

# Force new election
rawrxd-cli cluster force-election

# Remove problematic node
rawrxd-cli cluster remove-node --id <node-id>

# Restart cluster with clean state
rawrxd-cli cluster reset --confirm
```

---

## Security Issues

### Issue: Authentication failures

**Symptoms:**
```
401 Unauthorized
Invalid API key
```

**Resolution:**
```bash
# Check API key
rawrxd-cli auth validate-key --key <api-key>

# Generate new key
rawrxd-cli auth generate-key --user admin --scope full

# Check authentication config
rawrxd-cli config get auth.enabled

# Review failed auth attempts
rawrxd-cli logs --filter "authentication failed" --since "1 hour ago"
```

### Issue: Certificate expired

**Symptoms:**
```
certificate has expired
x509: certificate has expired
```

**Resolution:**
```bash
# Check expiration
echo | openssl s_client -connect localhost:8443 2>/dev/null | openssl x509 -noout -dates

# Renew certificates
rawrxd-cli security renew-certs

# Or use Let's Encrypt
rawrxd-cli security enable-letsencrypt --email admin@example.com

# Restart service
sudo systemctl restart rawrxd
```

---

## Diagnostic Commands Reference

### System Information
```bash
# Full system report
rawrxd-cli diagnose --full > report.txt

# Quick health check
rawrxd-cli health --quick

# Component status
rawrxd-cli status --components

# Resource usage
rawrxd-cli metrics --system
```

### Log Analysis
```bash
# Recent errors
rawrxd-cli logs --level error --since "1 hour ago"

# Specific component
rawrxd-cli logs --component inference-engine --follow

# Export logs
rawrxd-cli logs --export --since "24 hours ago" --output logs.zip
```

### Performance Profiling
```bash
# CPU profiling
rawrxd-cli profile --cpu --duration 30s

# Memory profiling
rawrxd-cli profile --memory --duration 30s

# GPU profiling
rawrxd-cli profile --gpu --duration 30s
```

---

## Getting Help

### Before Contacting Support

1. Gather diagnostic information:
```bash
rawrxd-cli diagnose --full > diagnostic-report.txt
rawrxd-cli version > version.txt
rawrxd-cli config export > config.yaml
```

2. Check documentation:
- [API Documentation](https://docs.rawrxd.io/api)
- [Configuration Reference](https://docs.rawrxd.io/config)
- [FAQ](https://docs.rawrxd.io/faq)

3. Search known issues:
- [GitHub Issues](https://github.com/rawrxd/issues)
- [Community Forum](https://forum.rawrxd.io)

### Contact Support

- **Email:** support@rawrxd.io
- **Slack:** #rawrxd-support
- **GitHub:** Create an issue with diagnostic report attached

---

## Emergency Procedures

### Complete System Failure

1. **Immediate Actions:**
```bash
# Stop service
sudo systemctl stop rawrxd

# Check for core dumps
ls -la /var/lib/rawrxd/cores/

# Backup current state
sudo tar czf /tmp/rawrxd-emergency-backup.tar.gz /var/lib/rawrxd/

# Restart with safe mode
rawrxd-server --safe-mode --config /etc/rawrxd/config.minimal.yaml
```

2. **Recovery:**
```bash
# Restore from backup
rawrxd-cli restore --from-backup latest

# Verify integrity
rawrxd-cli verify --all

# Gradual restart
rawrxd-cli cluster restart --rolling
```

### Data Corruption

```bash
# Stop all writes
rawrxd-cli maintenance enable

# Check data integrity
rawrxd-cli verify --data-integrity

# Repair if possible
rawrxd-cli repair --auto

# Restore from backup if repair fails
rawrxd-cli restore --from-backup --before <timestamp>
```
