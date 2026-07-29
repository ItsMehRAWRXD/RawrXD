# Sovereign Substrate - Troubleshooting Guide

## Common Issues and Solutions

### Build Issues

#### Issue: CMake configuration fails
```
CMake Error: Could not find a package configuration file provided by...
```

**Solution:**
```bash
# Ensure you have CMake 3.16+
cmake --version

# Clear CMake cache and reconfigure
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
```

#### Issue: Compiler not found (Windows)
```
'cl' is not recognized as an internal or external command
```

**Solution:**
```cmd
# Run from Visual Studio Developer Command Prompt
# Or set up environment:
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

#### Issue: Link errors on Windows
```
unresolved external symbol...
```

**Solution:**
```bash
# Ensure all dependencies are built
cmake --build . --target ALL_BUILD

# Or try static linking
cmake .. -DRAWR_BUILD_SHARED=OFF
```

### Runtime Issues

#### Issue: Control Plane won't start
```
Failed to bind to port 8080
```

**Solution:**
```bash
# Check if port is in use
lsof -i :8080  # Linux/macOS
netstat -ano | findstr :8080  # Windows

# Change port in config
echo '{"control_plane": {"port": 8082}}' > config/override.json
```

#### Issue: Model API calls fail
```
Model API error: 401 Unauthorized
```

**Solution:**
```bash
# Set API key
export KIMI_API_KEY="your-key-here"  # Linux/macOS
set KIMI_API_KEY=your-key-here  # Windows

# Or add to config
echo '{"model": {"api_key": "your-key"}}' > config/local.json
```

#### Issue: Tool execution permission denied
```
Permission denied: /etc/passwd
```

**Solution:**
```bash
# Check security settings
cat config/sovereign.json | grep -A5 sandbox

# Add allowed path
# Edit config/sovereign.json:
# "allowed_paths": ["${WORKSPACE}", "/your/path"]
```

### Test Failures

#### Issue: Tests fail with timeout
```
Test timeout after 30 seconds
```

**Solution:**
```bash
# Run with longer timeout
ctest --timeout 120

# Or run specific test
./tests/test_agent_kernel --gtest_filter="*"
```

#### Issue: Memory tests fail
```
Memory leak detected
```

**Solution:**
```bash
# Run with valgrind (Linux)
valgrind --leak-check=full ./tests/test_repository_memory

# Or disable memory tests temporarily
cmake .. -DRAWR_MEMORY_TESTS=OFF
```

### Performance Issues

#### Issue: High memory usage
```
Memory usage exceeds 500MB
```

**Solution:**
```bash
# Reduce cache size
# Edit config/sovereign.json:
# "performance": {"cache_size_mb": 256}

# Enable garbage collection
# "performance": {"gc_interval_minutes": 5}
```

#### Issue: Slow intent execution
```
Intent execution takes > 10 seconds
```

**Solution:**
```bash
# Check model timeout
# Edit config/sovereign.json:
# "model": {"timeout_seconds": 30}

# Enable caching
# "performance": {"cache_size_mb": 512}
```

### Security Issues

#### Issue: Audit logs not written
```
Failed to write audit log
```

**Solution:**
```bash
# Check log directory permissions
ls -la /var/log/sovereign  # Linux
# Should be writable by application user

# Or change log location
# Edit config/sovereign.json:
# "security": {"audit_logging": {"log_file": "${HOME}/logs/audit.log"}}
```

#### Issue: Rate limiting too strict
```
Rate limit exceeded
```

**Solution:**
```bash
# Adjust rate limits
# Edit config/sovereign.json:
# "security": {"rate_limiting": {"requests_per_second": 20}}
```

### Integration Issues

#### Issue: WebSocket connection fails
```
WebSocket connection error
```

**Solution:**
```javascript
// Check CORS settings
// Edit config/sovereign.json:
// "control_plane": {"cors_origins": ["http://your-domain:3000"]}

// Verify WebSocket port
// "control_plane": {"websocket_port": 8081}
```

#### Issue: Python client can't connect
```
Connection refused
```

**Solution:**
```python
# Verify server is running
curl http://localhost:8080/health

# Check firewall
# Linux: sudo ufw allow 8080
# Windows: netsh advfirewall firewall add rule...
```

### Docker Issues

#### Issue: Docker build fails
```
failed to solve: rpc error
```

**Solution:**
```bash
# Clear Docker cache
docker system prune -a

# Or build without cache
docker build --no-cache -f docker/Dockerfile.sovereign .
```

#### Issue: Container exits immediately
```
Container exited with code 1
```

**Solution:**
```bash
# Check logs
docker logs <container-id>

# Run interactively
docker run -it sovereign:latest /bin/bash
```

### Deployment Issues

#### Issue: Deployment script fails
```
Deployment failed at health check
```

**Solution:**
```bash
# Check service status
systemctl status sovereign  # Linux
Get-Service Sovereign  # Windows

# View logs
journalctl -u sovereign -f  # Linux
Get-EventLog -LogName Application  # Windows
```

#### Issue: Rollback fails
```
No backup found for rollback
```

**Solution:**
```bash
# Check backup directory
ls -la /opt/sovereign-backups/

# Create manual backup
./scripts/deploy-sovereign.sh staging backup-only
```

## Debug Mode

### Enable Debug Logging

```bash
# Set log level
export RAWR_LOG_LEVEL=DEBUG

# Or edit config
# "logging": {"level": "DEBUG"}
```

### Run with GDB

```bash
# Linux
gdb ./demo/demo_sovereign_substrate
(gdb) run
(gdb) bt  # Get backtrace on crash
```

### Run with Visual Studio Debugger

```cmd
# Windows
devenv /debugexe .\demo\demo_sovereign_substrate.exe
```

## Getting Help

### Collect Debug Information

```bash
# Run diagnostic script
./scripts/diagnose.sh > debug-info.txt

# Include:
# - OS version
# - Compiler version
# - CMake version
# - Full build log
# - Config files
# - Test output
```

### Report Issues

1. Check existing issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
2. Create new issue with:
   - Description of problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Debug information
   - Minimal reproduction case

## Quick Fixes

### Reset Everything

```bash
# Nuclear option - reset everything
rm -rf build
rm -rf ~/.sovereign
rm -rf /opt/sovereign
./scripts/quick-start.sh
```

### Clean Build

```bash
# Clean build
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel
```

### Update Configuration

```bash
# Reset to defaults
cp config/sovereign.json config/sovereign.json.bak
curl -o config/sovereign.json https://raw.githubusercontent.com/.../sovereign.json
```

## Known Limitations

1. **Windows Path Length**: Maximum 260 characters
   - Solution: Use `\\?\` prefix or enable long paths in Windows

2. **macOS Gatekeeper**: May block unsigned binaries
   - Solution: `xattr -cr ./demo/demo_sovereign_substrate`

3. **Linux SELinux**: May prevent file access
   - Solution: `setenforce 0` or configure SELinux policies

## Support

- **Documentation**: https://docs.rawrxd.dev
- **GitHub Issues**: https://github.com/ItsMehRAWRXD/RawrXD/issues
- **Discord**: https://discord.gg/rawrxd
- **Email**: support@rawrxd.dev
