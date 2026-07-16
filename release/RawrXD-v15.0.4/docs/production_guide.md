# RawrXD Production Deployment Guide

Complete guide for deploying RawrXD in production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Security Hardening](#security-hardening)
3. [Deployment](#deployment)
4. [Monitoring](#monitoring)
5. [Maintenance](#maintenance)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 8 cores | 32+ cores |
| RAM | 32 GB | 128+ GB |
| Disk | 100 GB SSD | 500 GB NVMe |
| GPU | Optional | NVIDIA A100 |
| Network | 1 Gbps | 10 Gbps |

### Software Requirements

- Windows Server 2019/2022 or Linux (Ubuntu 22.04+)
- PowerShell 7.0+
- CUDA 12.0+ (for GPU support)
- Docker (optional)

## Security Hardening

### 1. Configure Security Policy

```cpp
SecurityPolicy policy;
policy.require_auth = true;
policy.require_tls = true;
policy.min_tls_version = 13;  // TLS 1.3
policy.max_prompt_length = 8192;
policy.max_requests_per_minute = 60;
policy.audit_all_requests = true;

SecurityEnforcer enforcer(policy);
```

### 2. Enable Rate Limiting

```cpp
TokenBucketRateLimiter::Config config;
config.refill_rate_per_second = 10;
config.bucket_capacity = 100;

TokenBucketRateLimiter limiter(config);

// Check before processing
if (!limiter.allow(user_id)) {
    return ErrorCode::RATE_LIMITED;
}
```

### 3. Input Validation

```cpp
InputValidator::ValidationRules rules;
rules.max_length = 8192;
rules.sanitize_html = true;
rules.forbidden_patterns = {"<script", "javascript:"};

InputValidator validator(rules);

std::string error;
if (!validator.validate(input, error)) {
    return ErrorCode::INVALID_INPUT;
}
```

### 4. Circuit Breakers

```cpp
CircuitBreakerConfig config;
config.failure_threshold = 5;
config.timeout = std::chrono::seconds(30);

auto breaker = CircuitBreakerRegistry::getInstance()
    .getOrCreate("inference", config);

auto result = breaker->execute([&]() {
    return model->infer(input);
});
```

## Deployment

### Automated Deployment

```powershell
# Deploy to production
.\scripts\production_deploy.ps1 `
    -Version "1.0.0" `
    -Environment "production" `
    -ConfigPath "config/production.yaml"

# Dry run (test without deploying)
.\scripts\production_deploy.ps1 `
    -Version "1.0.0" `
    -Environment "staging" `
    -DryRun
```

### Manual Deployment Steps

1. **Backup Current Version**
   ```powershell
   # Backup is automatic in production_deploy.ps1
   # Manual backup:
   Copy-Item -Path "bin/" -Destination "backups/bin_$(Get-Date -Format yyyyMMdd)" -Recurse
   ```

2. **Stop Service**
   ```powershell
   Stop-Service -Name "RawrXD-production"
   ```

3. **Deploy Binaries**
   ```powershell
   Copy-Item -Path "artifacts/1.0.0/*" -Destination "." -Recurse -Force
   ```

4. **Update Configuration**
   ```powershell
   # Update config/production.yaml
   ```

5. **Start Service**
   ```powershell
   Start-Service -Name "RawrXD-production"
   ```

6. **Verify Health**
   ```powershell
   Invoke-RestMethod -Uri "http://localhost:8080/health"
   ```

### Rollback

```powershell
# Automatic rollback on failure (enabled by default)
# Manual rollback:
.\scripts\rollback.ps1 -Environment "production"

# Rollback to specific version
.\scripts\rollback.ps1 -Environment "production" -Version "0.9.0"
```

## Monitoring

### Health Checks

RawrXD provides several health endpoints:

| Endpoint | Purpose |
|----------|---------|
| `/health` | Overall health status |
| `/ready` | Ready to accept traffic |
| `/live` | Service is alive |
| `/startup` | Startup complete |

### Configure Health Checks

```cpp
HealthChecker health_checker;

// Register checks
health_checker.registerCheck("memory", []() {
    return health_checks::checkMemory(1024);  // 1GB min
}, true);  // Critical

health_checker.registerCheck("model", []() {
    return health_checks::checkModelLoaded(model);
}, true);

health_checker.registerCheck("inference", []() {
    return health_checks::checkInferenceLatency(model, 100ms);
}, false);  // Non-critical

// Start monitoring
health_checker.startMonitoring(std::chrono::seconds(30));
```

### Prometheus Metrics

```cpp
HealthMetricsExporter exporter(health_checker);

// Export to Prometheus
std::cout << exporter.exportPrometheus();
```

Metrics available:
- `health_check_status` - Health check pass/fail
- `health_check_duration_ms` - Health check duration
- `circuit_breaker_state` - Circuit breaker state
- `rate_limit_remaining` - Rate limit remaining

### Alerting

Configure alerts for:
- Health check failures
- High error rates
- Circuit breaker trips
- Rate limit exceeded
- Memory/disk thresholds

## Maintenance

### Maintenance Mode

```powershell
# Enable maintenance mode
.\scripts\maintenance_mode.ps1 -Enable -Message "Upgrading to v1.1.0"

# Check status
.\scripts\maintenance_mode.ps1 -Status

# Disable maintenance mode
.\scripts\maintenance_mode.ps1 -Disable
```

When in maintenance mode:
- API returns 503 Service Unavailable
- Retry-After header indicates when to retry
- Health endpoints still available for monitoring

### Log Rotation

```powershell
# Configure log rotation in config/production.yaml
logging:
  max_size_mb: 100
  max_files: 10
  retention_days: 30
```

### Backup Strategy

1. **Automated Backups**: Created during each deployment
2. **Backup Location**: `backups/`
3. **Retention**: Keep last 10 backups
4. **Verification**: Test restore quarterly

## Troubleshooting

### Common Issues

#### Service Won't Start

```powershell
# Check logs
Get-Content logs/rawrxd.log -Tail 100

# Check Windows Event Log
Get-EventLog -LogName Application -Source "RawrXD" -Newest 10

# Verify configuration
Test-Configuration -Path config/production.yaml
```

#### High Memory Usage

```powershell
# Check memory health
Invoke-RestMethod http://localhost:8080/health | Select-Object status

# Restart if needed
Restart-Service -Name "RawrXD-production"
```

#### Circuit Breaker Tripped

```powershell
# Check circuit breaker status
Invoke-RestMethod http://localhost:8080/metrics | 
    Select-String "circuit_breaker"

# Reset circuit breaker (if issue resolved)
# Requires API call or service restart
```

#### Rate Limiting

```powershell
# Check rate limit status
Invoke-RestMethod http://localhost:8080/metrics | 
    Select-String "rate_limit"

# Adjust limits if needed
# Edit config/production.yaml and restart
```

### Emergency Procedures

#### Complete Outage

1. Check service status: `Get-Service RawrXD-production`
2. Check logs: `Get-Content logs/error.log -Tail 50`
3. Attempt restart: `Restart-Service RawrXD-production`
4. If restart fails, rollback: `.\scripts\rollback.ps1 -Environment production`

#### Security Incident

1. Enable maintenance mode immediately
2. Review audit logs: `Get-Content logs/audit.log -Tail 100`
3. Block suspicious IPs in firewall
4. Rotate API keys
5. Investigate and remediate

### Support Contacts

- **On-call**: oncall@rawrxd.ai
- **Security**: security@rawrxd.ai
- **Emergency**: +1-555-RAWRXD

## Best Practices

1. **Always backup before deploying**
2. **Test in staging first**
3. **Monitor health after deployment**
4. **Keep rollback ready**
5. **Document all changes**
6. **Rotate secrets regularly**
7. **Review audit logs daily**
8. **Test disaster recovery quarterly**

## Checklist

Pre-deployment:
- [ ] Staging tests passed
- [ ] Configuration reviewed
- [ ] Backup created
- [ ] Rollback plan ready
- [ ] Team notified

Post-deployment:
- [ ] Health checks passing
- [ ] Metrics normal
- [ ] No error spikes
- [ ] Performance acceptable
- [ ] Documentation updated
