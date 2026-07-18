# RawrXD Administrator Training

## Phase I Batch 3/5: Training Materials

Training course for system administrators managing RawrXD Sovereign deployments.

---

## Course Overview

**Duration:** 4 hours  
**Level:** Intermediate  
**Prerequisites:** Basic Linux/Windows administration, networking fundamentals

---

## Module 1: Installation & Setup (45 min)

### Learning Objectives
- Install RawrXD on multiple platforms
- Configure basic settings
- Verify installation

### Hands-On Lab

```bash
# Install RawrXD
sudo apt-get install rawrxd

# Configure service
sudo systemctl enable rawrxd
sudo systemctl start rawrxd

# Verify
sudo systemctl status rawrxd
curl http://localhost:8080/api/v1/health
```

### Quiz
1. What is the default port for RawrXD?
2. How do you enable the service to start on boot?
3. Where are configuration files stored?

---

## Module 2: Configuration Management (60 min)

### Learning Objectives
- Understand configuration file structure
- Tune performance settings
- Configure security options

### Configuration Sections

```yaml
# Server settings
server:
  host: "0.0.0.0"      # Bind address
  port: 8080           # HTTP port
  workers: 4           # Worker processes

# Inference settings
inference:
  batch_size: 512      # Tokens per batch
  max_tokens: 4096     # Max output length
  temperature: 0.7     # Sampling temperature

# Security settings
security:
  auth_required: true
  api_key_rotation_days: 30
  rate_limiting: true
```

### Exercise

Configure RawrXD for high-throughput deployment:
- Set batch_size to 1024
- Enable GPU acceleration
- Configure rate limiting

---

## Module 3: Monitoring & Alerting (60 min)

### Learning Objectives
- Set up Prometheus/Grafana
- Configure alert rules
- Interpret metrics

### Lab: Setting Up Monitoring

```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz
tar xvfz prometheus-2.45.0.linux-amd64.tar.gz

# Configure prometheus.yml
cat > prometheus.yml << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rawrxd'
    static_configs:
      - targets: ['localhost:8080']
EOF

# Start Prometheus
./prometheus --config.file=prometheus.yml
```

### Key Metrics to Monitor

| Metric | Warning | Critical |
|--------|---------|----------|
| CPU Usage | >70% | >90% |
| Memory Usage | >80% | >95% |
| Disk Free | <10GB | <5GB |
| Latency P95 | >500ms | >1000ms |
| TPS | <20 | <10 |

---

## Module 4: Backup & Recovery (45 min)

### Learning Objectives
- Create backups
- Restore from backup
- Perform version rollback

### Backup Procedures

```bash
# Create full backup
sudo rawrxd-cli backup create --output /backup/rawrxd-$(date +%Y%m%d).tar.gz

# List backups
sudo rawrxd-cli backup list

# Restore from backup
sudo rawrxd-cli backup restore /backup/rawrxd-20260713.tar.gz
```

### Emergency Recovery

```bash
# Enter safe mode
sudo rawrxd-cli safe-mode enter

# Check health
sudo rawrxd-cli health check

# Rollback to previous version
sudo rawrxd-cli rollback --version 1.0.0
```

---

## Module 5: Troubleshooting (30 min)

### Common Issues

#### High Memory Usage
```bash
# Check memory usage
ps aux | grep rawrxd

# Clear cache
sudo rawrxd-cli cache clear

# Reduce batch size in config
```

#### Service Won't Start
```bash
# Check logs
sudo journalctl -u rawrxd -n 100

# Verify config
sudo rawrxd --config-check

# Check port conflicts
sudo netstat -tlnp | grep 8080
```

#### Low TPS
```bash
# Check GPU utilization
nvidia-smi

# Verify model is loaded
curl http://localhost:8080/api/v1/models

# Check for errors in logs
sudo tail -f /var/log/rawrxd/error.log
```

---

## Assessment

### Practical Exam

1. Install RawrXD on a fresh system
2. Configure for production use
3. Set up monitoring
4. Create and restore a backup
5. Troubleshoot a simulated outage

### Certification

Upon completion, administrators receive:
- RawrXD Certified Administrator credential
- Access to support portal
- Priority support queue

---

## Resources

- [Full Documentation](https://docs.rawrxd.ai)
- [Support Portal](https://support.rawrxd.ai)
- [Community Forum](https://community.rawrxd.ai)

---

*RawrXD Administrator Training v1.0.0*
