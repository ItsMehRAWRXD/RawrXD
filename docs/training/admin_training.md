# RawrXD Administrator Training

## Course Overview

This training course prepares system administrators to deploy, configure, and maintain RawrXD Sovereign AI inference runtime in production environments.

**Duration**: 2 days  
**Prerequisites**: Linux administration, container basics, networking fundamentals  
**Target Audience**: DevOps engineers, system administrators, platform engineers

## Day 1: Installation and Configuration

### Module 1: Introduction (1 hour)

#### What is RawrXD?
- Production-grade AI inference runtime
- Local LLM deployment platform
- OpenAI-compatible API
- Enterprise security features

#### Architecture Overview
- Service components
- Data flow
- Scaling options
- Security model

#### Use Cases
- Private AI deployment
- Cost optimization
- Compliance requirements
- Low-latency inference

### Module 2: Installation (2 hours)

#### System Requirements

**Minimum Requirements:**
- CPU: 4 cores
- RAM: 16 GB
- Disk: 50 GB SSD
- GPU: Optional (8GB+ VRAM recommended)

**Recommended Production:**
- CPU: 8+ cores
- RAM: 32+ GB
- Disk: 100+ GB NVMe SSD
- GPU: NVIDIA RTX 4090 / AMD RX 7900 XTX

#### Installation Methods

**Package Manager (Recommended):**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install rawrxd

# CentOS/RHEL
sudo yum install rawrxd

# macOS
brew install rawrxd
```

**Docker:**
```bash
docker pull rawrxd/sovereign:latest
docker run -p 8080:8080 rawrxd/sovereign:latest
```

**Binary Download:**
```bash
wget https://releases.rawrxd.local/latest/rawrxd-linux-amd64
chmod +x rawrxd-linux-amd64
sudo mv rawrxd-linux-amd64 /usr/local/bin/rawrxd
```

#### Configuration

**Configuration File Structure:**
```yaml
# /etc/rawrxd/config.yaml
server:
  host: 0.0.0.0
  port: 8080
  tls:
    enabled: true
    cert_file: /etc/rawrxd/ssl/server.crt
    key_file: /etc/rawrxd/ssl/server.key

models:
  directory: /var/lib/rawrxd/models
  default: llama3.1-8b
  preload: []

gpu:
  enabled: true
  device: 0
  memory_fraction: 0.95
  
logging:
  level: INFO
  format: json
  output: /var/log/rawrxd/server.log
  
security:
  auth_enabled: true
  api_key_header: X-API-Key
  rate_limiting:
    enabled: true
    requests_per_minute: 100
```

**Environment Variables:**
```bash
export RAWRXD_CONFIG=/etc/rawrxd/config.yaml
export RAWRXD_LOG_LEVEL=DEBUG
export RAWRXD_GPU_LAYERS=35
```

### Module 3: Model Management (2 hours)

#### Downloading Models

**From Ollama Library:**
```bash
rawrxd pull llama3.1-8b
rawrxd pull llama3.1-70b
rawrxd pull qwen2.5-14b
```

**From Hugging Face:**
```bash
rawrxd pull hf.co/unsloth/Llama-3.1-8B-GGUF
```

**Direct URL:**
```bash
rawrxd pull https://example.com/models/custom-model.gguf
```

#### Model Configuration

**Quantization Levels:**
| Level | Size | Speed | Quality |
|-------|------|-------|---------|
| Q4_0 | 4.3 GB | Fastest | Good |
| Q4_K_M | 4.7 GB | Fast | Better |
| Q5_K_M | 5.5 GB | Medium | Very Good |
| Q6_K | 6.6 GB | Medium | Excellent |
| Q8_0 | 8.5 GB | Slower | Best |
| F16 | 16 GB | Slowest | Maximum |

**GPU Layer Offloading:**
```bash
# Auto-detect optimal layers
rawrxd serve --gpu-layers -1

# Manual configuration
rawrxd serve --gpu-layers 35
```

#### Model Operations

**List Models:**
```bash
rawrxd list
```

**Show Model Info:**
```bash
rawrxd show llama3.1-8b
```

**Remove Model:**
```bash
rawrxd rm llama3.1-8b
```

**Copy/Customize:**
```bash
rawrxd cp llama3.1-8b my-custom-model
```

### Module 4: Service Management (1 hour)

#### Systemd Service

**Create Service File:**
```ini
# /etc/systemd/system/rawrxd.service
[Unit]
Description=RawrXD AI Inference Server
After=network.target

[Service]
Type=simple
User=rawrxd
Group=rawrxd
WorkingDirectory=/var/lib/rawrxd
ExecStart=/usr/local/bin/rawrxd serve
Restart=always
RestartSec=5
Environment="RAWRXD_CONFIG=/etc/rawrxd/config.yaml"

[Install]
WantedBy=multi-user.target
```

**Service Commands:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable rawrxd
sudo systemctl start rawrxd
sudo systemctl status rawrxd
sudo journalctl -u rawrxd -f
```

#### Health Checks

**Built-in Health Endpoint:**
```bash
curl http://localhost:8080/health
```

**Custom Health Check Script:**
```bash
#!/bin/bash
# /usr/local/bin/rawrxd-health-check

if curl -sf http://localhost:8080/health; then
    echo "Healthy"
    exit 0
else
    echo "Unhealthy"
    exit 1
fi
```

## Day 2: Operations and Troubleshooting

### Module 5: Monitoring (2 hours)

#### Metrics Collection

**Prometheus Integration:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'rawrxd'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
```

**Key Metrics:**
- `rawrxd_requests_total` - Total requests
- `rawrxd_request_duration_seconds` - Latency histogram
- `rawrxd_tokens_generated_total` - Token throughput
- `rawrxd_gpu_memory_used_bytes` - GPU memory usage
- `rawrxd_active_requests` - Concurrent requests

#### Logging

**Log Levels:**
- ERROR: Critical failures
- WARNING: Issues requiring attention
- INFO: Normal operations
- DEBUG: Detailed diagnostics

**Log Aggregation:**
```yaml
# Fluentd configuration
<source>
  @type tail
  path /var/log/rawrxd/*.log
  pos_file /var/log/fluent/rawrxd.pos
  tag rawrxd
  <parse>
    @type json
  </parse>
</source>
```

#### Alerting

**Alert Rules:**
```yaml
# alerts.yml
groups:
  - name: rawrxd
    rules:
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(rawrxd_request_duration_seconds_bucket[5m])) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"
          
      - alert: HighErrorRate
        expr: rate(rawrxd_requests_total{status=~"5.."}[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
```

### Module 6: Security (2 hours)

#### Authentication

**API Key Setup:**
```bash
# Generate API key
rawrxd api-key generate --name production

# List API keys
rawrxd api-key list

# Revoke API key
rawrxd api-key revoke <key-id>
```

**JWT Configuration:**
```yaml
security:
  jwt:
    enabled: true
    issuer: rawrxd.local
    audience: api.rawrxd.local
    secret: ${JWT_SECRET}
    expiry: 24h
```

#### Network Security

**Firewall Rules:**
```bash
# Allow API traffic
sudo ufw allow 8080/tcp

# Restrict to specific networks
sudo ufw allow from 10.0.0.0/8 to any port 8080
```

**TLS Configuration:**
```bash
# Generate certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# Configure RawrXD
rawrxd serve --tls-cert cert.pem --tls-key key.pem
```

#### Secrets Management

**Environment Variables:**
```bash
# Use systemd drop-in
sudo mkdir -p /etc/systemd/system/rawrxd.service.d
sudo tee /etc/systemd/system/rawrxd.service.d/secrets.conf <<EOF
[Service]
Environment="API_KEY_SECRET=$(cat /etc/rawrxd/api-key)"
Environment="DB_PASSWORD=$(cat /etc/rawrxd/db-password)"
EOF

sudo systemctl daemon-reload
sudo systemctl restart rawrxd
```

### Module 7: Backup and Recovery (1 hour)

#### Backup Strategy

**What to Backup:**
- Configuration files (/etc/rawrxd/)
- Model files (/var/lib/rawrxd/models/)
- Logs (/var/log/rawrxd/)
- API keys and secrets

**Backup Script:**
```bash
#!/bin/bash
# /usr/local/bin/rawrxd-backup

BACKUP_DIR="/backup/rawrxd/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup config
cp -r /etc/rawrxd $BACKUP_DIR/

# Backup models (if not stored elsewhere)
rsync -av /var/lib/rawrxd/models/ $BACKUP_DIR/models/

# Create archive
tar czf $BACKUP_DIR.tar.gz $BACKUP_DIR

# Upload to S3 (optional)
aws s3 cp $BACKUP_DIR.tar.gz s3://rawrxd-backups/

# Cleanup old backups
find /backup/rawrxd -name "*.tar.gz" -mtime +30 -delete
```

#### Recovery Procedures

**Configuration Recovery:**
```bash
# Restore from backup
tar xzf /backup/rawrxd/20240115.tar.gz -C /
sudo systemctl restart rawrxd
```

**Model Recovery:**
```bash
# Re-download models
rawrxd pull llama3.1-8b
rawrxd pull llama3.1-70b
```

### Module 8: Troubleshooting (2 hours)

#### Common Issues

**High Memory Usage:**
```bash
# Check memory usage
free -h
ps aux | grep rawrxd

# Reduce batch size
export RAWRXD_BATCH_SIZE=128

# Enable memory mapping
export RAWRXD_USE_MMAP=true
```

**GPU Not Detected:**
```bash
# Check NVIDIA drivers
nvidia-smi

# Check CUDA version
nvcc --version

# Verify GPU visibility
docker run --rm --gpus all nvidia/cuda:12.0-base nvidia-smi
```

**Slow Performance:**
```bash
# Check CPU usage
top

# Enable optimizations
export RAWRXD_USE_AVX2=true
export RAWRXD_THREADS=8

# Profile inference
rawrxd benchmark llama3.1-8b --verbose
```

#### Diagnostic Commands

```bash
# System information
rawrxd doctor

# Performance test
rawrxd benchmark llama3.1-8b

# Log analysis
rawrxd logs --tail 1000 --level ERROR

# Debug mode
rawrxd serve --log-level DEBUG
```

#### Getting Help

**Support Channels:**
- Documentation: https://docs.rawrxd.local
- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Community Forum: https://forum.rawrxd.local
- Enterprise Support: support@rawrxd.local

## Lab Exercises

### Lab 1: Basic Installation
1. Install RawrXD using package manager
2. Configure basic settings
3. Download a model
4. Test inference

### Lab 2: Production Setup
1. Configure TLS
2. Set up authentication
3. Configure monitoring
4. Create systemd service

### Lab 3: Troubleshooting
1. Simulate high load
2. Identify performance bottleneck
3. Apply optimization
4. Verify improvement

### Lab 4: Disaster Recovery
1. Create backup
2. Simulate data loss
3. Restore from backup
4. Verify functionality

## Assessment

### Written Test (30 minutes)
- Configuration scenarios
- Troubleshooting questions
- Security best practices
- Architecture knowledge

### Practical Exam (2 hours)
- Deploy RawrXD cluster
- Configure monitoring
- Resolve simulated issues
- Document procedures

## Certification

Upon successful completion:
- RawrXD Administrator Certificate
- Access to advanced training
- Priority support
- Beta program eligibility

## Resources

### Documentation
- Installation Guide
- Configuration Reference
- API Documentation
- Security Guide

### Tools
- RawrXD CLI
- Monitoring Dashboard
- Diagnostic Scripts
- Benchmark Tools

### Community
- Discord Server
- GitHub Repository
- Monthly Webinars
- User Conference
