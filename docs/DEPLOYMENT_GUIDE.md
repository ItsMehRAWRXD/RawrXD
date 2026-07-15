# RawrXD Deployment Guide

Complete guide for deploying RawrXD v1.5.0 in production environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

#### Minimum (Development)
- CPU: 4 cores
- RAM: 16 GB
- Storage: 50 GB SSD
- GPU: Optional (CPU inference)

#### Recommended (Production)
- CPU: 16+ cores
- RAM: 64+ GB
- Storage: 500 GB NVMe SSD
- GPU: NVIDIA A100 80GB or equivalent
- Network: 10 Gbps

#### Multi-GPU Setup
- 2-8x NVIDIA A100/H100 GPUs
- NVLink interconnect
- 256+ GB system RAM

### Software Requirements

- OS: Ubuntu 22.04 LTS / CentOS 8 / Windows Server 2022
- Docker: 24.0+ (for containerized deployment)
- Kubernetes: 1.28+ (for orchestrated deployment)
- NVIDIA Driver: 535+ (for GPU support)
- CUDA: 12.0+ (for GPU support)

---

## Installation

### Option 1: Binary Installation

```bash
# Download latest release
wget https://github.com/ItsMehRAWRXD/RawrXD/releases/latest/download/rawrxd-linux-x64.tar.gz

# Extract
tar -xzf rawrxd-linux-x64.tar.gz
sudo mv rawrxd /usr/local/bin/
sudo chmod +x /usr/local/bin/rawrxd

# Verify installation
rawrxd --version
```

### Option 2: Build from Source

```bash
# Clone repository
git clone https://github.com/ItsMehRAWRXD/RawrXD.git
cd RawrXD

# Install dependencies
sudo apt-get update
sudo apt-get install -y cmake build-essential libssl-dev

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install
sudo make install
```

### Option 3: Docker

```bash
# Pull image
docker pull rawrxd/rawrxd:latest

# Run
docker run -d \
  --name rawrxd \
  -p 8080:8080 \
  -v /path/to/models:/models:ro \
  -e RAWRXD_MODEL_PATH=/models/model.gguf \
  rawrxd/rawrxd:latest
```

---

## Configuration

### Basic Configuration

Create `config/server.json`:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "threads": 16,
    "request_timeout_ms": 60000
  },
  "model": {
    "path": "/models/llama-7b.gguf",
    "context_length": 4096,
    "batch_size": 32
  },
  "optimization": {
    "flash_attention": true,
    "continuous_batching": true,
    "quantization": {
      "enabled": true,
      "type": "Q4_K"
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RAWRXD_CONFIG_PATH` | Config file path | `config/server.json` |
| `RAWRXD_LOG_LEVEL` | Log level (TRACE/DEBUG/INFO/WARN/ERROR) | `INFO` |
| `RAWRXD_MODEL_PATH` | Model file path | From config |
| `RAWRXD_PORT` | Server port | From config |
| `RAWRXD_THREADS` | Worker threads | From config |
| `CUDA_VISIBLE_DEVICES` | GPU devices to use | All |

### Advanced Configuration

#### GPU Settings

```json
{
  "gpu": {
    "device_ids": [0, 1, 2, 3],
    "memory_fraction": 0.9,
    "allow_growth": true,
    "tensor_cores": true
  }
}
```

#### Distributed Settings

```json
{
  "distributed": {
    "enabled": true,
    "tensor_parallel": 4,
    "pipeline_parallel": 1,
    "master_addr": "192.168.1.100",
    "master_port": 29500,
    "world_size": 4,
    "rank": 0
  }
}
```

#### Monitoring Settings

```json
{
  "monitoring": {
    "prometheus_port": 9090,
    "log_level": "INFO",
    "log_format": "json",
    "enable_tracing": true,
    "trace_sample_rate": 0.1
  }
}
```

---

## Deployment Options

### Single Node (Single GPU)

```bash
# Start server
rawrxd_server --config config/server.json

# Or with command line options
rawrxd_server \
  --model /models/llama-7b.gguf \
  --port 8080 \
  --threads 16
```

### Single Node (Multi-GPU)

```bash
# Using tensor parallelism
rawrxd_server \
  --config config/server.json \
  --tensor-parallel 4

# Or with environment variables
export CUDA_VISIBLE_DEVICES=0,1,2,3
rawrxd_server --config config/server.json
```

### Docker Compose

```yaml
version: '3.8'

services:
  rawrxd:
    image: rawrxd/rawrxd:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./models:/models:ro
      - ./config:/config:ro
    environment:
      - RAWRXD_CONFIG_PATH=/config/server.json
      - RAWRXD_LOG_LEVEL=INFO
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - ./config/grafana:/etc/grafana/provisioning:ro
    restart: unless-stopped
```

Start with:
```bash
docker-compose up -d
```

### Kubernetes

#### Basic Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rawrxd
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rawrxd
  template:
    metadata:
      labels:
        app: rawrxd
    spec:
      containers:
      - name: rawrxd
        image: rawrxd/rawrxd:v1.5.0
        ports:
        - containerPort: 8080
        - containerPort: 9090
        resources:
          limits:
            nvidia.com/gpu: "1"
            memory: "32Gi"
            cpu: "8"
          requests:
            nvidia.com/gpu: "1"
            memory: "16Gi"
            cpu: "4"
        volumeMounts:
        - name: models
          mountPath: /models
          readOnly: true
        - name: config
          mountPath: /config
          readOnly: true
      volumes:
      - name: models
        persistentVolumeClaim:
          claimName: rawrxd-models
      - name: config
        configMap:
          name: rawrxd-config
      nodeSelector:
        accelerator: nvidia-gpu
```

#### With Horizontal Pod Autoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rawrxd-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rawrxd
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Pods
    pods:
      metric:
        name: rawrxd_requests_per_second
      target:
        type: AverageValue
        averageValue: "100"
```

Deploy:
```bash
kubectl apply -f kubernetes/
```

### Cloud Deployment

#### AWS (EKS)

```bash
# Create EKS cluster
eksctl create cluster \
  --name rawrxd-cluster \
  --region us-west-2 \
  --node-type p4d.24xlarge \
  --nodes 3

# Install NVIDIA device plugin
kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.0/nvidia-device-plugin.yml

# Deploy RawrXD
kubectl apply -f kubernetes/
```

#### GCP (GKE)

```bash
# Create GKE cluster with GPU nodes
gcloud container clusters create rawrxd-cluster \
  --accelerator type=nvidia-tesla-a100,count=1 \
  --machine-type a2-highgpu-1g \
  --num-nodes 3

# Install NVIDIA driver
gcloud container clusters get-credentials rawrxd-cluster
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/container-engine-accelerators/master/nvidia-driver-installer/cos/daemonset-preloaded.yaml

# Deploy RawrXD
kubectl apply -f kubernetes/
```

#### Azure (AKS)

```bash
# Create AKS cluster with GPU nodes
az aks create \
  --resource-group myResourceGroup \
  --name rawrxd-cluster \
  --node-vm-size Standard_NC24s_v3 \
  --node-count 3

# Install NVIDIA device plugin
kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.14.0/nvidia-device-plugin.yml

# Deploy RawrXD
kubectl apply -f kubernetes/
```

---

## Monitoring

### Prometheus Metrics

Access metrics at `http://localhost:9090/metrics`

Key metrics:
- `rawrxd_requests_total` - Total requests
- `rawrxd_request_duration_seconds` - Request latency
- `rawrxd_tokens_generated_total` - Throughput
- `rawrxd_gpu_memory_usage_bytes` - GPU memory

### Grafana Dashboard

Import dashboard from `config/grafana/dashboard.json`

URL: `http://localhost:3000`

Default credentials:
- Username: `admin`
- Password: `rawrxd-admin`

### Health Checks

```bash
# Health endpoint
curl http://localhost:8080/health

# Expected response:
# {"status": "healthy", "version": "1.5.0"}
```

### Logging

View logs:
```bash
# Docker
docker logs rawrxd

# Kubernetes
kubectl logs -l app=rawrxd

# Systemd
journalctl -u rawrxd -f
```

---

## Performance Tuning

### Batch Size Optimization

```json
{
  "optimization": {
    "continuous_batching": {
      "max_batch_size": 32,
      "max_waiting_tokens": 20,
      "max_waiting_time_ms": 100
    }
  }
}
```

### Memory Optimization

```json
{
  "kv_cache": {
    "type": "paged",
    "page_size": 256,
    "max_cache_size_mb": 8192
  }
}
```

### GPU Optimization

```json
{
  "optimization": {
    "flash_attention": true,
    "speculative_decoding": {
      "enabled": true,
      "num_draft_tokens": 4
    },
    "quantization": {
      "enabled": true,
      "type": "Q4_K"
    }
  }
}
```

---

## Troubleshooting

### Common Issues

#### Out of Memory

**Symptoms:**
- Server crashes with OOM error
- GPU memory allocation failures

**Solutions:**
1. Reduce batch size
2. Enable quantization
3. Reduce context length
4. Use model parallelism

#### Slow Performance

**Symptoms:**
- High latency
- Low throughput

**Solutions:**
1. Enable Flash Attention
2. Enable continuous batching
3. Increase batch size
4. Check GPU utilization

#### Model Loading Failures

**Symptoms:**
- Server fails to start
- Model file not found errors

**Solutions:**
1. Verify model path
2. Check file permissions
3. Verify model format (GGUF)
4. Check disk space

### Debug Mode

Enable debug logging:
```bash
export RAWRXD_LOG_LEVEL=DEBUG
rawrxd_server --config config/server.json
```

### Profiling

Enable performance profiling:
```json
{
  "monitoring": {
    "enable_profiling": true,
    "profile_output_path": "/tmp/profiles"
  }
}
```

---

## Security

### API Key Authentication

```json
{
  "security": {
    "api_key_required": true,
    "api_keys": ["sk-xxx", "sk-yyy"]
  }
}
```

### TLS/SSL

```json
{
  "server": {
    "tls": {
      "enabled": true,
      "cert_path": "/etc/ssl/certs/server.crt",
      "key_path": "/etc/ssl/private/server.key"
    }
  }
}
```

### Network Policies

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: rawrxd-network-policy
spec:
  podSelector:
    matchLabels:
      app: rawrxd
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: frontend
    ports:
    - protocol: TCP
      port: 8080
```

---

## Backup and Recovery

### Model Backup

```bash
# Backup models
rsync -av /models/ backup/models/

# Or use cloud storage
aws s3 sync /models/ s3://my-bucket/models/
```

### Configuration Backup

```bash
# Backup config
cp config/server.json config/server.json.backup

# Version control
git add config/server.json
git commit -m "Backup configuration"
```

### Disaster Recovery

1. Keep model files in multiple locations
2. Use persistent volumes for Kubernetes
3. Regular configuration backups
4. Document recovery procedures

---

## Support

- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Documentation: https://rawrxd.readthedocs.io
- Discord: https://discord.gg/rawrxd
