# Getting Started with RawrXD Sovereign

## Phase I Batch 2/5: User Guides

Welcome to RawrXD Sovereign - the production-grade AI inference runtime.

---

## Quick Start

### 1. Installation

#### Windows (Winget)
```powershell
winget install RawrXD.RawrXD
```

#### Windows (Chocolatey)
```powershell
choco install rawrxd
```

#### macOS (Homebrew)
```bash
brew install rawrxd
```

#### Linux (APT)
```bash
curl -fsSL https://apt.rawrxd.ai/setup.sh | sudo bash
sudo apt-get install rawrxd
```

### 2. Start the Service

#### Windows
```powershell
Start-Service RawrXD
```

#### macOS/Linux
```bash
sudo systemctl start rawrxd
```

### 3. Verify Installation

```bash
rawrxd --version
```

Expected output:
```
RawrXD Sovereign v1.0.0
Build: 2026-07-13
Platform: x64
```

---

## First Inference

### Using curl

```bash
curl -X POST http://localhost:8080/api/v1/inference \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama-3-8b",
    "prompt": "Hello, RawrXD!",
    "max_tokens": 100
  }'
```

### Using Python

```python
import requests

response = requests.post(
    "http://localhost:8080/api/v1/inference",
    json={
        "model": "llama-3-8b",
        "prompt": "Hello, RawrXD!",
        "max_tokens": 100
    }
)

print(response.json()["content"])
```

---

## Configuration

Edit the configuration file:

**Windows:**
```
%ProgramData%\RawrXD\config\rawrxd.yaml
```

**Linux/macOS:**
```
/etc/rawrxd/rawrxd.yaml
```

### Basic Configuration

```yaml
version: "1.0.0"

server:
  host: "0.0.0.0"
  port: 8080

inference:
  default_model: "llama-3-8b"
  max_tokens: 4096
  temperature: 0.7
  top_p: 0.9
  top_k: 40

models:
  directory: "/opt/rawrxd/models"
  preload: ["llama-3-8b"]

logging:
  level: "info"
  file: "/var/log/rawrxd/service.log"

features:
  autonomous: true
  hotpatch: true
  telemetry: true
```

---

## Loading Models

### Download a Model

```bash
rawrxd-cli model pull llama-3-8b
```

### Load a Model

```bash
curl -X POST http://localhost:8080/api/v1/models/load \
  -H "Content-Type: application/json" \
  -d '{"model_id": "llama-3-8b", "gpu_layers": 33}'
```

---

## Monitoring

### Check Health

```bash
curl http://localhost:8080/api/v1/health
```

### View Metrics

```bash
curl http://localhost:8080/api/v1/metrics
```

### Access Grafana Dashboard

Open http://localhost:3000 in your browser (if Grafana is configured).

---

## Troubleshooting

### Service Won't Start

1. Check logs:
   ```bash
   tail -f /var/log/rawrxd/service.log
   ```

2. Verify configuration:
   ```bash
   rawrxd --config-check
   ```

3. Check port availability:
   ```bash
   netstat -tlnp | grep 8080
   ```

### Low Performance

1. Check GPU utilization:
   ```bash
   nvidia-smi
   ```

2. Adjust batch size:
   ```yaml
   inference:
     batch_size: 512
   ```

3. Enable GPU layers:
   ```yaml
   models:
     gpu_layers: 33  # Adjust based on your GPU
   ```

---

## Next Steps

- [API Reference](API_REFERENCE.md)
- [Configuration Guide](CONFIGURATION.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Troubleshooting](TROUBLESHOOTING.md)

---

*RawrXD Getting Started Guide v1.0.0*
