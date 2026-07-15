# RawrXD Knowledge Base - Frequently Asked Questions

## General Questions

### What is RawrXD?
RawrXD Sovereign is a production-grade AI inference runtime designed for deploying large language models locally. It provides an OpenAI-compatible API for running LLMs on your own infrastructure with enterprise-grade security, monitoring, and scalability.

### What models are supported?
RawrXD supports models in the following formats:
- **GGUF** (llama.cpp format) - Recommended
- **SafeTensors** (Hugging Face format)
- **ONNX** (Open Neural Network Exchange)

Popular supported models include:
- Llama 3.1 (8B, 70B, 405B)
- Qwen 2.5 (various sizes)
- Mistral (7B, 8x7B, 8x22B)
- Gemma (2B, 9B, 27B)
- And many more via GGUF conversion

### Is RawrXD free to use?
Yes, RawrXD Sovereign is open-source software licensed under the MIT License. You can use it for free for personal and commercial purposes. Enterprise support subscriptions are available for organizations requiring SLA-backed support.

## Installation & Setup

### What are the minimum system requirements?
**Minimum:**
- 4 CPU cores
- 16 GB RAM
- 50 GB SSD storage

**Recommended for Production:**
- 8+ CPU cores
- 32+ GB RAM
- 100+ GB NVMe SSD
- GPU with 16GB+ VRAM (NVIDIA RTX 4090 or AMD RX 7900 XTX)

### How do I install RawrXD?

**Windows (PowerShell):**
```powershell
winget install RawrXD.RawrXD
```

**macOS (Homebrew):**
```bash
brew tap rawrxd/tap
brew install rawrxd
```

**Linux (APT):**
```bash
curl -fsSL https://releases.rawrxd.local/install.sh | sudo bash
```

**Docker:**
```bash
docker pull rawrxd/sovereign:latest
```

### How do I configure RawrXD?
Configuration is done via YAML file at `~/.rawrxd/config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 8080

models:
  directory: ~/.rawrxd/models
  default: llama3.1-8b

gpu:
  enabled: true
  layers: -1  # Auto-detect
```

## Model Management

### How do I download a model?
```bash
rawrxd pull llama3.1-8b
```

Or from Hugging Face:
```bash
rawrxd pull hf.co/unsloth/Llama-3.1-8B-GGUF
```

### Where are models stored?
Models are stored in `~/.rawrxd/models/` by default. You can change this in the configuration:

```yaml
models:
  directory: /path/to/models
```

### How do I load a model?
Models are loaded automatically on first use. To preload:
```bash
rawrxd load llama3.1-8b
```

### What quantization should I use?
| Quantization | Size | Speed | Quality | Use Case |
|--------------|------|-------|---------|----------|
| Q4_0 | 4.3 GB | Fastest | Good | Development |
| Q4_K_M | 4.7 GB | Fast | Better | Balanced |
| Q5_K_M | 5.5 GB | Medium | Very Good | Production |
| Q6_K | 6.6 GB | Medium | Excellent | Quality-focused |
| Q8_0 | 8.5 GB | Slower | Best | Maximum quality |
| F16 | 16 GB | Slowest | Maximum | Research |

### How do I unload a model?
```bash
rawrxd unload llama3.1-8b
```

Or via API:
```bash
curl -X DELETE http://localhost:8080/v1/models/llama3.1-8b
```

## Performance

### What performance can I expect?
**With AMD RX 7800 XT (16GB):**
- Throughput: 45+ tokens/second
- Time to First Token: ~85ms
- P95 Latency: ~420ms

**With NVIDIA RTX 4090 (24GB):**
- Throughput: 60+ tokens/second
- Time to First Token: ~60ms
- P95 Latency: ~350ms

### How do I optimize performance?

**GPU Optimization:**
```yaml
gpu:
  enabled: true
  layers: 35  # Adjust based on VRAM
  
inference:
  threads: 8
  batch_size: 512
```

**CPU Optimization:**
```yaml
inference:
  threads: 16  # Match physical cores
  use_avx2: true
  use_avx512: true
```

### Why is my GPU not being used?
1. Check NVIDIA drivers: `nvidia-smi`
2. Verify CUDA installation: `nvcc --version`
3. Check RawrXD GPU detection in logs
4. Ensure GPU layers > 0: `gpu_layers: -1` for auto

### How do I reduce memory usage?
1. Use lower quantization (Q4 instead of Q8)
2. Reduce context length
3. Enable memory mapping: `use_mmap: true`
4. Reduce batch size

## API Usage

### Is the API OpenAI-compatible?
Yes! RawrXD provides an OpenAI-compatible API:

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="your-api-key"
)

response = client.chat.completions.create(
    model="llama3.1-8b",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### How do I enable authentication?
```yaml
security:
  auth_enabled: true
  api_key: ${RAWRXD_API_KEY}
```

Generate API key:
```bash
rawrxd api-key generate --name production
```

### How do I use streaming?
```python
response = client.chat.completions.create(
    model="llama3.1-8b",
    messages=[{"role": "user", "content": "Tell me a story"}],
    stream=True
)

for chunk in response:
    print(chunk.choices[0].delta.content, end="")
```

### What are the rate limits?
Default: 100 requests/minute per API key

Configure in `config.yaml`:
```yaml
security:
  rate_limiting:
    enabled: true
    requests_per_minute: 100
```

## Troubleshooting

### Service won't start
**Check:**
1. Port 8080 available: `netstat -tuln | grep 8080`
2. Sufficient disk space: `df -h`
3. Configuration valid: `rawrxd config validate`
4. Logs for errors: `journalctl -u rawrxd -n 100`

### Out of memory errors
**Solutions:**
1. Reduce GPU layers
2. Use smaller quantization
3. Enable swap (emergency only)
4. Add more RAM

### High latency
**Check:**
1. GPU utilization: `nvidia-smi`
2. Batch queue depth
3. Model size vs VRAM
4. Concurrent request count

**Solutions:**
1. Increase GPU layers
2. Enable request batching
3. Scale horizontally
4. Use faster quantization

### Model loading fails
**Check:**
1. Model file exists and is valid
2. Sufficient disk space
3. File permissions
4. Model format compatibility

**Fix:**
```bash
# Re-download model
rawrxd rm llama3.1-8b
rawrxd pull llama3.1-8b
```

### Authentication errors
**Check:**
1. API key valid and not expired
2. Header format correct: `Authorization: Bearer <key>`
3. Clock synchronized (for JWT)
4. Key has required permissions

## Security

### Is my data secure?
Yes, RawrXD implements:
- TLS 1.3 encryption in transit
- AES-256-GCM encryption at rest
- RBAC with fine-grained permissions
- Audit logging
- SOC 2 and ISO 27001 compliance

### How do I rotate API keys?
```bash
# Generate new key
rawrxd api-key generate --name production-new

# Update applications
# Revoke old key
rawrxd api-key revoke old-key-id
```

### Can I run RawrXD offline?
Yes! RawrXD is designed for air-gapped deployments:
1. Download models on connected system
2. Transfer to offline system
3. Configure local model path
4. Disable external features

## Scaling

### How do I scale horizontally?
Deploy multiple RawrXD instances behind a load balancer:

```yaml
# docker-compose.yml
services:
  rawrxd-1:
    image: rawrxd/sovereign:latest
    ports:
      - "8081:8080"
  
  rawrxd-2:
    image: rawrxd/sovereign:latest
    ports:
      - "8082:8080"
  
  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
```

### How do I enable auto-scaling?
**Kubernetes:**
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
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

## Enterprise Features

### What enterprise features are available?
- **Sovereign Governance**: 3-sigma safety envelope
- **Hotpatch System**: Zero-downtime updates
- **Multi-tenant Support**: Resource isolation
- **Advanced Monitoring**: Prometheus/Grafana integration
- **Audit Logging**: Complete compliance trail
- **SLA-backed Support**: 24/7 enterprise support

### How do I get enterprise support?
Contact sales@rawrxd.local or visit https://rawrxd.local/enterprise

### Is there a managed service option?
Yes, RawrXD Cloud provides fully managed deployment:
- Managed infrastructure
- Automatic updates
- 99.99% SLA
- Global CDN
- Contact sales for pricing

## Contributing

### How can I contribute?
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

See CONTRIBUTING.md for details.

### Where can I report bugs?
- GitHub Issues: https://github.com/ItsMehRAWRXD/RawrXD/issues
- Support Email: support@rawrxd.local
- Discord: https://discord.gg/rawrxd

### How do I request features?
Submit feature requests via:
- GitHub Discussions
- Discord #feature-requests
- Email: feedback@rawrxd.local

## Getting Help

### Documentation
- Full docs: https://docs.rawrxd.local
- API reference: https://docs.rawrxd.local/api
- Architecture: https://docs.rawrxd.local/architecture

### Community
- Discord: https://discord.gg/rawrxd
- Forum: https://forum.rawrxd.local
- Twitter: @RawrXD_AI

### Support
- Email: support@rawrxd.local
- Status: https://status.rawrxd.local
- Enterprise: enterprise@rawrxd.local

---

**Last Updated**: 2026-07-13  
**Version**: 1.0.0  
**Contributing**: Edit this file on GitHub
