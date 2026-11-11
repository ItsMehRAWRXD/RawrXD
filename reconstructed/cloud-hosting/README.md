# RawrXD Quantum Models - Cloud + Local + Offline

Deploy quantum GGUF models to the cloud **OR** run them completely offline on your local machine!

## ⚡ Quick Start - Choose Your Path

### 🚀 Super Quick Start (Recommended!)
**The Absolute Easiest!** - One command to install, download models, and launch everything:

```bash
./quick-start.sh
```

Opens Web UI at **http://localhost:8081** automatically! 🎉

📖 **Quick Guide:** [QUICKSTART.md](QUICKSTART.md)

---

### 🏠 Local/Offline (Best for Personal Use)
**The Absolute Bestest!** - Run AI models on your own machine, completely offline, 100% private!

```bash
# Linux/macOS - One command install
./install-local.sh

# Windows - Double-click or run
.\install-local.bat

# Start server
rawrxd-serve

# Or start everything (server + UI)
./quick-start.sh
```

✨ **Benefits:**
- ✅ **FREE** - No monthly costs
- ✅ **PRIVATE** - Nothing leaves your machine
- ✅ **OFFLINE** - Works without internet
- ✅ **FAST** - Sub-10ms latency
- ✅ **UNLIMITED** - No API limits

📖 **Full Guide:** [OFFLINE_SETUP.md](OFFLINE_SETUP.md)

---

### ☁️ Cloud Deployment (For Production/Sharing)

**Cost: \/month | Free tier: 18 months on \ credit**

1. **Create DigitalOcean account** → https://digitalocean.com
2. **Grab \ credit** (60 days) or enable billing
3. **Generate API token** → Account → API → Tokens
4. **Fork this repo** → Your GitHub account
5. **Deploy:**
   - Option A: App Platform (easiest) → See .do/app.yaml
   - Option B: Terraform → See deploy/terraform/
   - Option C: Manual SSH → See deploy/scripts/

## Deployment Options

### Option A: DigitalOcean App Platform (Recommended)

1. Go to https://cloud.digitalocean.com/apps
2. Create App → GitHub
3. Select this repository
4. DigitalOcean auto-detects .do/app.yaml
5. Deploy

Automatic CI/CD: Every push to main triggers deployment.

### Option B: Terraform

`ash
cd deploy/terraform
terraform init
terraform apply
`

### Option C: Manual SSH

`ash
bash deploy/scripts/deploy-to-digitalocean.sh <droplet-ip>
`

## Architecture

`
Spaces (S3 CDN)    Droplet (API Server)
    \/mo              \/mo
   250GB              1 vCPU
  1TB free           1 GB RAM
   egress
    │                    │
    └────┬───────────────┘
         │
    llama.cpp server
    2GB quantum models
    Port 8080
`

## API Usage

`ash
# Health check
curl http://<droplet-ip>:8080/health

# Completion
curl -X POST http://<droplet-ip>:8080/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello", "n_predict": 128}'

# Full API docs
http://<droplet-ip>:8080/docs
`

## Cost

### Cloud Deployment Costs
| Component | Cost | Details |
|-----------|------|---------|
| Spaces | \/mo | 250 GB included, 1 TB egress free, CDN auto |
| Droplet | \/mo | 1 vCPU, 1 GB RAM, 25 GB SSD, no backups |
| **Total** | **\/mo** | **18 months free on \ credit** |

### Local/Offline Costs
| Component | Cost | Details |
|-----------|------|---------|
| Hardware | $0 (use existing) | Your computer |
| Software | **$0** | 100% Free & Open Source |
| Models | **$0** | Free from HuggingFace |
| Bandwidth | **$0** | No internet needed |
| **Total** | **$0/month** | **Forever Free!** |

---

## Documentation

### Local/Offline Setup
- **Offline Setup Guide:** [OFFLINE_SETUP.md](OFFLINE_SETUP.md) ⭐ **Start Here!**
- **Install Scripts:** `install-local.sh` (Linux/macOS) or `install-local.bat` (Windows)
- **Model Manager:** `model-manager.sh` - Download and manage models offline

### Cloud Deployment
- Full setup guide: [deploy/README-CLOUD-HOSTING.md](deploy/README-CLOUD-HOSTING.md)
- Deployment scripts: [deploy/scripts/](deploy/scripts/)
- Terraform configs: [deploy/terraform/](deploy/terraform/)
- Docker image: [deploy/docker/](deploy/docker/)
- App config: [.do/app.yaml](.do/app.yaml)
- CI/CD workflow: [.github/workflows/deploy-digitalocean.yml](.github/workflows/deploy-digitalocean.yml)

## GitHub Actions Setup

When you push to main, GitHub Actions automatically:
1. Build Docker image with llama.cpp server
2. Push to GitHub Container Registry (GHCR)
3. Deploy to DigitalOcean App Platform

**Required GitHub Secrets:**
- \DIGITALOCEAN_ACCESS_TOKEN\ (Get from DigitalOcean Account → API)

Settings → Secrets and variables → Actions → New repository secret

## Local Development

Test locally before deploying:

`ash
bash deploy/scripts/local-dev-setup.sh

# Test API
curl http://localhost:8080/health

# View logs
docker-compose -f deploy/docker/docker-compose.yml logs -f

# Stop
docker-compose -f deploy/docker/docker-compose.yml down
`

## Upload Models to Spaces

`ash
export DO_SPACES_KEY="your_key"
export DO_SPACES_SECRET="your_secret"
export DIGITALOCEAN_TOKEN="your_token"

bash deploy/scripts/upload-to-spaces.sh
`

## Scaling

| Setup | Droplets | RAM | Cost/mo |
|-------|----------|-----|---------|
| Dev | 1 | 1 GB | \ |
| Prod | 5 | 1 GB | \ |
| 70B models | 1 | 32 GB | \ |

## Links

- DigitalOcean: https://digitalocean.com
- llama.cpp: https://github.com/ggerganov/llama.cpp
- Terraform: https://terraform.io

## License

MIT
