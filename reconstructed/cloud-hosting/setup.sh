#!/usr/bin/env bash
set -euo pipefail

echo "=== RawrXD Cloud-Hosting Setup ==="

# Check prerequisites
for cmd in docker docker-compose terraform; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "[WARN] $cmd not found — install it for full functionality"
    else
        echo "[OK] $cmd $(${cmd} --version 2>&1 | head -1)"
    fi
done

# Create local env file if missing
if [ ! -f .env ]; then
    cat > .env <<'EOF'
# RawrXD Cloud Hosting Configuration
LLAMA_MODEL_PATH=/models/your-model.gguf
LLAMA_PORT=8080
LLAMA_THREADS=4
LLAMA_GPU_LAYERS=99
LLAMA_CONTEXT_SIZE=4096
API_KEY=changeme
EOF
    echo "[OK] Created .env — edit it with your settings"
fi

# Create terraform.tfvars.example if missing
if [ ! -f deploy/terraform/terraform.tfvars.example ]; then
    cat > deploy/terraform/terraform.tfvars.example <<'EOF'
do_token         = "your-digitalocean-api-token"
ssh_fingerprint  = "your:ssh:key:fingerprint"
allowed_ssh_ips  = ["YOUR.IP.ADDR.HERE/32"]
cdn_domain       = ""
EOF
    echo "[OK] Created terraform.tfvars.example"
fi

echo ""
echo "Next steps:"
echo "  1. Edit .env with your model path and API key"
echo "  2. cd deploy/docker && docker-compose up -d"
echo "  3. curl http://localhost:8080/health"
