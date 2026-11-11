#!/bin/bash

# DigitalOcean Droplet User Data Script (runs on first boot)
# Installs and starts llama.cpp server with quantized models

set -e

MODELS_BUCKET="${MODELS_BUCKET}"
SPACES_REGION="${SPACES_REGION}"
SPACES_KEY="${SPACES_KEY}"
SPACES_SECRET="${SPACES_SECRET}"

export AWS_ACCESS_KEY_ID="${SPACES_KEY}"
export AWS_SECRET_ACCESS_KEY="${SPACES_SECRET}"

echo "[*] Starting llama.cpp server setup..." >> /var/log/cloud-init-output.log

# Create model directory
mkdir -p /models
cd /models

# Download models from Spaces CDN (global edge cache, TLS auto)
echo "[*] Downloading 2GB quantum models..." >> /var/log/cloud-init-output.log

MODELS_CDN="https://${MODELS_BUCKET}.${SPACES_REGION}.cdn.digitaloceanspaces.com/models"

# Model list - adjust based on your uploaded models
for model in quantum-2b-q4.gguf quantum-3b-q4.gguf quantum-7b-q4.gguf; do
    if wget --timeout=30 --waitretry=5 --tries=3 \
        --show-progress "${MODELS_CDN}/${model}" 2>&1 | tee -a /var/log/cloud-init-output.log; then
        echo "[✓] Downloaded ${model}" >> /var/log/cloud-init-output.log
    else
        echo "[!] Failed to download ${model}" >> /var/log/cloud-init-output.log
    fi
done

# Start llama.cpp server container (Docker already installed in image)
echo "[*] Starting llama.cpp server container..." >> /var/log/cloud-init-output.log

docker pull ghcr.io/ggerganov/llama.cpp:server

# Run with optimal settings for 1 vCPU / 1 GB RAM droplet
docker run -d \
    --name llama-server \
    --restart unless-stopped \
    -p 8080:8080 \
    -v /models:/models \
    -v /var/cache/llama:/root/.cache \
    ghcr.io/ggerganov/llama.cpp:server \
    --host 0.0.0.0 \
    --port 8080 \
    --threads 2 \
    --ctx-size 2048 \
    --batch-size 512 \
    -m /models/quantum-2b-q4.gguf

echo "[✓] llama.cpp server started" >> /var/log/cloud-init-output.log

# Verify server is running
sleep 5
if curl -s http://localhost:8080/health > /dev/null; then
    echo "[✓] Server health check passed" >> /var/log/cloud-init-output.log
else
    echo "[!] Server health check failed - check logs with: docker logs llama-server" >> /var/log/cloud-init-output.log
fi

echo "[✓] Setup complete" >> /var/log/cloud-init-output.log
