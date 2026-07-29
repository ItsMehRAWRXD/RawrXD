# DigitalOcean Terraform Configuration
# RawrXD Cloud-Hosting: llama.cpp Inference Server

terraform {
  required_version = ">= 1.0"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.28"
    }
  }
}

provider "digitalocean" {
  token = var.do_token
}

# DigitalOcean Spaces Bucket for Model Storage
resource "digitalocean_spaces_bucket" "model_storage" {
  name   = "rawrxd-models"
  region = var.region
  acl    = "private"

  lifecycle_rule {
    enabled = true
    expiration {
      days = 90
    }
    prefix = "archive/"
  }
}

# CDN endpoint for models (conditional — only if cdn_domain is set)
resource "digitalocean_cdn" "models_cdn" {
  count            = var.cdn_domain != "" ? 1 : 0
  origin           = digitalocean_spaces_bucket.model_storage.bucket_domain_name
  custom_domain    = var.cdn_domain
  ttl              = 3600
}

# Droplet for llama.cpp inference
resource "digitalocean_droplet" "llama_server" {
  image    = "docker-20-04"
  name     = "rawrxd-llama-server"
  region   = var.region
  size     = var.droplet_size
  backups  = false
  ipv6     = true
  monitoring = true

  ssh_keys = [var.ssh_fingerprint]

  tags = ["rawrxd", "llama-server"]

  user_data = <<-USERDATA
    #!/bin/bash
    set -euo pipefail
    apt-get update && apt-get install -y docker.io docker-compose
    systemctl enable docker && systemctl start docker
    mkdir -p /opt/models
    echo "Droplet provisioned for llama.cpp inference"
  USERDATA

  lifecycle {
    ignore_changes = [user_data]
  }
}

# Reserved IP for stable endpoint
resource "digitalocean_reserved_ip" "llama_ip" {
  region     = var.region
  droplet_id = digitalocean_droplet.llama_server.id
}

# Firewall
resource "digitalocean_firewall" "llama" {
  name = "rawrxd-llama-fw"

  droplet_ids = [digitalocean_droplet.llama_server.id]

  # SSH (restricted)
  inbound_rule {
    protocol   = "tcp"
    port_range = "22"
    source_addresses = var.allowed_ssh_ips
  }

  # API (port 8080)
  inbound_rule {
    protocol   = "tcp"
    port_range = "8080"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound HTTPS
  outbound_rule {
    protocol              = "tcp"
    port_range            = "443"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound HTTP
  outbound_rule {
    protocol              = "tcp"
    port_range            = "80"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound DNS (TCP)
  outbound_rule {
    protocol              = "tcp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound DNS (UDP)
  outbound_rule {
    protocol              = "udp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}
