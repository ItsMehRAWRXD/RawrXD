# Cloud-Hosting Copilot Instructions

## Project
This repo deploys a llama.cpp inference server to DigitalOcean using Docker + Terraform.

## Architecture
- `deploy/docker/` — Dockerfile and docker-compose for local dev
- `deploy/terraform/` — Infrastructure as Code for DigitalOcean
- `deploy/scripts/` — Shell scripts for manual deployment
- `.github/workflows/` — CI/CD pipeline

## Conventions
- All infrastructure changes must go through Terraform — no manual droplet config
- Docker images are pushed to GHCR
- Models are stored in DO Spaces (private bucket)
- API must always require authentication
- SSH access must be restricted to specific IPs
