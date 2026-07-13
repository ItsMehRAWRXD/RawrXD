#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    RawrXD Deployment Script

.DESCRIPTION
    Automates deployment of RawrXD to various environments including
    Docker, Kubernetes, and cloud platforms.

.EXAMPLE
    .\deploy.ps1 -Environment docker -Action deploy

.EXAMPLE
    .\deploy.ps1 -Environment kubernetes -Action deploy -Namespace production
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet("docker", "kubernetes", "azure", "aws", "gcp")]
    [string]$Environment,

    [Parameter(Mandatory)]
    [ValidateSet("deploy", "update", "rollback", "delete", "status")]
    [string]$Action,

    [Parameter()]
    [string]$Namespace = "rawrxd",

    [Parameter()]
    [string]$Version = "latest",

    [Parameter()]
    [string]$ConfigPath = "config/deployment.env",

    [Parameter()]
    [switch]$Wait,

    [Parameter()]
    [switch]$Force
)

# Configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Load configuration
function Load-Config {
    param([string]$Path)
    
    $config = @{}
    if (Test-Path $Path) {
        Get-Content $Path | ForEach-Object {
            if ($_ -match "^([^#][^=]*)=(.*)$") {
                $config[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
    }
    return $config
}

function Write-Status {
    param([string]$Message, [string]$Status = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    Write-Host "[$Status] " -ForegroundColor $colors[$Status] -NoNewline
    Write-Host $Message
}

function Test-Command {
    param([string]$Command)
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

# Docker deployment functions
function Deploy-Docker {
    Write-Status "Deploying to Docker..." "Info"
    
    $composeFile = "docker/docker-compose.yml"
    
    switch ($Action) {
        "deploy" {
            Write-Status "Building and starting containers..." "Info"
            docker-compose -f $composeFile up -d --build
            
            if ($Wait) {
                Write-Status "Waiting for services to be ready..." "Info"
                Start-Sleep -Seconds 10
                
                # Health check
                $health = docker-compose -f $composeFile ps
                Write-Status "Container status:" "Info"
                $health | ForEach-Object { Write-Host "  $_" }
            }
        }
        "update" {
            Write-Status "Updating containers..." "Info"
            docker-compose -f $composeFile pull
            docker-compose -f $composeFile up -d
        }
        "rollback" {
            Write-Status "Rolling back to previous version..." "Info"
            docker-compose -f $composeFile down
            docker-compose -f $composeFile up -d
        }
        "delete" {
            Write-Status "Removing containers..." "Info"
            docker-compose -f $composeFile down -v
        }
        "status" {
            Write-Status "Container status:" "Info"
            docker-compose -f $composeFile ps
            
            Write-Status "Container logs:" "Info"
            docker-compose -f $composeFile logs --tail=20
        }
    }
}

# Kubernetes deployment functions
function Deploy-Kubernetes {
    Write-Status "Deploying to Kubernetes..." "Info"
    
    if (-not (Test-Command "kubectl")) {
        throw "kubectl not found. Please install kubectl."
    }
    
    # Check cluster connection
    $context = kubectl config current-context 2>$null
    if (-not $context) {
        throw "Not connected to a Kubernetes cluster."
    }
    Write-Status "Using context: $context" "Info"
    
    $k8sDir = "kubernetes"
    
    switch ($Action) {
        "deploy" {
            Write-Status "Creating namespace $Namespace..." "Info"
            kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f -
            
            Write-Status "Applying Kubernetes manifests..." "Info"
            
            # Process templates
            $manifests = Get-ChildItem -Path $k8sDir -Filter "*.yaml" | Sort-Object Name
            foreach ($manifest in $manifests) {
                Write-Status "Applying $($manifest.Name)..." "Info"
                
                # Replace environment variables in template
                $content = Get-Content $manifest.FullName -Raw
                $content = $content -replace '\$\{RAWRXD_REPLICAS\}', $env:RAWRXD_REPLICAS
                $content = $content -replace '\$\{RAWRXD_HOST\}', $env:RAWRXD_HOST
                $content = $content -replace '\$\{RAWRXD_VERSION\}', $Version
                
                # Apply manifest
                $content | kubectl apply -f - -n $Namespace
            }
            
            if ($Wait) {
                Write-Status "Waiting for deployment to be ready..." "Info"
                kubectl wait --for=condition=available --timeout=300s deployment/rawrxd -n $Namespace
                
                Write-Status "Deployment status:" "Info"
                kubectl get pods -n $Namespace
            }
        }
        "update" {
            Write-Status "Updating deployment..." "Info"
            kubectl set image deployment/rawrxd rawrxd=rawrxd/rawrxd:$Version -n $Namespace
            kubectl rollout status deployment/rawrxd -n $Namespace
        }
        "rollback" {
            Write-Status "Rolling back deployment..." "Info"
            kubectl rollout undo deployment/rawrxd -n $Namespace
            kubectl rollout status deployment/rawrxd -n $Namespace
        }
        "delete" {
            if (-not $Force) {
                $confirm = Read-Host "Are you sure you want to delete the deployment? (yes/no)"
                if ($confirm -ne "yes") {
                    Write-Status "Deletion cancelled" "Warning"
                    return
                }
            }
            
            Write-Status "Deleting deployment..." "Info"
            kubectl delete -f $k8sDir -n $Namespace --ignore-not-found
            kubectl delete namespace $Namespace --ignore-not-found
        }
        "status" {
            Write-Status "Deployment status:" "Info"
            kubectl get deployment rawrxd -n $Namespace
            
            Write-Status "Pod status:" "Info"
            kubectl get pods -n $Namespace
            
            Write-Status "Service status:" "Info"
            kubectl get svc -n $Namespace
            
            Write-Status "Ingress status:" "Info"
            kubectl get ingress -n $Namespace
        }
    }
}

# Azure deployment functions
function Deploy-Azure {
    Write-Status "Deploying to Azure..." "Info"
    
    if (-not (Test-Command "az")) {
        throw "Azure CLI not found. Please install Azure CLI."
    }
    
    switch ($Action) {
        "deploy" {
            Write-Status "Deploying to Azure Container Instances..." "Info"
            
            $resourceGroup = $env:AZURE_RESOURCE_GROUP
            $location = $env:AZURE_LOCATION
            
            # Create resource group if it doesn't exist
            az group create --name $resourceGroup --location $location --output none
            
            # Deploy container
            az container create `
                --resource-group $resourceGroup `
                --name rawrxd `
                --image rawrxd/rawrxd:$Version `
                --ports 8080 9090 `
                --cpu 4 `
                --memory 8 `
                --location $location `
                --output none
            
            Write-Status "Deployment complete" "Success"
        }
        "update" {
            Write-Status "Updating Azure container..." "Info"
            
            $resourceGroup = $env:AZURE_RESOURCE_GROUP
            
            az container delete --resource-group $resourceGroup --name rawrxd --yes
            Deploy-Azure
        }
        "delete" {
            $resourceGroup = $env:AZURE_RESOURCE_GROUP
            az container delete --resource-group $resourceGroup --name rawrxd --yes
        }
        "status" {
            $resourceGroup = $env:AZURE_RESOURCE_GROUP
            az container show --resource-group $resourceGroup --name rawrxd
        }
    }
}

# AWS deployment functions
function Deploy-AWS {
    Write-Status "Deploying to AWS..." "Info"
    
    if (-not (Test-Command "aws")) {
        throw "AWS CLI not found. Please install AWS CLI."
    }
    
    switch ($Action) {
        "deploy" {
            Write-Status "Deploying to AWS ECS..." "Info"
            
            # This would integrate with ECS or EKS
            # Simplified example
            Write-Status "AWS deployment would use ECS or EKS" "Warning"
        }
        "status" {
            aws ecs list-services --cluster rawrxd
        }
    }
}

# GCP deployment functions
function Deploy-GCP {
    Write-Status "Deploying to GCP..." "Info"
    
    if (-not (Test-Command "gcloud")) {
        throw "Google Cloud SDK not found. Please install gcloud."
    }
    
    switch ($Action) {
        "deploy" {
            Write-Status "Deploying to Google Cloud Run..." "Info"
            
            $project = $env:GCP_PROJECT
            $region = $env:GCP_REGION
            
            gcloud run deploy rawrxd `
                --image rawrxd/rawrxd:$Version `
                --platform managed `
                --region $region `
                --project $project `
                --allow-unauthenticated `
                --memory 8Gi `
                --cpu 4 `
                --concurrency 100
            
            Write-Status "Deployment complete" "Success"
        }
        "status" {
            gcloud run services describe rawrxd --region $env:GCP_REGION
        }
    }
}

# Main execution
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Deployment Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Load configuration
$config = Load-Config -Path $ConfigPath
foreach ($key in $config.Keys) {
    if (-not (Get-Item Env:$key -ErrorAction SilentlyContinue)) {
        Set-Item Env:$key $config[$key]
    }
}

# Execute deployment
switch ($Environment) {
    "docker" { Deploy-Docker }
    "kubernetes" { Deploy-Kubernetes }
    "azure" { Deploy-Azure }
    "aws" { Deploy-AWS }
    "gcp" { Deploy-GCP }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Deployment $Action completed" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
