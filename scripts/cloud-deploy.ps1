# RawrXD Cloud Deployment Script
# Deploys RawrXD to cloud providers (AWS, Azure, GCP)

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("AWS", "Azure", "GCP", "Kubernetes", "Docker")]
    [string]$Provider = "Docker",
    
    [string]$Environment = "staging",
    [string]$Region = "us-east-1",
    [string]$InstanceType = "",
    [switch]$DryRun,
    [switch]$AutoApprove,
    [string]$ConfigFile = "cloud-config.json"
)

$ErrorActionPreference = "Stop"

# Cloud provider configurations
$CloudConfig = @{
    AWS = @{
        Regions = @("us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1")
        InstanceTypes = @("t3.medium", "t3.large", "t3.xlarge", "g4dn.xlarge", "g4dn.2xlarge")
        AMIs = @{
            "us-east-1" = "ami-0c55b159cbfafe1f0"
            "us-west-2" = "ami-0c55b159cbfafe1f0"
        }
    }
    Azure = @{
        Regions = @("eastus", "westus2", "westeurope", "southeastasia")
        InstanceTypes = @("Standard_D4s_v3", "Standard_D8s_v3", "Standard_NC6s_v3", "Standard_NC12s_v3")
    }
    GCP = @{
        Regions = @("us-central1", "us-west1", "europe-west1", "asia-southeast1")
        InstanceTypes = @("n1-standard-4", "n1-standard-8", "n1-highmem-4", "n1-highmem-8")
    }
}

$script:DeploymentId = "rawrxd-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$script:Results = @{
    Timestamp = Get-Date -Format "o"
    Provider = $Provider
    Environment = $Environment
    Region = $Region
    Status = "Pending"
    Resources = @()
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-Deployment {
    Write-Status "Initializing cloud deployment..."
    Write-Status "Provider: $Provider"
    Write-Status "Environment: $Environment"
    Write-Status "Region: $Region"
    
    if ($DryRun) {
        Write-Warning "DRY RUN MODE - No actual resources will be created"
    }
    
    # Check for required tools
    switch ($Provider) {
        "AWS" {
            $aws = Get-Command aws -ErrorAction SilentlyContinue
            if (-not $aws) {
                Write-Error "AWS CLI not found. Please install: https://aws.amazon.com/cli/"
                exit 1
            }
        }
        "Azure" {
            $az = Get-Command az -ErrorAction SilentlyContinue
            if (-not $az) {
                Write-Error "Azure CLI not found. Please install: https://docs.microsoft.com/cli/azure/install-azure-cli"
                exit 1
            }
        }
        "GCP" {
            $gcloud = Get-Command gcloud -ErrorAction SilentlyContinue
            if (-not $gcloud) {
                Write-Error "Google Cloud SDK not found. Please install: https://cloud.google.com/sdk/docs/install"
                exit 1
            }
        }
        "Kubernetes" {
            $kubectl = Get-Command kubectl -ErrorAction SilentlyContinue
            if (-not $kubectl) {
                Write-Error "kubectl not found. Please install: https://kubernetes.io/docs/tasks/tools/"
                exit 1
            }
        }
    }
    
    Write-Success "Prerequisites verified"
}

function Deploy-AWS {
    Write-Status "Deploying to AWS..."
    
    $stackName = "rawrxd-$Environment"
    $templateFile = "cloudformation/rawrxd-template.yaml"
    
    if (-not (Test-Path $templateFile)) {
        Write-Warning "CloudFormation template not found. Using default configuration..."
        $templateFile = Create-DefaultCloudFormationTemplate
    }
    
    $parameters = @(
        "ParameterKey=Environment,ParameterValue=$Environment",
        "ParameterKey=InstanceType,ParameterValue=$InstanceType",
        "ParameterKey=DeploymentId,ParameterValue=$script:DeploymentId"
    )
    
    if (-not $DryRun) {
        # Check if stack exists
        $stack = aws cloudformation describe-stacks --stack-name $stackName --region $Region 2>$null | ConvertFrom-Json
        
        if ($stack) {
            Write-Status "Updating existing stack..."
            aws cloudformation update-stack `
                --stack-name $stackName `
                --template-body file://$templateFile `
                --parameters $parameters `
                --region $Region `
                --capabilities CAPABILITY_IAM
        } else {
            Write-Status "Creating new stack..."
            aws cloudformation create-stack `
                --stack-name $stackName `
                --template-body file://$templateFile `
                --parameters $parameters `
                --region $Region `
                --capabilities CAPABILITY_IAM
        }
        
        Write-Status "Waiting for stack to complete..."
        aws cloudformation wait stack-create-complete --stack-name $stackName --region $Region
        
        # Get outputs
        $outputs = aws cloudformation describe-stacks --stack-name $stackName --region $Region | ConvertFrom-Json
        $script:Results.Resources = $outputs.Stacks[0].Outputs
    } else {
        Write-Status "Would deploy CloudFormation stack: $stackName"
        Write-Status "Parameters: $($parameters -join ', ')"
    }
    
    Write-Success "AWS deployment complete"
}

function Deploy-Azure {
    Write-Status "Deploying to Azure..."
    
    $resourceGroup = "rawrxd-$Environment-rg"
    $deploymentName = "rawrxd-$script:DeploymentId"
    $templateFile = "arm-templates/rawrxd-template.json"
    
    if (-not (Test-Path $templateFile)) {
        Write-Warning "ARM template not found. Using default configuration..."
        $templateFile = Create-DefaultARMTemplate
    }
    
    if (-not $DryRun) {
        # Create resource group if not exists
        $rg = az group show --name $resourceGroup 2>$null | ConvertFrom-Json
        if (-not $rg) {
            Write-Status "Creating resource group..."
            az group create --name $resourceGroup --location $Region
        }
        
        # Deploy template
        Write-Status "Deploying ARM template..."
        $deployment = az deployment group create `
            --resource-group $resourceGroup `
            --name $deploymentName `
            --template-file $templateFile `
            --parameters environment=$Environment instanceType=$InstanceType `
            --query properties.outputs | ConvertFrom-Json
        
        $script:Results.Resources = $deployment
    } else {
        Write-Status "Would deploy to resource group: $resourceGroup"
        Write-Status "Template: $templateFile"
    }
    
    Write-Success "Azure deployment complete"
}

function Deploy-GCP {
    Write-Status "Deploying to GCP..."
    
    $projectId = gcloud config get-value project 2>$null
    $deploymentName = "rawrxd-$Environment"
    
    if (-not $DryRun) {
        # Deploy using Deployment Manager
        Write-Status "Creating deployment..."
        gcloud deployment-manager deployments create $deploymentName `
            --config cloud-deployment.yaml `
            --properties environment=$Environment,region=$Region
        
        # Get deployment info
        $deployment = gcloud deployment-manager deployments describe $deploymentName --format json | ConvertFrom-Json
        $script:Results.Resources = $deployment
    } else {
        Write-Status "Would deploy to project: $projectId"
        Write-Status "Deployment name: $deploymentName"
    }
    
    Write-Success "GCP deployment complete"
}

function Deploy-Kubernetes {
    Write-Status "Deploying to Kubernetes..."
    
    $namespace = "rawrxd-$Environment"
    $manifestFile = "k8s/rawrxd-deployment.yaml"
    
    if (-not (Test-Path $manifestFile)) {
        Write-Warning "K8s manifest not found. Using default configuration..."
        $manifestFile = Create-DefaultK8sManifest
    }
    
    if (-not $DryRun) {
        # Create namespace
        kubectl create namespace $namespace --dry-run=client -o yaml | kubectl apply -f -
        
        # Apply manifests
        Write-Status "Applying Kubernetes manifests..."
        kubectl apply -f $manifestFile -n $namespace
        
        # Wait for deployment
        Write-Status "Waiting for deployment to be ready..."
        kubectl wait --for=condition=available --timeout=300s deployment/rawrxd -n $namespace
        
        # Get service info
        $service = kubectl get service rawrxd -n $namespace -o json | ConvertFrom-Json
        $script:Results.Resources = @{
            Namespace = $namespace
            ServiceIP = $service.status.loadBalancer.ingress[0].ip
            Port = $service.spec.ports[0].port
        }
    } else {
        Write-Status "Would deploy to namespace: $namespace"
        Write-Status "Manifest: $manifestFile"
    }
    
    Write-Success "Kubernetes deployment complete"
}

function Deploy-Docker {
    Write-Status "Deploying with Docker Compose..."
    
    $composeFile = "docker-compose.$Environment.yml"
    if (-not (Test-Path $composeFile)) {
        $composeFile = "docker-compose.yml"
    }
    
    if (-not $DryRun) {
        # Pull latest images
        Write-Status "Pulling latest images..."
        docker-compose -f $composeFile pull
        
        # Deploy
        Write-Status "Starting services..."
        docker-compose -f $composeFile up -d
        
        # Health check
        Write-Status "Performing health check..."
        Start-Sleep -Seconds 10
        $health = docker-compose -f $composeFile ps
        $script:Results.Resources = @{ Status = $health }
    } else {
        Write-Status "Would deploy using: $composeFile"
    }
    
    Write-Success "Docker deployment complete"
}

function Create-DefaultCloudFormationTemplate {
    $template = @"
AWSTemplateFormatVersion: '2010-09-09'
Description: RawrXD Deployment

Parameters:
  Environment:
    Type: String
    Default: staging
  InstanceType:
    Type: String
    Default: t3.large
  DeploymentId:
    Type: String

Resources:
  RawrXDInstance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: !Ref InstanceType
      ImageId: ami-0c55b159cbfafe1f0
      Tags:
        - Key: Name
          Value: !Sub 'rawrxd-\${Environment}'
        - Key: DeploymentId
          Value: !Ref DeploymentId
      UserData:
        Fn::Base64: |
          #!/bin/bash
          yum update -y
          yum install -y docker
          service docker start
          docker run -d -p 8080:8080 rawrxd/rawrxd:latest

Outputs:
  InstanceId:
    Description: EC2 Instance ID
    Value: !Ref RawrXDInstance
  PublicIP:
    Description: Public IP Address
    Value: !GetAtt RawrXDInstance.PublicIp
"@
    
    $tempFile = "$env:TEMP\rawrxd-cf-template.yaml"
    $template | Out-File $tempFile
    return $tempFile
}

function Create-DefaultARMTemplate {
    $template = @"
{
    "`$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "environment": { "type": "string" },
        "instanceType": { "type": "string", "defaultValue": "Standard_D4s_v3" }
    },
    "resources": [
        {
            "type": "Microsoft.Compute/virtualMachines",
            "apiVersion": "2020-06-01",
            "name": "[concat('rawrxd-', parameters('environment'))]",
            "location": "[resourceGroup().location]",
            "properties": {
                "hardwareProfile": { "vmSize": "[parameters('instanceType')]" },
                "osProfile": {
                    "computerName": "[concat('rawrxd-', parameters('environment'))]",
                    "adminUsername": "rawrxdadmin"
                },
                "storageProfile": {
                    "imageReference": {
                        "publisher": "Canonical",
                        "offer": "UbuntuServer",
                        "sku": "18.04-LTS",
                        "version": "latest"
                    }
                }
            }
        }
    ],
    "outputs": {
        "vmId": {
            "type": "string",
            "value": "[resourceId('Microsoft.Compute/virtualMachines', concat('rawrxd-', parameters('environment')))]"
        }
    }
}
"@
    
    $tempFile = "$env:TEMP\rawrxd-arm-template.json"
    $template | Out-File $tempFile
    return $tempFile
}

function Create-DefaultK8sManifest {
    $manifest = @"
apiVersion: v1
kind: Service
metadata:
  name: rawrxd
spec:
  selector:
    app: rawrxd
  ports:
    - port: 8080
      targetPort: 8080
  type: LoadBalancer
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rawrxd
spec:
  replicas: 1
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
          image: rawrxd/rawrxd:latest
          ports:
            - containerPort: 8080
"@
    
    $tempFile = "$env:TEMP\rawrxd-k8s-manifest.yaml"
    $manifest | Out-File $tempFile
    return $tempFile
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Deployment Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Provider: $Provider" -ForegroundColor White
    Write-Host "Environment: $Environment" -ForegroundColor White
    Write-Host "Region: $Region" -ForegroundColor White
    Write-Host "Deployment ID: $script:DeploymentId" -ForegroundColor White
    Write-Host ""
    
    if ($script:Results.Resources.Count -gt 0) {
        Write-Host "Resources:" -ForegroundColor White
        $script:Results.Resources | ConvertTo-Json -Depth 3 | Write-Host
    }
    
    if ($DryRun) {
        Write-Warning "This was a dry run. No resources were actually created."
    } else {
        Write-Success "Deployment complete!"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Cloud Deployment" -ForegroundColor Cyan
    Write-Host "=======================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Deployment
    
    switch ($Provider) {
        "AWS" { Deploy-AWS }
        "Azure" { Deploy-Azure }
        "GCP" { Deploy-GCP }
        "Kubernetes" { Deploy-Kubernetes }
        "Docker" { Deploy-Docker }
    }
    
    Show-Summary
}

Main
