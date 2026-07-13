# Phase D.4 Batch 3/5: Terraform Infrastructure
# Sovereign Cluster Infrastructure Module
# Copyright (c) 2026 RawrXD Team

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# ============================================================================
# Data Sources
# ============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# Get latest EKS optimized AMI
data "aws_ami" "eks_optimized" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.kubernetes_version}-v*"]
  }
}

# ============================================================================
# VPC and Networking
# ============================================================================

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "${var.cluster_name}-vpc"
  cidr = var.vpc_cidr
  
  azs             = slice(data.aws_availability_zones.available.names, 0, var.availability_zone_count)
  private_subnets = [for i in range(var.availability_zone_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  public_subnets  = [for i in range(var.availability_zone_count) : cidrsubnet(var.vpc_cidr, 8, i + 100)]
  
  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true
  enable_dns_hostnames   = true
  enable_dns_support     = true
  
  # Tags for Kubernetes load balancer discovery
  public_subnet_tags = {
    "kubernetes.io/role/elb"                      = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
  
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb"             = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
  
  tags = merge(var.tags, {
    Name = "${var.cluster_name}-vpc"
  })
}

# ============================================================================
# EKS Cluster
# ============================================================================

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"
  
  cluster_name    = var.cluster_name
  cluster_version = var.kubernetes_version
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  # Control plane logging
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  # Public endpoint access (restrict in production)
  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true
  
  cluster_endpoint_public_access_cidrs = var.allowed_cidr_blocks
  
  # Security groups
  cluster_security_group_additional_rules = {
    ingress_nodes_ephemeral_ports_tcp = {
      description                = "Nodes on ephemeral ports"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "ingress"
      source_node_security_group = true
    }
  }
  
  # Managed node groups
  eks_managed_node_groups = {
    sovereign_nodes = {
      name           = "sovereign-node-group"
      instance_types = var.node_instance_types
      
      min_size     = var.node_group_min_size
      max_size     = var.node_group_max_size
      desired_size = var.node_group_desired_size
      
      capacity_type = var.node_capacity_type
      
      ami_type       = "AL2_x86_64"
      ami_id         = data.aws_ami.eks_optimized.id
      
      labels = {
        "node-type" = "sovereign"
        "sovereign.rawrxd.io/node-group" = "primary"
      }
      
      taints = [{
        key    = "dedicated"
        value  = "sovereign"
        effect = "NO_SCHEDULE"
      }]
      
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 100
            volume_type           = "gp3"
            iops                  = 3000
            throughput            = 125
            encrypted             = true
            kms_key_id            = aws_kms_key.eks.arn
            delete_on_termination = true
          }
        }
      }
      
      tags = merge(var.tags, {
        Name = "${var.cluster_name}-sovereign-node"
      })
    }
  }
  
  # Fargate profiles (optional)
  fargate_profiles = var.enable_fargate ? {
    kube_system = {
      name = "kube-system"
      selectors = [
        { namespace = "kube-system" }
      ]
    }
    sovereign = {
      name = "sovereign"
      selectors = [
        { 
          namespace = "sovereign"
          labels = {
            "compute-type" = "fargate"
          }
        }
      ]
      subnets = module.vpc.private_subnets
    }
  } : {}
  
  # AWS Auth config map
  manage_aws_auth_configmap = true
  aws_auth_roles = [
    {
      rolearn  = aws_iam_role.admin.arn
      username = "admin"
      groups   = ["system:masters"]
    }
  ]
  
  tags = var.tags
}

# ============================================================================
# KMS Key for Encryption
# ============================================================================

resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key for ${var.cluster_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = merge(var.tags, {
    Name = "${var.cluster_name}-eks-encryption"
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# ============================================================================
# IAM Roles
# ============================================================================

resource "aws_iam_role" "admin" {
  name = "${var.cluster_name}-admin-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    ]
  })
  
  tags = var.tags
}

# Sovereign node IAM role
resource "aws_iam_role" "sovereign_node" {
  name = "${var.cluster_name}-sovereign-node-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = var.tags
}

resource "aws_iam_role_policy" "sovereign_node" {
  name = "${var.cluster_name}-sovereign-node-policy"
  role = aws_iam_role.sovereign_node.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.checkpoints.arn,
          "${aws_s3_bucket.checkpoints.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.eks.arn
      }
    ]
  })
}

# ============================================================================
# S3 Bucket for Checkpoints
# ============================================================================

resource "aws_s3_bucket" "checkpoints" {
  bucket = "${var.cluster_name}-sovereign-checkpoints-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(var.tags, {
    Name = "${var.cluster_name}-checkpoints"
  })
}

resource "aws_s3_bucket_versioning" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.eks.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "checkpoints" {
  bucket = aws_s3_bucket.checkpoints.id
  
  rule {
    id     = "expire-old-checkpoints"
    status = "Enabled"
    
    expiration {
      days = 30
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# ============================================================================
# Security Groups
# ============================================================================

resource "aws_security_group" "sovereign_nodes" {
  name_prefix = "${var.cluster_name}-sovereign-"
  description = "Security group for Sovereign nodes"
  vpc_id      = module.vpc.vpc_id
  
  ingress {
    description = "Sovereign HTTP API"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  ingress {
    description = "Sovereign Discovery"
    from_port   = 7946
    to_port     = 7946
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  ingress {
    description = "Sovereign Metrics"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(var.tags, {
    Name = "${var.cluster_name}-sovereign-nodes"
  })
}

# ============================================================================
# CloudWatch Log Group
# ============================================================================

resource "aws_cloudwatch_log_group" "sovereign" {
  name              = "/aws/eks/${var.cluster_name}/sovereign"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.eks.arn
  
  tags = var.tags
}

# ============================================================================
# Outputs
# ============================================================================

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = module.eks.cluster_endpoint
}

output "cluster_certificate_authority_data" {
  description = "EKS cluster CA certificate"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS control plane"
  value       = module.eks.cluster_security_group_id
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.vpc.private_subnets
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.vpc.public_subnets
}

output "s3_checkpoint_bucket" {
  description = "S3 bucket for checkpoints"
  value       = aws_s3_bucket.checkpoints.id
}

output "kms_key_arn" {
  description = "KMS key ARN for encryption"
  value       = aws_kms_key.eks.arn
}
