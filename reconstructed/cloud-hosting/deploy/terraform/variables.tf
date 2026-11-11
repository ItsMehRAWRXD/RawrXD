variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Deployment region"
  type        = string
  default     = "nyc1"
}

variable "droplet_size" {
  description = "Droplet size slug"
  type        = string
  default     = "s-4vcpu-8gb"
}

variable "ssh_fingerprint" {
  description = "SSH key fingerprint for droplet access"
  type        = string
  sensitive   = true
}

variable "allowed_ssh_ips" {
  description = "CIDR blocks allowed SSH access — NEVER leave as 0.0.0.0/0"
  type        = list(string)
  validation {
    condition     = !contains(var.allowed_ssh_ips, "0.0.0.0/0")
    error_message = "SSH must not be open to 0.0.0.0/0. Specify your IP."
  }
}

variable "model_name" {
  description = "GGUF model filename in Spaces bucket"
  type        = string
  default     = "model.gguf"
}

variable "spaces_access_key" {
  description = "Spaces access key for model storage"
  type        = string
  sensitive   = true
  default     = ""
}

variable "spaces_secret_key" {
  description = "Spaces secret key for model storage"
  type        = string
  sensitive   = true
  default     = ""
}

variable "api_key" {
  description = "API key for llama-server authentication"
  type        = string
  sensitive   = true
  default     = ""
}

variable "cdn_domain" {
  description = "Custom domain for CDN (leave empty to skip CDN)"
  type        = string
  default     = ""
}
