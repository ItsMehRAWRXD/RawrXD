output "droplet_ip" {
  description = "Public IP of the inference server"
  value       = digitalocean_reserved_ip.llama_ip.ip_address
}

output "spaces_endpoint" {
  description = "Spaces bucket endpoint for model upload"
  value       = digitalocean_spaces_bucket.model_storage.bucket_domain_name
}

output "api_url" {
  description = "Inference API endpoint"
  value       = "http://${digitalocean_reserved_ip.llama_ip.ip_address}:8080"
}
