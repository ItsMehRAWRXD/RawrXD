#!/bin/bash

# RawrXD Quantum Models - Offline Model Manager
# Download and manage GGUF models for offline use

set -e

MODELS_DIR="${HOME}/.local/share/rawrxd/models"
CACHE_DIR="${HOME}/.local/share/rawrxd/cache"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Model catalog with direct download links
declare -A MODELS=(
    # Small models (< 2GB)
    ["phi-2-q4"]="https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_K_M.gguf|1.6GB|Phi-2 2.7B Q4_K_M"
    ["tinyllama-q4"]="https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf|669MB|TinyLlama 1.1B Q4"
    
    # Medium models (2-5GB)
    ["mistral-7b-q4"]="https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf|4.4GB|Mistral 7B Instruct Q4"
    ["llama2-7b-q4"]="https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.Q4_K_M.gguf|4.1GB|Llama 2 7B Chat Q4"
    
    # Large models (5GB+)
    ["mixtral-8x7b-q4"]="https://huggingface.co/TheBloke/Mixtral-8x7B-Instruct-v0.1-GGUF/resolve/main/mixtral-8x7b-instruct-v0.1.Q4_K_M.gguf|26GB|Mixtral 8x7B Q4"
    ["llama2-13b-q4"]="https://huggingface.co/TheBloke/Llama-2-13B-chat-GGUF/resolve/main/llama-2-13b-chat.Q4_K_M.gguf|7.4GB|Llama 2 13B Chat Q4"
)

print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  RawrXD Quantum Models - Offline Model Manager            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# List available models
list_models() {
    print_header
    echo -e "${BLUE}Available Models for Download:${NC}"
    echo ""
    
    echo "ID                  | Size   | Description"
    echo "--------------------+--------+------------------------------------------"
    for key in "${!MODELS[@]}"; do
        IFS='|' read -r url size desc <<< "${MODELS[$key]}"
        printf "%-19s | %-6s | %s\n" "$key" "$size" "$desc"
    done | sort
    
    echo ""
    echo -e "${BLUE}Currently Installed Models:${NC}"
    echo ""
    
    if [ -d "$MODELS_DIR" ] && [ "$(ls -A $MODELS_DIR/*.gguf 2>/dev/null | wc -l)" -gt 0 ]; then
        for model in "$MODELS_DIR"/*.gguf; do
            size=$(du -h "$model" | cut -f1)
            echo "  - $(basename "$model") ($size)"
        done
    else
        print_warning "No models installed yet"
    fi
    
    echo ""
}

# Download a specific model
download_model() {
    local model_id="$1"
    
    if [ -z "$model_id" ]; then
        print_error "Please specify a model ID"
        echo "Usage: $0 download <model-id>"
        echo "Run '$0 list' to see available models"
        exit 1
    fi
    
    if [ -z "${MODELS[$model_id]}" ]; then
        print_error "Unknown model ID: $model_id"
        echo "Run '$0 list' to see available models"
        exit 1
    fi
    
    IFS='|' read -r url size desc <<< "${MODELS[$model_id]}"
    
    print_header
    echo -e "${BLUE}Downloading: ${desc}${NC}"
    echo -e "${BLUE}Size: ${size}${NC}"
    echo ""
    
    # Extract filename from URL
    filename=$(basename "$url")
    output_path="${MODELS_DIR}/${filename}"
    
    # Check if already downloaded
    if [ -f "$output_path" ]; then
        print_warning "Model already exists: $output_path"
        read -p "Re-download? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Skipping download"
            return
        fi
        rm -f "$output_path"
    fi
    
    # Ensure directory exists
    mkdir -p "$MODELS_DIR"
    
    # Download with progress
    print_info "Downloading to: $output_path"
    print_info "This may take a while depending on your connection..."
    echo ""
    
    if command -v wget &> /dev/null; then
        wget -O "$output_path" "$url" --progress=bar:force 2>&1 | \
            grep --line-buffered "%" | \
            sed -u -e "s,\.,,g" | \
            awk '{printf("\r  Progress: %4s", $2); fflush()}'
        echo ""
    elif command -v curl &> /dev/null; then
        curl -L -o "$output_path" "$url" --progress-bar
    else
        print_error "Neither wget nor curl found. Please install one of them."
        exit 1
    fi
    
    # Verify download
    if [ -f "$output_path" ]; then
        actual_size=$(du -h "$output_path" | cut -f1)
        print_status "Download complete!"
        print_info "Saved to: $output_path"
        print_info "Size: $actual_size"
        echo ""
        print_info "You can now use this model with: rawrxd-serve"
    else
        print_error "Download failed"
        exit 1
    fi
}

# Remove a model
remove_model() {
    local model_file="$1"
    
    if [ -z "$model_file" ]; then
        print_error "Please specify a model file"
        echo "Usage: $0 remove <model-filename>"
        exit 1
    fi
    
    local full_path="${MODELS_DIR}/${model_file}"
    
    if [ ! -f "$full_path" ]; then
        print_error "Model not found: $full_path"
        exit 1
    fi
    
    print_warning "About to delete: $full_path"
    read -p "Are you sure? [y/N]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f "$full_path"
        print_status "Model removed"
    else
        print_info "Cancelled"
    fi
}

# Show disk usage
show_usage() {
    print_header
    echo -e "${BLUE}Disk Usage:${NC}"
    echo ""
    
    if [ -d "$MODELS_DIR" ]; then
        echo "Models directory: $MODELS_DIR"
        du -sh "$MODELS_DIR" 2>/dev/null || echo "0 bytes"
        echo ""
        
        if [ "$(ls -A $MODELS_DIR/*.gguf 2>/dev/null | wc -l)" -gt 0 ]; then
            echo "Individual models:"
            for model in "$MODELS_DIR"/*.gguf; do
                size=$(du -h "$model" | cut -f1)
                echo "  - $(basename "$model"): $size"
            done
        fi
    else
        print_warning "Models directory not found"
    fi
    
    echo ""
}

# Verify model integrity (basic check)
verify_model() {
    local model_file="$1"
    
    if [ -z "$model_file" ]; then
        print_error "Please specify a model file"
        echo "Usage: $0 verify <model-filename>"
        exit 1
    fi
    
    local full_path="${MODELS_DIR}/${model_file}"
    
    if [ ! -f "$full_path" ]; then
        print_error "Model not found: $full_path"
        exit 1
    fi
    
    print_info "Verifying: $model_file"
    
    # Check file size
    size=$(stat -f%z "$full_path" 2>/dev/null || stat -c%s "$full_path" 2>/dev/null)
    if [ "$size" -lt 1000000 ]; then
        print_error "File is too small ($(du -h "$full_path" | cut -f1)). May be corrupted."
        exit 1
    fi
    
    # Check if it's a valid GGUF file (starts with GGUF magic)
    if command -v xxd &> /dev/null; then
        magic=$(xxd -p -l 4 "$full_path")
        if [ "$magic" = "47475546" ] || [ "$magic" = "46554747" ]; then
            print_status "Valid GGUF format detected"
        else
            print_warning "File may not be a valid GGUF file"
        fi
    fi
    
    print_status "Model appears valid ($(du -h "$full_path" | cut -f1))"
}

# Show help
show_help() {
    print_header
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  list                  - Show available and installed models"
    echo "  download <model-id>   - Download a model from catalog"
    echo "  remove <filename>     - Remove an installed model"
    echo "  usage                 - Show disk usage"
    echo "  verify <filename>     - Verify model integrity"
    echo "  help                  - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 list"
    echo "  $0 download phi-2-q4"
    echo "  $0 remove phi-2.Q4_K_M.gguf"
    echo "  $0 verify phi-2.Q4_K_M.gguf"
    echo ""
}

# Main
case "${1:-help}" in
    list)
        list_models
        ;;
    download)
        download_model "$2"
        ;;
    remove)
        remove_model "$2"
        ;;
    usage)
        show_usage
        ;;
    verify)
        verify_model "$2"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
