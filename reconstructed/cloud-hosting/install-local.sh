#!/bin/bash

# RawrXD Quantum Models - Offline Local Installation
# This script sets up llama.cpp and models for local/offline use
# No cloud services required!

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/share/rawrxd"
BIN_DIR="${HOME}/.local/bin"
MODELS_DIR="${INSTALL_DIR}/models"
CACHE_DIR="${INSTALL_DIR}/cache"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RawrXD Quantum Models - Offline Local Installation       ║${NC}"
echo -e "${BLUE}║  The Absolute Bestest Local AI Experience!                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to print status messages
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

# Check OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        print_error "Unsupported OS: $OSTYPE"
        print_info "Please use install-local.bat for Windows"
        exit 1
    fi
    print_status "Detected OS: $OS"
}

# Check dependencies
check_dependencies() {
    print_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Essential tools
    for cmd in git cmake make curl; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=($cmd)
        fi
    done
    
    # Compiler
    if ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
        missing_deps+=("gcc or clang")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_info "Installing dependencies..."
        
        if [[ "$OS" == "linux" ]]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update
                sudo apt-get install -y build-essential cmake git curl wget
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y gcc gcc-c++ cmake git curl wget
            elif command -v pacman &> /dev/null; then
                sudo pacman -Sy --noconfirm base-devel cmake git curl wget
            else
                print_error "Unsupported package manager. Please install: ${missing_deps[*]}"
                exit 1
            fi
        elif [[ "$OS" == "macos" ]]; then
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew not found. Please install from https://brew.sh"
                exit 1
            fi
            brew install cmake git curl wget
        fi
        
        print_status "Dependencies installed"
    else
        print_status "All dependencies satisfied"
    fi
}

# Create directory structure
setup_directories() {
    print_info "Setting up directories..."
    
    mkdir -p "${INSTALL_DIR}"
    mkdir -p "${BIN_DIR}"
    mkdir -p "${MODELS_DIR}"
    mkdir -p "${CACHE_DIR}"
    mkdir -p "${INSTALL_DIR}/logs"
    
    print_status "Directories created at ${INSTALL_DIR}"
}

# Build llama.cpp from source
build_llama_cpp() {
    print_info "Building llama.cpp server..."
    
    cd "${INSTALL_DIR}"
    
    # Clone or update llama.cpp
    if [ -d "llama.cpp" ]; then
        print_info "Updating existing llama.cpp..."
        cd llama.cpp
        git pull
    else
        print_info "Cloning llama.cpp..."
        git clone https://github.com/ggerganov/llama.cpp.git
        cd llama.cpp
    fi
    
    # Build with optimizations
    print_info "Compiling (this may take a few minutes)..."
    mkdir -p build
    cd build
    
    # Detect and use available acceleration
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"
    
    # Check for Metal (macOS)
    if [[ "$OS" == "macos" ]]; then
        CMAKE_FLAGS="${CMAKE_FLAGS} -DLLAMA_METAL=ON"
        print_info "Metal acceleration enabled (macOS)"
    fi
    
    # Check for CUDA
    if command -v nvidia-smi &> /dev/null; then
        CMAKE_FLAGS="${CMAKE_FLAGS} -DLLAMA_CUBLAS=ON"
        print_info "CUDA acceleration enabled"
    fi
    
    # Check for ROCm (AMD)
    if [ -d "/opt/rocm" ]; then
        CMAKE_FLAGS="${CMAKE_FLAGS} -DLLAMA_HIPBLAS=ON"
        print_info "ROCm acceleration enabled"
    fi
    
    cmake .. ${CMAKE_FLAGS}
    cmake --build . --config Release -j $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    # Copy server binary
    if [ -f "bin/server" ]; then
        cp bin/server "${BIN_DIR}/llama-server"
        chmod +x "${BIN_DIR}/llama-server"
        print_status "llama-server installed to ${BIN_DIR}/llama-server"
    elif [ -f "bin/llama-server" ]; then
        cp bin/llama-server "${BIN_DIR}/llama-server"
        chmod +x "${BIN_DIR}/llama-server"
        print_status "llama-server installed to ${BIN_DIR}/llama-server"
    else
        print_error "Server binary not found after build"
        exit 1
    fi
    
    # Copy other useful tools
    for tool in main quantize perplexity embedding; do
        if [ -f "bin/$tool" ] || [ -f "bin/llama-$tool" ]; then
            cp bin/*$tool "${BIN_DIR}/" 2>/dev/null || true
        fi
    done
}

# Download sample model
download_sample_model() {
    print_info "Checking for models..."
    
    if [ "$(ls -A ${MODELS_DIR}/*.gguf 2>/dev/null | wc -l)" -gt 0 ]; then
        print_status "Models already present"
        return
    fi
    
    print_warning "No models found. Would you like to download a sample model?"
    read -p "Download Phi-2 (2.7B parameters, ~1.6GB)? [Y/n]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        print_info "Downloading Phi-2 Q4_K_M model from HuggingFace..."
        
        cd "${MODELS_DIR}"
        
        # Using huggingface-cli if available, otherwise wget
        if command -v huggingface-cli &> /dev/null; then
            huggingface-cli download microsoft/phi-2-gguf phi-2.Q4_K_M.gguf --local-dir . --local-dir-use-symlinks False
        else
            # Direct download
            MODEL_URL="https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_K_M.gguf"
            wget -O phi-2.Q4_K_M.gguf "${MODEL_URL}" --progress=bar:force 2>&1 | \
                grep --line-buffered "%" | \
                sed -u -e "s,\.,,g" | \
                awk '{printf("\r[*] Progress: %4s", $2)}'
            echo ""
        fi
        
        if [ -f "phi-2.Q4_K_M.gguf" ]; then
            print_status "Model downloaded successfully"
        else
            print_warning "Model download failed. You can manually download models to ${MODELS_DIR}"
        fi
    else
        print_info "Skipping model download. You can add models to: ${MODELS_DIR}"
    fi
}

# Create launcher script
create_launcher() {
    print_info "Creating launcher script..."
    
    cat > "${BIN_DIR}/rawrxd-serve" << 'EOF'
#!/bin/bash
# RawrXD Quantum Models - Local Server Launcher

INSTALL_DIR="${HOME}/.local/share/rawrxd"
MODELS_DIR="${INSTALL_DIR}/models"
LOGS_DIR="${INSTALL_DIR}/logs"

# Find first available model
MODEL=$(find "${MODELS_DIR}" -name "*.gguf" -type f | head -1)

if [ -z "$MODEL" ]; then
    echo "Error: No models found in ${MODELS_DIR}"
    echo "Please download a GGUF model and place it in the models directory"
    exit 1
fi

echo "Starting RawrXD Local Server..."
echo "Model: $(basename $MODEL)"
echo "API will be available at: http://localhost:8080"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start server
"${HOME}/.local/bin/llama-server" \
    --model "$MODEL" \
    --host 0.0.0.0 \
    --port 8080 \
    --threads $(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) \
    --ctx-size 2048 \
    --batch-size 512 \
    2>&1 | tee "${LOGS_DIR}/server.log"
EOF
    
    chmod +x "${BIN_DIR}/rawrxd-serve"
    print_status "Launcher created: rawrxd-serve"
}

# Create systemd service (Linux only)
create_systemd_service() {
    if [[ "$OS" != "linux" ]]; then
        return
    fi
    
    print_info "Would you like to create a systemd service (auto-start on boot)?"
    read -p "[y/N]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mkdir -p "${HOME}/.config/systemd/user"
        
        cat > "${HOME}/.config/systemd/user/rawrxd.service" << EOF
[Unit]
Description=RawrXD Quantum Models Local Server
After=network.target

[Service]
Type=simple
ExecStart=${BIN_DIR}/rawrxd-serve
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
        
        systemctl --user daemon-reload
        systemctl --user enable rawrxd.service
        
        print_status "Systemd service created and enabled"
        print_info "Start with: systemctl --user start rawrxd"
        print_info "Check status: systemctl --user status rawrxd"
    fi
}

# Update PATH
update_path() {
    print_info "Updating PATH..."
    
    SHELL_RC="${HOME}/.bashrc"
    if [[ "$SHELL" == *"zsh"* ]]; then
        SHELL_RC="${HOME}/.zshrc"
    fi
    
    # Check if already in PATH
    if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
        echo "" >> "${SHELL_RC}"
        echo "# RawrXD Quantum Models" >> "${SHELL_RC}"
        echo "export PATH=\"\${HOME}/.local/bin:\$PATH\"" >> "${SHELL_RC}"
        print_status "PATH updated in ${SHELL_RC}"
        print_warning "Please run: source ${SHELL_RC}"
    else
        print_status "PATH already configured"
    fi
}

# Main installation flow
main() {
    detect_os
    check_dependencies
    setup_directories
    build_llama_cpp
    download_sample_model
    create_launcher
    create_systemd_service
    update_path
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Installation Complete! 🎉                                 ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Quick Start:${NC}"
    echo "  1. Add to PATH: source ~/.bashrc  (or ~/.zshrc)"
    echo "  2. Start server: rawrxd-serve"
    echo "  3. Test API: curl http://localhost:8080/health"
    echo ""
    echo -e "${BLUE}Directories:${NC}"
    echo "  Installation: ${INSTALL_DIR}"
    echo "  Models:       ${MODELS_DIR}"
    echo "  Logs:         ${INSTALL_DIR}/logs"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  - Add more models to: ${MODELS_DIR}"
    echo "  - View available models: ls ${MODELS_DIR}"
    echo "  - Server logs: tail -f ${INSTALL_DIR}/logs/server.log"
    echo ""
    echo -e "${YELLOW}Offline Mode:${NC} Everything works without internet! Models are cached locally."
    echo ""
}

# Run installation
main
