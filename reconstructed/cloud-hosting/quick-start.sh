#!/bin/bash

# RawrXD - Quick Start Script
# Launches server and UI together for the best local experience

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  RawrXD - Quick Start (Server + UI)                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if installed
if ! command -v rawrxd-serve &> /dev/null && [ ! -f "${HOME}/.local/bin/rawrxd-serve" ]; then
    echo -e "${YELLOW}[!]${NC} RawrXD not installed yet"
    echo ""
    echo "Would you like to install now?"
    read -p "[Y/n]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        if [ -f "${SCRIPT_DIR}/install-local.sh" ]; then
            bash "${SCRIPT_DIR}/install-local.sh"
        else
            echo "Installation script not found. Please run install-local.sh first."
            exit 1
        fi
    else
        echo "Installation cancelled. Please install first with:"
        echo "  ./install-local.sh"
        exit 0
    fi
fi

# Function to check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 || netstat -an 2>/dev/null | grep -q ":$port.*LISTEN"; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Check if server is already running
if check_port 8080; then
    echo -e "${GREEN}[✓]${NC} Server already running on port 8080"
else
    echo -e "${BLUE}[*]${NC} Starting RawrXD server..."
    
    # Start server in background
    if command -v rawrxd-serve &> /dev/null; then
        nohup rawrxd-serve > "${HOME}/.local/share/rawrxd/logs/server.log" 2>&1 &
    elif [ -f "${HOME}/.local/bin/rawrxd-serve" ]; then
        nohup "${HOME}/.local/bin/rawrxd-serve" > "${HOME}/.local/share/rawrxd/logs/server.log" 2>&1 &
    else
        echo -e "${YELLOW}[!]${NC} Could not find rawrxd-serve command"
        exit 1
    fi
    
    SERVER_PID=$!
    echo -e "${GREEN}[✓]${NC} Server started (PID: $SERVER_PID)"
    
    # Wait for server to be ready
    echo -e "${BLUE}[*]${NC} Waiting for server to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:8080/health > /dev/null 2>&1; then
            echo -e "${GREEN}[✓]${NC} Server ready!"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${YELLOW}[!]${NC} Server is taking longer than expected to start"
            echo "Check logs: tail -f ${HOME}/.local/share/rawrxd/logs/server.log"
        fi
        sleep 1
    done
fi

# Start UI
echo -e "${BLUE}[*]${NC} Starting Web UI..."
sleep 1

# Make start-ui.sh executable if it exists
if [ -f "${SCRIPT_DIR}/start-ui.sh" ]; then
    chmod +x "${SCRIPT_DIR}/start-ui.sh"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  🎉 RawrXD is Ready!                                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Access Points:${NC}"
echo "  🌐 Web UI:  http://localhost:8081"
echo "  🔌 API:     http://localhost:8080"
echo "  📊 Health:  http://localhost:8080/health"
echo "  📖 Docs:    http://localhost:8080/docs"
echo ""
echo -e "${BLUE}Quick Commands:${NC}"
echo "  View logs:  tail -f ~/.local/share/rawrxd/logs/server.log"
echo "  Stop all:   pkill -f 'rawrxd-serve|start-ui.sh'"
echo ""
echo -e "${YELLOW}Opening Web UI in browser...${NC}"
echo ""

# Try to open browser
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:8081 2>/dev/null &
elif command -v open &> /dev/null; then
    open http://localhost:8081 2>/dev/null &
else
    echo "Please open http://localhost:8081 in your browser"
fi

# Start UI server (this will block)
if [ -f "${SCRIPT_DIR}/start-ui.sh" ]; then
    exec bash "${SCRIPT_DIR}/start-ui.sh"
else
    echo "UI script not found. Opening API in browser instead..."
    if command -v xdg-open &> /dev/null; then
        xdg-open http://localhost:8080/docs 2>/dev/null
    elif command -v open &> /dev/null; then
        open http://localhost:8080/docs 2>/dev/null
    fi
    
    echo ""
    echo "Server running at http://localhost:8080"
    echo "Press Ctrl+C to stop"
    
    # Keep script running
    tail -f "${HOME}/.local/share/rawrxd/logs/server.log" 2>/dev/null || sleep infinity
fi
