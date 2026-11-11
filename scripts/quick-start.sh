#!/bin/bash
#
# Sovereign Substrate - Quick Start Script
# Usage: ./quick-start.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Sovereign Substrate - Quick Start                  ║"
echo "║                                                              ║"
echo "║  The IDE is now autonomous. Let it evolve.                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v cmake &> /dev/null; then
    echo -e "${RED}Error: CMake is not installed${NC}"
    echo "Please install CMake 3.16 or later"
    exit 1
fi

if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
    echo -e "${RED}Error: No C++ compiler found${NC}"
    echo "Please install g++ or clang++"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites met${NC}"

# Create build directory
echo -e "${YELLOW}Setting up build environment...${NC}"
mkdir -p build
cd build

# Configure
echo -e "${YELLOW}Configuring build...${NC}"
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DRAWR_BUILD_TESTS=ON \
    -DRAWR_BUILD_DEMO=ON \
    -DRAWR_SECURITY_HARDENING=ON \
    -DRAWR_MODEL_ADAPTER=ON \
    -DRAWR_PERSISTENCE=ON \
    -DRAWR_TELEMETRY=ON

# Build
echo -e "${YELLOW}Building Sovereign Substrate...${NC}"
cmake --build . --parallel $(nproc)

echo -e "${GREEN}✓ Build complete${NC}"

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
if ctest --output-on-failure; then
    echo -e "${GREEN}✓ All tests passed${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi

# Run demo
echo -e "${YELLOW}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Running Demo                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

./demo/demo_sovereign_substrate

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Sovereign Substrate Ready!                      ║"
echo "║                                                              ║"
echo "║  Next steps:                                                 ║"
echo "║    1. Read START_HERE_SOVEREIGN.md                          ║"
echo "║    2. Explore examples/ directory                           ║"
echo "║    3. Check out the API documentation                       ║"
echo "║                                                              ║"
echo "║  The IDE is now autonomous.                                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
