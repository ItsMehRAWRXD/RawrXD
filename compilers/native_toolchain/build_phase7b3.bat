@echo off
echo Building RawRamXD Phase 7B.3 - Unified Memory Fabric
echo ============================================================

g++ -O3 -std=c++17 -o RawRamXD_Phase7B3.exe src\fabric\RawRamXD_Phase7B3_UnifiedMemoryFabric.cpp -ld3d12 -ldxgi -lkernel32 -luser32

echo Build complete: RawRamXD_Phase7B3.exe
