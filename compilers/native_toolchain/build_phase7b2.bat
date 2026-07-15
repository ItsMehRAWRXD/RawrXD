@echo off
echo Building RawRamXD Phase 7B.2 - Multi-GPU Fabric Federation
echo ============================================================

cl.exe /O2 /EHsc /std:c++20 /Fe:RawRamXD_Phase7B2.exe ^
    src\fabric\RawRamXD_Phase7B2_MultiGPU_Federation.cpp ^
    d3d12.lib dxgi.lib kernel32.lib user32.lib advapi32.lib ole32.lib

echo Build complete: RawRamXD_Phase7B2.exe
