#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD::Governance {
enum class GpuBackend : uint8_t { None, Vulkan, DX12, Other };
struct CpuCapabilities {
    uint32_t logical_threads=0, physical_cores=0;
    bool avx=false,avx2=false,avx512f=false,avx512bw=false,avx512vnni=false,fma=false,bmi2=false;
    bool os_avx_state=false, os_avx512_state=false;
};
struct GpuInfo { std::string name; uint64_t dedicated_bytes=0, shared_bytes=0; uint32_t vendor_id=0,device_id=0; GpuBackend backend=GpuBackend::None; bool discrete=false; };
struct HardwareSnapshot {
    uint64_t timestamp_ns=0,total_ram_bytes=0,available_ram_bytes=0,total_virtual_bytes=0,available_virtual_bytes=0;
    CpuCapabilities cpu; std::vector<GpuInfo> gpus; uint64_t total_vram_bytes=0,free_vram_bytes=0; uint32_t gpu_count=0; uint64_t generation=0;
    double ram_headroom() const noexcept; double vram_headroom() const noexcept;
    bool materially_changed_from(const HardwareSnapshot&) const noexcept;
};
class HardwareCapabilityProbe { public: HardwareSnapshot probe() const; };
}
