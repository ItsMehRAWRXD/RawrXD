// K2GpuStreamCopy.hpp — K2 stream lane host→device vkCmdCopy + overlap
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace CPUInference { class VulkanCompute; }

namespace Deep2 {

bool K2GpuStreamCopy_Wanted();
bool K2GpuStreamCopy_OverlapWanted();
void K2GpuStreamCopy_Bind(CPUInference::VulkanCompute* vc);
CPUInference::VulkanCompute* K2GpuStreamCopy_Vc();
void K2GpuStreamCopy_Reset();
bool K2GpuStreamCopy_UploadLargest(const std::vector<uint8_t>* payloads, size_t n);
uint64_t K2GpuStreamCopy_UploadOps();
uint64_t K2GpuStreamCopy_UploadBytes();
uint64_t K2GpuStreamCopy_FailOps();
void K2GpuStreamCopy_Emit(FILE* f);

} // namespace Deep2
