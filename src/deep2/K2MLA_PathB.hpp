// K2MLA_PathB.hpp — containment harness: delete q_b D2H (not the phenomenon)
#pragma once
#include "K2KVCache.hpp"
#include "vulkan_compute.h"
#include <cstdint>
#include <cstdio>
#include <string>

namespace Deep2 {

bool PathBWanted() noexcept;
void PathB_NoteQDev(CPUInference::VulkanCompute::DeviceBuf& q,
                    size_t nbytes) noexcept;
void PathB_ClearQDev() noexcept;
CPUInference::VulkanCompute::DeviceBuf* PathB_QDev() noexcept;
void PathB_NoteAttendOk() noexcept;
void PathB_NoteAttendFail() noexcept;
void PathB_NoteQbD2hSkipped() noexcept;
void PathB_NoteQbD2h(uint64_t bytes, uint32_t vkCopyCalls,
                     uint64_t hostMemcpyBytes) noexcept;
void PathB_NoteNoCorresponding() noexcept;
void PathB_Reset() noexcept;
void PathB_Emit(FILE* f) noexcept;

bool PathBAttend(CPUInference::VulkanCompute* vc,
                 CPUInference::VulkanCompute::DeviceBuf& qDev,
                 const float* k_b, const float* v_b, const float* k_pe,
                 float* attnOut, rawrxd::deep2::K2KVCache* kvCache,
                 uint32_t nHeads, uint32_t nope, uint32_t rope, uint32_t vDim,
                 uint32_t pos, uint32_t layer, uint32_t maxSeq, uint32_t nLayers,
                 float theta, float ropeScale, std::string& error);

} // namespace Deep2
