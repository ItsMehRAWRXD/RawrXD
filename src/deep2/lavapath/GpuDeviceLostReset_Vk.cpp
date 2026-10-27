/* GpuDeviceLostReset_Vk.cpp — Deep2::VulkanCompute lost/reset wire. ≤99. */
#include "GpuDeviceLostReset.hpp"
#include "../vulkan_compute.h"
#include <cstdio>

namespace Deep2 {
namespace {

bool TeardownThunk(void* ud) {
    auto* self = static_cast<VulkanCompute*>(ud);
    if (!self) return false;
    self->cleanup();
    return true;
}

bool RecreateThunk(void* ud) {
    auto* self = static_cast<VulkanCompute*>(ud);
    if (!self) return false;
    return self->initialize();
}

} // namespace

bool VulkanCompute::NoteVkResult(int vk, const char* stage) {
    lastLostVk_ = vk;
    if (vk == static_cast<int>(VK_SUCCESS)) {
        lastLostPhase_ = "ok";
        return true;
    }
    if (GpuLost::IsLostCode(vk)) {
        GpuLost::Mark(lostSeq_, vk);
        lastLostPhase_ = GpuLost::PhaseFor(vk);
        deviceLostCount_ = lostSeq_.mark;
        return false;
    }
    lastLostPhase_ = stage ? stage : "fail";
    return false;
}

bool VulkanCompute::DeviceIsLost() const noexcept { return lostSeq_.lost; }

uint64_t VulkanCompute::DeviceLostCount() const noexcept {
    return deviceLostCount_;
}

int VulkanCompute::LastLostVk() const noexcept { return lastLostVk_; }

const char* VulkanCompute::LastLostPhase() const noexcept {
    return lastLostPhase_ ? lastLostPhase_ : "none";
}

void VulkanCompute::InjectDeviceLostForTest(int code) {
    NoteVkResult(code, "inject");
}

bool VulkanCompute::RecoverDeviceIfOptIn() {
    if (!GpuLost::OptInEnabled()) {
        std::fprintf(stderr, "DEEP2_GPU_DEVICE_RESET skipped (opt-in off)\n");
        std::fflush(stderr);
        return false;
    }
    if (!lostSeq_.lost) return false;
    return GpuLost::RunReset(lostSeq_, TeardownThunk, RecreateThunk, this);
}

} // namespace Deep2
