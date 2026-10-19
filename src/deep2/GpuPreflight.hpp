// GpuPreflight.hpp — Windows PnP GPU health admission gate
// Checks Windows device status (not just Vulkan enumeration) before
// Vulkan initialization or model loading for both rawr run and the agent.

#pragma once

#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <vector>
#include <string>
#include <cstdio>

// Friendly names of the configured dedicated GPUs.
struct GpuHealth {
    std::wstring friendlyName;
    std::wstring instanceId;
    DWORD status = 0;           // CM_Get_DevNode_Status result
    DWORD problem = 0;          // ConfigManagerErrorCode
    bool started = false;       // DN_STARTED
    bool problemFree = false;   // CM_PROB_NONE
    bool healthy = false;       // started && problemFree
};

// Enumerate Display class devices and return health for each.
std::vector<GpuHealth> EnumerateGpuHealth();

// Check health of the two configured RawrXD GPUs (R9700 + RX 7800 XT).
// Returns true if both are healthy (or if allowCpuOnly is true, always true).
// Output lines are printed to stderr in the RAWRXD_GPU_PREFLIGHT format.
bool GpuPreflightCheck(bool allowCpuOnly = false);

// Returns true if Vulkan ICD appears usable (device enumeration succeeds).
bool VulkanIcdReady();
