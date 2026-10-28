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
    DEVINST devInst = 0;        // for CM_Disable/Enable reset path
    DWORD status = 0;           // CM_Get_DevNode_Status result
    DWORD problem = 0;          // ConfigManagerErrorCode (31 = CM_PROB_FAILED_ADD)
    bool started = false;       // DN_STARTED
    bool problemFree = false;   // CM_PROB_NONE
    bool healthy = false;       // started && problemFree
};

// Enumerate Display class devices and return health for each.
std::vector<GpuHealth> EnumerateGpuHealth();

// Code 31 / 10 / 14 / 43 — recoverable PnP problem codes for display adapters.
// CM_PROB_FAILED_ADD (31) == Windows ERROR_GEN_FAILURE numeric alias.
bool GpuProblemCodeRecoverable(DWORD problem);
bool GpuIsCode31(DWORD problem); // CM_PROB_FAILED_ADD / ERROR_GEN_FAILURE

// Disable→Enable DevNode reset; returns true if STARTED && CM_PROB_NONE after.
bool AttemptGpuDevNodeReset(DEVINST devInst, DWORD problemBefore);

// UAC RunAs → scripts/Reset-GpuDevicePnp.ps1 (7800 XT Code 10/31 Disable+Enable).
// Returns true only if script exit 0 (problem cleared / bypass healthy).
bool AttemptElevatedGpuPnpCycle();
// Same; *outLaunched=true if elevated helper process actually started.
bool AttemptElevatedGpuPnpCycleEx(bool* outLaunched);

// DXGI/D3D device-removed family (not PnP Code 31, but same recovery class).
bool GpuIsDxgiDeviceRemovedHr(long hr);

// Check health of the two configured RawrXD GPUs (R9700 + RX 7800 XT).
// On recoverable problem codes (esp. Code 31), attempts DevNode reset once.
// Returns true if both are healthy (or if allowCpuOnly is true, always true).
bool GpuPreflightCheck(bool allowCpuOnly = false);

// Returns true if Vulkan ICD appears usable (device enumeration succeeds).
bool VulkanIcdReady();
