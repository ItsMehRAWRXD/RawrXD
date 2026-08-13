#include "rawrxd_gpu_context.hpp"
#include "rawrxd_host.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>
#include <dxgi.h>
#include <new>

// ============================================================================
// RawrXD Multi-GPU Context — Implementation
// B018: Explicit device enumeration, no inference logic in host
// ============================================================================

struct rawrxd_gpu_context_t {
    uint32_t device_index;
    rawrxd_gpu_device_info_t info{};
    bool valid = false;
};

// ============================================================================
// DXGI-based device enumeration
// ============================================================================

int rawrxd_gpu_enumerate(rawrxd_gpu_device_info_t* out_devices, uint32_t* out_count)
{
    if (!out_devices || !out_count) {
        return RAWRXD_ERR_INVALID_PARAM;
    }

    *out_count = 0;

    // Create DXGI factory
    IDXGIFactory1* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&pFactory));
    if (FAILED(hr)) {
        std::fprintf(stderr, "[B018] CreateDXGIFactory1 failed: 0x%08X\n", static_cast<uint32_t>(hr));
        return RAWRXD_ERR_ENGINE_INIT;
    }

    uint32_t count = 0;
    for (uint32_t i = 0; i < RAWRXD_GPU_MAX_DEVICES; ++i) {
        IDXGIAdapter1* pAdapter = nullptr;
        hr = pFactory->EnumAdapters1(i, &pAdapter);
        if (hr == DXGI_ERROR_NOT_FOUND) {
            break; // No more adapters
        }
        if (FAILED(hr)) {
            continue;
        }

        DXGI_ADAPTER_DESC1 desc;
        hr = pAdapter->GetDesc1(&desc);
        if (FAILED(hr)) {
            pAdapter->Release();
            continue;
        }

        // Skip software adapters
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
            pAdapter->Release();
            continue;
        }

        rawrxd_gpu_device_info_t& info = out_devices[count];
        info.device_index = count;

        // Convert wide-char name to UTF-8
        int name_len = WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1,
                                            info.name, RAWRXD_GPU_NAME_LEN, nullptr, nullptr);
        if (name_len <= 0) {
            std::strncpy(info.name, "Unknown", RAWRXD_GPU_NAME_LEN - 1);
        }
        info.name[RAWRXD_GPU_NAME_LEN - 1] = '\0';

        info.pci_vendor_id = desc.VendorId;
        info.pci_device_id = desc.DeviceId;
        info.vram_total_bytes = desc.DedicatedVideoMemory;
        info.vram_available_bytes = desc.DedicatedVideoMemory; // Approximation
        info.compute_units = 0; // Would require GPU-specific query
        info.max_clock_mhz = 0; // Would require GPU-specific query
        info.flags = 0;

        // Detect vendor and set flags
        if (desc.VendorId == 0x10DE) { // NVIDIA
            info.flags |= RAWRXD_GPU_FLAG_CUDA;
        } else if (desc.VendorId == 0x1002 || desc.VendorId == 0x1022) { // AMD
            info.flags |= RAWRXD_GPU_FLAG_RDNA3; // Conservative assumption
        } else if (desc.VendorId == 0x8086) { // Intel
            // No specific flag yet
        }

        // Check for Resizable BAR / Large BAR
        // This is a heuristic: if shared system memory is large, assume SAM/ReBAR
        if (desc.SharedSystemMemory >= 4ULL * 1024 * 1024 * 1024) {
            info.flags |= RAWRXD_GPU_FLAG_LARGE_BAR;
        }

        std::memset(info.reserved, 0, sizeof(info.reserved));

        pAdapter->Release();
        ++count;

        if (count >= RAWRXD_GPU_MAX_DEVICES) {
            break;
        }
    }

    pFactory->Release();
    *out_count = count;

    std::printf("[B018] Enumerated %u GPU device(s)\n", count);
    for (uint32_t i = 0; i < count; ++i) {
        std::printf("  [%u] %s (0x%04X:0x%04X) VRAM=%llu MB flags=0x%04X\n",
                    out_devices[i].device_index,
                    out_devices[i].name,
                    out_devices[i].pci_vendor_id,
                    out_devices[i].pci_device_id,
                    static_cast<unsigned long long>(out_devices[i].vram_total_bytes / (1024 * 1024)),
                    out_devices[i].flags);
    }

    return RAWRXD_OK;
}

// ============================================================================
// Context lifecycle
// ============================================================================

rawrxd_gpu_context_handle_t rawrxd_gpu_context_create(uint32_t device_index)
{
    // Query device info first
    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    int rc = rawrxd_gpu_enumerate(devices, &count);
    if (rc != RAWRXD_OK || device_index >= count) {
        return nullptr;
    }

    rawrxd_gpu_context_t* ctx = new (std::nothrow) rawrxd_gpu_context_t();
    if (!ctx) {
        return nullptr;
    }

    ctx->device_index = device_index;
    ctx->info = devices[device_index];
    ctx->valid = true;

    std::printf("[B018] Created GPU context for device %u: %s\n",
                device_index, ctx->info.name);

    return ctx;
}

void rawrxd_gpu_context_destroy(rawrxd_gpu_context_handle_t ctx)
{
    if (!ctx) return;
    std::printf("[B018] Destroyed GPU context for device %u: %s\n",
                ctx->device_index, ctx->info.name);
    delete ctx;
}

int rawrxd_gpu_context_get_info(rawrxd_gpu_context_handle_t ctx, rawrxd_gpu_device_info_t* out_info)
{
    if (!ctx || !out_info || !ctx->valid) {
        return RAWRXD_ERR_INVALID_PARAM;
    }
    *out_info = ctx->info;
    return RAWRXD_OK;
}

// ============================================================================
// Capability queries
// ============================================================================

bool rawrxd_gpu_has_flag(const rawrxd_gpu_device_info_t* info, uint32_t flag)
{
    if (!info) return false;
    return (info->flags & flag) != 0;
}

bool rawrxd_gpu_can_fit_model(const rawrxd_gpu_device_info_t* info,
                               uint64_t parameter_count,
                               uint32_t bits_per_weight)
{
    if (!info || bits_per_weight == 0) return false;

    // Conservative estimate: model weights + KV cache + overhead
    uint64_t weight_bytes = (parameter_count * bits_per_weight) / 8;
    uint64_t kv_estimate = 256ULL * 1024 * 1024; // 256 MB minimum KV
    uint64_t overhead = 512ULL * 1024 * 1024;    // 512 MB overhead

    uint64_t total_needed = weight_bytes + kv_estimate + overhead;

    // Require 20% headroom
    uint64_t available_with_headroom = info->vram_available_bytes * 8 / 10;

    return total_needed <= available_with_headroom;
}
