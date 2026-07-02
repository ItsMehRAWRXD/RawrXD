#include "resource_arbiter.h"
#include <psapi.h>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "psapi.lib")

namespace RawrXD {
namespace Core {

// ============================================================================
// Singleton
// ============================================================================

ResourceArbiter& ResourceArbiter::Instance() {
    static ResourceArbiter instance;
    return instance;
}

// ============================================================================
// Initialization
// ============================================================================

bool ResourceArbiter::Initialize(const ResourceBudget& budget) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_initialized) return true;

    m_budget = budget;

    if (!DetectSystemResources()) {
        return false;
    }

    // Apply default budget fractions if not explicitly set
    if (m_budget.max_ram_bytes == 0) {
        // Leave 20% headroom for OS
        m_budget.max_ram_bytes = static_cast<size_t>(m_total_ram * 0.80);
    }
    if (m_budget.max_vram_bytes == 0 && m_total_vram > 0) {
        m_budget.max_vram_bytes = static_cast<size_t>(m_total_vram * 0.90);
    }
    if (m_budget.max_disk_cache_bytes == 0) {
        // Default: 10GB disk cache
        m_budget.max_disk_cache_bytes = 10ULL * 1024 * 1024 * 1024;
    }

    m_initialized = true;
    return true;
}

void ResourceArbiter::Shutdown() {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_initialized) return;

    // Notify all subsystems to release
    for (auto& [id, state] : m_subsystems) {
        if (state.on_evict_callback) {
            state.on_evict_callback();
        }
    }

    m_subsystems.clear();
    m_initialized = false;
}

// ============================================================================
// System Detection
// ============================================================================

bool ResourceArbiter::DetectSystemResources() {
    // RAM
    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    if (!GlobalMemoryStatusEx(&mem)) {
        return false;
    }
    m_total_ram = mem.ullTotalPhys;

    // VRAM — try DXGI first, then Vulkan
    m_total_vram = 0;
    
    // Simple DXGI detection
    HMODULE dxgi = LoadLibraryW(L"dxgi.dll");
    if (dxgi) {
        using CreateDXGIFactory1_t = HRESULT(WINAPI*)(REFIID, void**);
        auto createDXGIFactory1 = reinterpret_cast<CreateDXGIFactory1_t>(
            GetProcAddress(dxgi, "CreateDXGIFactory1"));
        
        if (createDXGIFactory1) {
            struct IDXGIAdapter1;
            struct IDXGIFactory1;
            
            // We can't include full DXGI headers, so use COM directly
            // This is a simplified check — in production, use proper DXGI queries
            // For now, detect VRAM via WMI or registry
        }
        FreeLibrary(dxgi);
    }

    // Fallback: detect VRAM from registry (AMD/NVIDIA/Intel)
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Video",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        // Enumerate subkeys to find GPU adapters
        // This is a simplified check
        RegCloseKey(hKey);
    }

    // If still unknown, estimate from system RAM
    if (m_total_vram == 0) {
        // Typical discrete GPU: 8-16GB. Integrated: shared with RAM.
        // Conservative estimate: 4GB or 1/4 of RAM, whichever is smaller
        m_total_vram = std::min(m_total_ram / 4, 4ULL * 1024 * 1024 * 1024);
    }

    return true;
}

// ============================================================================
// Subsystem Registration
// ============================================================================

bool ResourceArbiter::RegisterSubsystem(const SubsystemState& state) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_initialized) return false;

    // Calculate budget for this subsystem
    size_t budget = 0;
    switch (state.id) {
        case Subsystem::Inference:
            budget = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.inference_fraction);
            break;
        case Subsystem::Vision:
            budget = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.vision_fraction);
            break;
        case Subsystem::Crucible:
            budget = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.crucible_fraction);
            break;
        default:
            budget = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.system_fraction / 4);
            break;
    }

    SubsystemState registered = state;
    registered.budget_bytes = budget;
    registered.current_bytes = 0;
    registered.peak_bytes = 0;
    registered.active = true;

    m_subsystems[state.id] = registered;
    return true;
}

void ResourceArbiter::UnregisterSubsystem(Subsystem id) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_subsystems.find(id);
    if (it != m_subsystems.end()) {
        m_used_ram -= it->second.current_bytes;
        m_subsystems.erase(it);
    }
}

bool ResourceArbiter::IsSubsystemActive(Subsystem id) const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_subsystems.find(id);
    return it != m_subsystems.end() && it->second.active;
}

// ============================================================================
// Memory Allocation Coordination
// ============================================================================

bool ResourceArbiter::RequestAllocation(Subsystem id, size_t bytes, size_t& granted) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    granted = 0;

    auto it = m_subsystems.find(id);
    if (it == m_subsystems.end()) return false;

    auto& state = it->second;

    // Check if this would exceed subsystem budget
    if (state.current_bytes + bytes > state.budget_bytes) {
        // Try to free space within subsystem
        size_t overage = (state.current_bytes + bytes) - state.budget_bytes;
        if (state.on_evict_callback) {
            state.on_evict_callback();
            // Re-check after eviction
            if (state.current_bytes + bytes > state.budget_bytes) {
                // Partial grant
                granted = std::min(bytes, state.budget_bytes - state.current_bytes);
                state.current_bytes += granted;
                m_used_ram += granted;
                return granted > 0;
            }
        } else {
            // Partial grant
            granted = std::min(bytes, state.budget_bytes - state.current_bytes);
            state.current_bytes += granted;
            m_used_ram += granted;
            return granted > 0;
        }
    }

    // Check global pressure
    PressureLevel pressure = GetPressureLevel();
    if (pressure >= PressureLevel::High) {
        ApplyPressureMitigation(pressure);
    }

    // Full grant
    granted = bytes;
    state.current_bytes += granted;
    m_used_ram += granted;

    if (m_used_ram > m_peak_usage) {
        m_peak_usage = m_used_ram;
    }

    return true;
}

void ResourceArbiter::ReleaseAllocation(Subsystem id, size_t bytes) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_subsystems.find(id);
    if (it == m_subsystems.end()) return;

    auto& state = it->second;
    if (state.current_bytes >= bytes) {
        state.current_bytes -= bytes;
        m_used_ram -= bytes;
    }
}

void ResourceArbiter::ReportUsage(Subsystem id, size_t bytes) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_subsystems.find(id);
    if (it == m_subsystems.end()) return;

    auto& state = it->second;
    size_t delta = 0;
    if (bytes > state.current_bytes) {
        delta = bytes - state.current_bytes;
        m_used_ram += delta;
    } else {
        delta = state.current_bytes - bytes;
        m_used_ram -= delta;
    }
    state.current_bytes = bytes;

    if (state.current_bytes > state.peak_bytes) {
        state.peak_bytes = state.current_bytes;
    }
    if (m_used_ram > m_peak_usage) {
        m_peak_usage = m_used_ram;
    }
}

// ============================================================================
// Focus Mode
// ============================================================================

void ResourceArbiter::EnterFocusMode(Subsystem id) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_initialized) return;

    m_focus_subsystem = id;
    m_focus_mode_active = true;

    {
        std::lock_guard<std::recursive_mutex> stats_lock(m_stats_mutex);
        m_stats.focus_mode_switches++;
    }

    // Compress/offload non-focus subsystems
    for (auto& [sid, state] : m_subsystems) {
        if (sid == id) continue;

        if (state.can_compress && state.on_compress_callback) {
            state.on_compress_callback();
            {
                std::lock_guard<std::recursive_mutex> stats_lock(m_stats_mutex);
                m_stats.compression_count++;
            }
        }

        if (state.can_offload && state.on_evict_callback) {
            state.on_evict_callback();
            {
                std::lock_guard<std::recursive_mutex> stats_lock(m_stats_mutex);
                m_stats.eviction_count++;
            }
        }
    }
}

void ResourceArbiter::ExitFocusMode() {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_focus_mode_active = false;
    m_focus_subsystem = Subsystem::Compiler;

    // Restore normal budgets
    RebalanceBudgets();
}

// ============================================================================
// Pressure Management
// ============================================================================

ResourceArbiter::PressureLevel ResourceArbiter::GetPressureLevel() const {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_initialized) return PressureLevel::None;

    double ram_ratio = static_cast<double>(m_used_ram) / static_cast<double>(m_budget.max_ram_bytes);

    if (ram_ratio >= 0.95) return PressureLevel::Critical;
    if (ram_ratio >= 0.85) return PressureLevel::High;
    if (ram_ratio >= 0.70) return PressureLevel::Medium;
    if (ram_ratio >= 0.55) return PressureLevel::Low;
    return PressureLevel::None;
}

void ResourceArbiter::SetPressureCallback(std::function<void(PressureLevel)> callback) {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_pressure_callback = callback;
}

void ResourceArbiter::ApplyPressureMitigation(PressureLevel level) {
    if (m_pressure_callback) {
        m_pressure_callback(level);
    }

    switch (level) {
        case PressureLevel::Critical:
            // Evict everything non-critical
            for (auto& [id, state] : m_subsystems) {
                if (state.priority < MemoryTier::Critical && state.on_evict_callback) {
                    state.on_evict_callback();
                }
            }
            break;

        case PressureLevel::High:
            // Compress high-priority, evict low-priority
            for (auto& [id, state] : m_subsystems) {
                if (state.priority == MemoryTier::Low && state.on_evict_callback) {
                    state.on_evict_callback();
                } else if (state.priority == MemoryTier::Normal && state.can_compress && state.on_compress_callback) {
                    state.on_compress_callback();
                }
            }
            break;

        case PressureLevel::Medium:
            // Compress low-priority
            for (auto& [id, state] : m_subsystems) {
                if (state.priority == MemoryTier::Low && state.can_compress && state.on_compress_callback) {
                    state.on_compress_callback();
                }
            }
            break;

        default:
            break;
    }
}

// ============================================================================
// Global Memory Query
// ============================================================================

size_t ResourceArbiter::GetAvailableRAM() const {
    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    if (!GlobalMemoryStatusEx(&mem)) return 0;
    return mem.ullAvailPhys;
}

size_t ResourceArbiter::GetUsedVRAM() const {
    // TODO: Implement proper GPU memory query via Vulkan/DXGI
    return m_used_vram;
}

// ============================================================================
// Statistics
// ============================================================================

ResourceArbiter::Stats ResourceArbiter::GetStats() const {
    std::lock_guard<std::recursive_mutex> lock(m_stats_mutex);
    Stats stats = m_stats;
    stats.total_allocated = m_used_ram;
    stats.total_budget = m_budget.max_ram_bytes;
    stats.peak_usage = m_peak_usage;
    return stats;
}

// ============================================================================
// Emergency Purge
// ============================================================================

bool ResourceArbiter::EmergencyPurge() {
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (!m_initialized) return false;

    bool purged = false;
    for (auto& [id, state] : m_subsystems) {
        if (state.priority != MemoryTier::Critical && state.on_evict_callback) {
            state.on_evict_callback();
            purged = true;
        }
    }

    return purged;
}

// ============================================================================
// Rebalance Budgets
// ============================================================================

void ResourceArbiter::RebalanceBudgets() {
    for (auto& [id, state] : m_subsystems) {
        switch (id) {
            case Subsystem::Inference:
                state.budget_bytes = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.inference_fraction);
                break;
            case Subsystem::Vision:
                state.budget_bytes = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.vision_fraction);
                break;
            case Subsystem::Crucible:
                state.budget_bytes = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.crucible_fraction);
                break;
            default:
                state.budget_bytes = static_cast<size_t>(m_budget.max_ram_bytes * m_budget.system_fraction / 4);
                break;
        }
    }
}

} // namespace Core
} // namespace RawrXD
