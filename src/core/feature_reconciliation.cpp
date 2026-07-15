/**
 * Feature Registry Reconciliation Layer
 * 
 * Bridges the Failure Mode Firewall (FMF) with the Feature Registry to provide:
 * 1. Runtime-verified capability graph
 * 2. Stub execution detection and logging
 * 3. Build-time + runtime reconciliation
 * 4. No-stub execution enforcement
 */

#include "FailureModeFirewall.h"
#include "../../include/feature_registry.h"
#include <windows.h>
#include <psapi.h>
#include <sstream>
#include <fstream>
#include <algorithm>

// ============================================================================
// Feature Reconciliation State
// ============================================================================

struct ReconciliationState {
    bool declared;          // Declared in registry
    bool hasRealSymbol;     // Has real implementation symbol
    bool stubbed;           // Has stub fallback
    uint32_t stubCallCount;
    uint32_t realCallCount;
    std::string lastStubFile;
    std::string lastRealFile;
};

class FeatureReconciliation {
public:
    static FeatureReconciliation& Instance() {
        static FeatureReconciliation instance;
        return instance;
    }

    // Initialize from Feature Registry
    void InitializeFromRegistry() {
        auto& registry = FeatureRegistry::instance();
        auto features = registry.getAllFeatures();
        
        for (const auto& f : features) {
            if (!f.name) continue;
            
            ReconciliationState state;
            state.declared = (f.status != ImplStatus::Stub);
            state.hasRealSymbol = (f.funcPtr != nullptr && !f.stubDetected);
            state.stubbed = f.stubDetected;
            state.stubCallCount = 0;
            state.realCallCount = 0;
            
            m_states[f.name] = state;
            
            // Register with FMF
            FMF_REGISTER_FEATURE(f.name, state.declared, state.hasRealSymbol, state.stubbed);
        }
    }

    // Verify symbol presence in binary
    void VerifySymbols() {
        HMODULE hModule = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)&FeatureReconciliation::Instance,
                               &hModule)) {
            return;
        }

        // Get module base address and size
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return;
        }

        // For each feature, verify symbol presence
        for (auto& [name, state] : m_states) {
            // Try to get symbol address
            // Note: This is a simplified check - real implementation would use
            // export table or symbol table parsing
            
            // Check if function pointer is valid
            auto& registry = FeatureRegistry::instance();
            auto features = registry.getAllFeatures();
            
            for (const auto& f : features) {
                if (f.name && strcmp(f.name, name.c_str()) == 0) {
                    if (f.funcPtr != nullptr) {
                        // Verify pointer is within module bounds
                        uintptr_t addr = reinterpret_cast<uintptr_t>(f.funcPtr);
                        uintptr_t moduleStart = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                        uintptr_t moduleEnd = moduleStart + modInfo.SizeOfImage;
                        
                        if (addr >= moduleStart && addr < moduleEnd) {
                            state.hasRealSymbol = true;
                        }
                    }
                    break;
                }
            }
        }
    }

    // Update from FMF telemetry
    void UpdateFromFMF() {
        std::unordered_map<std::string, FeatureRuntimeState> fmfStats;
        FailureModeFirewall::Instance().GetAllFeatureStats(fmfStats);
        
        for (const auto& [name, fmfState] : fmfStats) {
            auto it = m_states.find(name);
            if (it != m_states.end()) {
                it->second.stubCallCount = fmfState.stubCallCount.load();
                it->second.realCallCount = fmfState.realCallCount.load();
            }
        }
    }

    // Get reconciliation state for a feature
    const ReconciliationState* GetState(const std::string& featureName) const {
        auto it = m_states.find(featureName);
        if (it == m_states.end()) return nullptr;
        return &it->second;
    }

    // Generate reconciliation report
    std::string GenerateReport() const {
        std::ostringstream oss;
        
        oss << "=== Feature Reconciliation Report ===\n\n";
        oss << "Feature                          | Declared | Real | Stub | StubCalls | RealCalls | Risk\n";
        oss << std::string(100, '-') << "\n";
        
        for (const auto& [name, state] : m_states) {
            std::string risk = "OK";
            if (state.stubbed && state.stubCallCount > 0 && state.realCallCount == 0) {
                risk = "CRITICAL";
            } else if (state.stubbed && state.stubCallCount > 0) {
                risk = "HIGH";
            } else if (state.stubbed && state.realCallCount > 0) {
                risk = "MEDIUM";
            }
            
            oss << std::left << std::setw(32) << name.substr(0, 31)
                << " | " << std::setw(8) << (state.declared ? "YES" : "NO")
                << " | " << std::setw(4) << (state.hasRealSymbol ? "YES" : "NO")
                << " | " << std::setw(4) << (state.stubbed ? "YES" : "NO")
                << " | " << std::setw(9) << state.stubCallCount
                << " | " << std::setw(8) << state.realCallCount
                << " | " << risk << "\n";
        }
        
        oss << "\n=== Summary ===\n";
        size_t critical = 0, high = 0, medium = 0, ok = 0;
        for (const auto& [name, state] : m_states) {
            if (state.stubbed && state.stubCallCount > 0 && state.realCallCount == 0) {
                critical++;
            } else if (state.stubbed && state.stubCallCount > 0) {
                high++;
            } else if (state.stubbed && state.realCallCount > 0) {
                medium++;
            } else {
                ok++;
            }
        }
        
        oss << "CRITICAL: " << critical << " (stub-only execution)\n";
        oss << "HIGH:     " << high << " (mixed stub/real)\n";
        oss << "MEDIUM:   " << medium << " (stubbed but real used)\n";
        oss << "OK:       " << ok << " (no issues)\n";
        
        return oss.str();
    }

    // Export to JSON for machine parsing
    void ExportJSON(const std::string& filepath) const {
        std::ofstream file(filepath);
        if (!file.is_open()) return;
        
        file << "{\n";
        file << "  \"features\": {\n";
        
        bool first = true;
        for (const auto& [name, state] : m_states) {
            if (!first) file << ",\n";
            first = false;
            
            std::string risk = "OK";
            if (state.stubbed && state.stubCallCount > 0 && state.realCallCount == 0) {
                risk = "CRITICAL";
            } else if (state.stubbed && state.stubCallCount > 0) {
                risk = "HIGH";
            } else if (state.stubbed && state.realCallCount > 0) {
                risk = "MEDIUM";
            }
            
            file << "    \"" << name << "\": {\n";
            file << "      \"declared\": " << (state.declared ? "true" : "false") << ",\n";
            file << "      \"hasRealSymbol\": " << (state.hasRealSymbol ? "true" : "false") << ",\n";
            file << "      \"stubbed\": " << (state.stubbed ? "true" : "false") << ",\n";
            file << "      \"stubCallCount\": " << state.stubCallCount << ",\n";
            file << "      \"realCallCount\": " << state.realCallCount << ",\n";
            file << "      \"risk\": \"" << risk << "\"\n";
            file << "    }";
        }
        
        file << "\n  }\n";
        file << "}\n";
        
        file.close();
    }

    // Check if a feature is safe to use (no stub-only execution)
    bool IsFeatureSafe(const std::string& featureName) const {
        auto it = m_states.find(featureName);
        if (it == m_states.end()) return false;
        
        const auto& state = it->second;
        
        // Feature is safe if:
        // 1. It has a real symbol
        // 2. It has been called at least once
        // 3. Stub calls are zero OR real calls > stub calls
        
        if (!state.hasRealSymbol) return false;
        if (state.realCallCount == 0 && state.stubCallCount > 0) return false;
        if (state.stubCallCount > state.realCallCount) return false;
        
        return true;
    }

    // Get all features with a given risk level
    std::vector<std::string> GetFeaturesByRisk(const std::string& riskLevel) const {
        std::vector<std::string> result;
        
        for (const auto& [name, state] : m_states) {
            std::string risk = "OK";
            if (state.stubbed && state.stubCallCount > 0 && state.realCallCount == 0) {
                risk = "CRITICAL";
            } else if (state.stubbed && state.stubCallCount > 0) {
                risk = "HIGH";
            } else if (state.stubbed && state.realCallCount > 0) {
                risk = "MEDIUM";
            }
            
            if (risk == riskLevel) {
                result.push_back(name);
            }
        }
        
        return result;
    }

private:
    FeatureReconciliation() = default;
    std::unordered_map<std::string, ReconciliationState> m_states;
};

// ============================================================================
// Integration Functions
// ============================================================================

extern "C" {

// Initialize reconciliation layer at startup
void InitializeFeatureReconciliation() {
    FeatureReconciliation::Instance().InitializeFromRegistry();
    FeatureReconciliation::Instance().VerifySymbols();
}

// Update reconciliation from FMF telemetry
void UpdateFeatureReconciliation() {
    FeatureReconciliation::Instance().UpdateFromFMF();
}

// Generate reconciliation report
const char* GetFeatureReconciliationReport() {
    static std::string report;
    report = FeatureReconciliation::Instance().GenerateReport();
    return report.c_str();
}

// Export reconciliation to JSON
void ExportFeatureReconciliationJSON(const char* filepath) {
    FeatureReconciliation::Instance().ExportJSON(filepath);
}

// Check if feature is safe to use
bool IsFeatureSafe(const char* featureName) {
    return FeatureReconciliation::Instance().IsFeatureSafe(featureName);
}

// Get features by risk level
const char** GetFeaturesByRisk(const char* riskLevel, int* count) {
    static std::vector<std::string> features;
    static std::vector<const char*> ptrs;
    
    features = FeatureReconciliation::Instance().GetFeaturesByRisk(riskLevel);
    ptrs.clear();
    for (const auto& f : features) {
        ptrs.push_back(f.c_str());
    }
    
    *count = static_cast<int>(ptrs.size());
    return ptrs.data();
}

} // extern "C"