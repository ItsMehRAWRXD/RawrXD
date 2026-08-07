// ============================================================================
// Blocker #30: Quant Kernel Registry Dequant Initialization Hooks
// Fixes QuantKernelRegistry dequant initialization to properly register
// all quant type handlers at startup, preventing null pointer dereferences.
// ============================================================================
#pragma once
#include <cstdint>
#include <functional>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace Deep2 {

// Dequant function signature: (input_quant, output_fp32, num_elements)
using DequantFunc = std::function<void(const void*, float*, size_t)>;
using GEMVFunc = std::function<void(const uint8_t*, const float*, float*, size_t, size_t)>;

class QuantKernelRegistryHooks {
public:
    static QuantKernelRegistryHooks& Instance() {
        static QuantKernelRegistryHooks instance;
        return instance;
    }

    // Register a dequant handler for a specific GGML type
    void RegisterDequant(int ggmlType, DequantFunc func) {
        std::lock_guard<std::mutex> lock(mutex_);
        dequantTable_[ggmlType] = func;
    }

    // Register a GEMV handler for a specific GGML type
    void RegisterGEMV(int ggmlType, GEMVFunc func) {
        std::lock_guard<std::mutex> lock(mutex_);
        gemvTable_[ggmlType] = func;
    }

    // Get dequant handler (returns nullptr if not registered)
    DequantFunc GetDequant(int ggmlType) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = dequantTable_.find(ggmlType);
        if (it != dequantTable_.end()) return it->second;
        return nullptr;
    }

    // Get GEMV handler (returns nullptr if not registered)
    GEMVFunc GetGEMV(int ggmlType) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = gemvTable_.find(ggmlType);
        if (it != gemvTable_.end()) return it->second;
        return nullptr;
    }

    // Check if a quant type is supported
    bool IsSupported(int ggmlType) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dequantTable_.find(ggmlType) != dequantTable_.end() ||
               gemvTable_.find(ggmlType) != gemvTable_.end();
    }

    // Get list of supported types
    std::vector<int> GetSupportedTypes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<int> types;
        for (const auto& pair : dequantTable_) {
            types.push_back(pair.first);
        }
        return types;
    }

    // Initialize all built-in handlers (call once at startup)
    void InitializeBuiltins();

    // Get number of registered handlers
    size_t GetDequantCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return dequantTable_.size();
    }

    size_t GetGEMVCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return gemvTable_.size();
    }

private:
    QuantKernelRegistryHooks() {}
    ~QuantKernelRegistryHooks() {}
    
    mutable std::mutex mutex_;
    std::unordered_map<int, DequantFunc> dequantTable_;
    std::unordered_map<int, GEMVFunc> gemvTable_;
};

} // namespace Deep2
