// Phase I.3/5: Memory Layout Optimization
// Optimizes tensor memory layout for cache efficiency and bandwidth utilization

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Optimization {

// ============================================================================
// Memory Layout Types
// ============================================================================

/// Tensor memory layout formats
enum class MemoryLayout : uint8_t {
    ROW_MAJOR = 0,           // Standard row-major (C-style)
    COLUMN_MAJOR = 1,      // Column-major (Fortran-style)
    TILED = 2,             // Tiled for cache efficiency
    SWIZZLED = 3,          // Swizzled for bank conflict avoidance
    NHWC = 4,              // NHWC for convolutions
    NCHW = 5,              // NCHW for convolutions
    CUSTOM = 255
};

/// Memory access pattern
enum class AccessPattern : uint8_t {
    SEQUENTIAL = 0,        // Sequential access
    STRIDED = 1,          // Strided access
    RANDOM = 2,           // Random access
    BLOCKED = 3           // Blocked access
};

/// Layout optimization configuration
struct LayoutConfig {
    MemoryLayout target_layout = MemoryLayout::TILED;
    uint32_t tile_size_x = 32;
    uint32_t tile_size_y = 32;
    uint32_t alignment = 256;      // Byte alignment
    bool pad_for_bank_conflict = true;
    bool prefetch_enabled = true;
    uint32_t prefetch_distance = 4;
};

/// Memory layout metrics
struct LayoutMetrics {
    size_t original_size_bytes;
    size_t optimized_size_bytes;
    double size_overhead_percent;
    double cache_hit_rate;
    double bandwidth_utilization_percent;
    double speedup_vs_original;
};

// ============================================================================
// Tensor Descriptor
// ============================================================================

/// Describes tensor shape and layout
struct TensorDescriptor {
    std::vector<size_t> dimensions;
    MemoryLayout current_layout;
    size_t element_size;             // Bytes per element
    size_t stride_bytes;             // Stride between elements
    
    size_t GetNumElements() const {
        size_t num = 1;
        for (auto dim : dimensions) num *= dim;
        return num;
    }
    
    size_t GetSizeBytes() const {
        return GetNumElements() * element_size;
    }
};

// ============================================================================
// Memory Layout Optimizer
// ============================================================================

/// Optimizes tensor memory layouts
class MemoryLayoutOptimizer {
public:
    MemoryLayoutOptimizer();
    ~MemoryLayoutOptimizer();

    /// Initialize optimizer
    bool Initialize();

    /// Shutdown
    void Shutdown();

    /// Analyze tensor access pattern
    bool AnalyzeAccessPattern(const TensorDescriptor& tensor,
                               const std::vector<AccessPattern>& access_history,
                               MemoryLayout* recommended_layout) const;

    /// Convert tensor to optimized layout
    bool ConvertLayout(const void* input,
                        const TensorDescriptor& input_desc,
                        void* output,
                        const TensorDescriptor& output_desc);

    /// Create tiled layout
    bool CreateTiledLayout(const void* input,
                            const TensorDescriptor& desc,
                            void* output,
                            uint32_t tile_x,
                            uint32_t tile_y);

    /// Create swizzled layout (bank conflict avoidance)
    bool CreateSwizzledLayout(const void* input,
                               const TensorDescriptor& desc,
                               void* output,
                               uint32_t swizzle_bits);

    /// Calculate optimal padding
    bool CalculatePadding(const TensorDescriptor& desc,
                          uint32_t alignment,
                          size_t* padded_size) const;

    /// Get layout metrics
    bool GetLayoutMetrics(const TensorDescriptor& original,
                          const TensorDescriptor& optimized,
                          LayoutMetrics* metrics) const;

    /// Enable/disable layout optimization
    void SetOptimizationEnabled(bool enabled);

    /// Check if optimization is enabled
    bool IsOptimizationEnabled() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Prefetch Controller
// ============================================================================

/// Manages memory prefetching
class PrefetchController {
public:
    PrefetchController();
    ~PrefetchController();

    /// Initialize controller
    bool Initialize();

    /// Prefetch memory region
    bool Prefetch(const void* addr, size_t length);

    /// Set prefetch distance
    void SetPrefetchDistance(uint32_t distance);

    /// Get prefetch distance
    uint32_t GetPrefetchDistance() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert layout to string
const char* MemoryLayoutToString(MemoryLayout layout);

/// Calculate linear index from multi-dimensional indices
size_t CalculateLinearIndex(const std::vector<size_t>& indices,
                             const std::vector<size_t>& dimensions,
                             MemoryLayout layout);

/// Check if layout conversion is beneficial
bool IsLayoutConversionBeneficial(const TensorDescriptor& source,
                                   const TensorDescriptor& target,
                                   const std::vector<AccessPattern>& expected_access);

/// Estimate cache efficiency
double EstimateCacheEfficiency(const TensorDescriptor& desc,
                                const std::vector<AccessPattern>& access_pattern);

} // namespace Optimization
} // namespace RawrXD
