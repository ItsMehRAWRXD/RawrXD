#pragma once
// ============================================================================
// TensorIdentity.hpp — RAWRXD_SPACELESS_UNMODEL_UNADDRESS_DESIGN_001
//
// The identity represents WHAT tensor is being requested, not WHERE its bytes
// currently happen to reside. This is the first SpaceLess primitive.
//
// Do NOT bake these into the identity:
//   - void*
//   - VirtualAlloc address
//   - mmap/view address
//   - GPU device address
//   - staging-buffer address
//   - current residency location
//   - temporary expanded-F32 address
//
// Those belong in ExecutionView / residency resolution.
//
// Critical invariant:
//   TensorIdentity
//         |
//         v
//   resolve(identity, requested_view)
//         |
//         +--> CPU resident bytes
//         +--> GPU resident bytes
//         +--> streamed/dequantized view
//         +--> temporary execution representation
//   identity remains unchanged
// ============================================================================

#include <cstdint>

namespace Deep2 {

struct TensorIdentity final {
    uint64_t model;       // stable model/content identity
    uint64_t tensor;      // stable tensor identity within model
    uint32_t layer;
    uint16_t role;
    uint16_t variant;

    constexpr bool operator==(const TensorIdentity&) const noexcept = default;

    // Hash suitable for unordered_map keys
    size_t hash() const noexcept {
        // FNV-1a 64-bit folded to size_t
        uint64_t h = 14695981039346656037ull;
        auto mix = [&](uint64_t v) {
            for (size_t i = 0; i < 8; ++i) {
                h ^= (v >> (i * 8)) & 0xFF;
                h *= 1099511628211ull;
            }
        };
        mix(model);
        mix(tensor);
        mix(static_cast<uint64_t>(layer));
        mix(static_cast<uint64_t>(role) | (static_cast<uint64_t>(variant) << 16));
        return static_cast<size_t>(h);
    }
};

} // namespace Deep2
