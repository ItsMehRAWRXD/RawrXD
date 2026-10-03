#pragma once
// ============================================================================
// ExecutionView.hpp — RAWRXD_SPACELESS_UNMODEL_UNADDRESS_DESIGN_001
//
// An ExecutionView is a BORROWED, EPHEMERAL view of tensor bytes that are
// physically resident SOMEWHERE (CPU RAM, GPU VRAM, mmap, staging buffer,
// dequantized temporary, etc.). It does NOT own the bytes. It does NOT
// describe how the bytes got there. It only says:
//
//   "For the duration of this execution, here is the address and extent
//    of tensor bytes you requested."
//
// The identity (TensorIdentity) is stable. The view (ExecutionView) is
// borrowed. The identity does not change when residency changes.
//
// Invariant:
//   resolve(identity) → ExecutionView → kernel(ExecutionView) → output
//   identity remains unchanged across every residency transition
// ============================================================================

#include "TensorIdentity.hpp"
#include <cstddef>
#include <cstdint>

namespace Deep2 {

struct LeaseToken {
    uint64_t generation = 0;   // bumped on every residency change
    uint64_t owner      = 0;   // opaque pool/arena id
    uint32_t epoch      = 0;   // sequence within generation (for ordering)

    bool operator==(const LeaseToken& o) const noexcept {
        return generation == o.generation && owner == o.owner && epoch == o.epoch;
    }
    bool operator!=(const LeaseToken& o) const noexcept { return !(*this == o); }
};

struct ExecutionView final {
    TensorIdentity identity;       // stable tensor identity (what)
    void*          transientAddress = nullptr; // ephemeral bytes (where, NOW)
    size_t         bytes            = 0;
    LeaseToken     lease;          // borrow proof — view valid only while lease holds

    // Convenience: is this view currently carrying bytes?
    bool hasBytes() const noexcept { return transientAddress != nullptr && bytes > 0; }

    // Convenience: typed access (caller must know the type; view does not)
    template<typename T>
    const T* as() const noexcept { return static_cast<const T*>(transientAddress); }

    template<typename T>
    T* asMutable() noexcept { return static_cast<T*>(transientAddress); }
};

} // namespace Deep2
