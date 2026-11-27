// ReapDescriptorBind.hpp — RAWRXD S03.6H (descriptor binding source)
// Builds a validated descriptor-binding request for a transformed expert buffer:
// binds (binding, range) to the PR-06 identity, validating geometry. Rejects
// incomplete/incompatible bindings. The engine applies it to a real descriptor.
// Storage-independent; no RNG; fail-closed.
#pragma once
#include <cstdint>

namespace RawrXD::Reap {

struct DescriptorBinding {
    bool     valid = false;
    uint64_t identity = 0;
    uint32_t binding = 0;
    uint64_t range = 0;
    uint64_t expertBytes = 0;
};

// Bind a transformed buffer [offset, offset+expertBytes) to a descriptor slot.
inline DescriptorBinding BindTransformed(uint64_t identity, uint32_t binding,
                                         uint64_t offset, uint64_t expertBytes,
                        bool selectionValid, uint64_t bufferSize) {
    DescriptorBinding b;
    b.identity = identity; b.binding = binding; b.expertBytes = expertBytes;
    if (!selectionValid || expertBytes == 0) return b;          // invalid selection: fail closed
    if (offset > bufferSize || expertBytes > bufferSize - offset) return b;   // out of range
    b.range = expertBytes; b.valid = true; return b;
}

} // namespace RawrXD::Reap