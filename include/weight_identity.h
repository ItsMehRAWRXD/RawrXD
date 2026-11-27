#pragma once
// RAWRXD NP-05A: device-independent resident-weight identity.
//
// Pure, Vulkan-free identity used by BOTH the production residency cache
// (VulkanCompute::EnsureQuantWeight) and CPU regression tests, so tests exercise
// the actual production identity rule rather than a duplicated test-only copy.
//
// A weight's identity is host-pointer-independent: it is derived from the active
// model id plus the weight CONTENT (first 8 bytes) and geometry/format. Two
// requests for the same content at different host addresses therefore produce the
// SAME Key, and a changed content (revision) or different model produces a
// DIFFERENT Key.
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace RawrXD {
namespace Deep2 {
namespace WeightIdentity {

struct Key {
    uint64_t model_id = 0;
    uint64_t fingerprint = 0;  // first min(8,bytes) source bytes
    size_t   bytes = 0;        // tensor geometry (byte count)
    int      kind = -1;        // quantization format
};

// Content fingerprint: first min(8,bytes) bytes of the packed weight.
inline uint64_t Fingerprint(const void* packed, size_t bytes) {
    uint64_t fp = 0;
    if (packed && bytes) std::memcpy(&fp, packed, sizeof(fp) < bytes ? sizeof(fp) : bytes);
    return fp;
}

// Build the identity for a weight request. `model_id` is the request-scoped model
// identity (0 when unknown); the rest is content/geometry/format.
inline Key Make(uint64_t model_id, const void* packed, size_t bytes, int kind) {
    Key k;
    k.model_id = model_id;
    k.fingerprint = Fingerprint(packed, bytes);
    k.bytes = bytes;
    k.kind = kind;
    return k;
}

// True when two identities refer to the same resident weight. A relocated host
// pointer with identical content/geometry/format/model matches; a changed revision
// (different fingerprint), a different model, or different geometry/format does not.
inline bool Matches(const Key& a, const Key& b) {
    return a.model_id == b.model_id && a.fingerprint == b.fingerprint &&
           a.bytes == b.bytes && a.kind == b.kind;
}

}  // namespace WeightIdentity
}  // namespace Deep2
}  // namespace RawrXD