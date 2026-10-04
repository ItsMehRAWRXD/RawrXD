#pragma once
// ============================================================================
// ReverseLayer.hpp — RAWRXD_COMPUTE_ENTRY_AUDIT_001 / RAWRXD_REVERSE_001
//
// THE REVERSE LAYER.
//
// Direction: OUTSIDE -> INSIDE.
//
// It accepts a semantic KernelIntent (a statement of what computation must
// remain true) and produces a NanoAddress: an execution request that names
// HOW the bytes can be recovered and WHAT current reality permits, while
// carrying NO physical address outward.
//
// Hard law, enforced by construction:
//
//   NANOADDRESS_CONTAINS_PHYSICAL_ADDRESS = 0
//
// ExecutionView still exists and still carries `transientAddress`, but that
// struct is the INSIDE-side realization produced by the resolver and consumed
// by the kernel. It is never reachable from KernelIntent, never stored in
// NanoAddress, and never handed back out of this layer.
//
// Companion direction lives in HeartbeatPublisher: INSIDE -> OUTSIDE, and it
// exports FACTS (bytes available, device reachable, generation), never
// pointers.
//
// NOT a duplicate of Beaconism.hpp: that file is a causal EVENT LOG
// (BeaconEvent::GPU_SUBMIT, TOKEN_LAYER_BEGIN, ...). This file publishes
// RESIDENCY/HARDWARE STATE. They are complementary, not substitutes.
// NOT a duplicate of ReverseIntegration.hpp: that file is a 3-line stub whose
// attach/validate/activate all `return true` with zero measurement and zero
// callers. It is reported, not built upon.
// ============================================================================

#include "TensorIdentity.hpp"
#include "ExecutionView.hpp"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {

// ---------------------------------------------------------------------------
// KernelIntent — the semantic requirement, stated with no device and no address
// ---------------------------------------------------------------------------
enum class Operation : uint8_t {
    MatrixVector = 0,
    RoPE        = 1,
    RMSNorm     = 2,
    Attention   = 3,
    SwiGLU      = 4,
    Softmax     = 5,
    CacheRead   = 6,
    CacheWrite  = 7,
};

enum class RepresentationKind : uint8_t {
    Quantized = 0,
    F32      = 1,
    F16      = 2,
    BF16     = 3,
};

struct RepresentationClass {
    RepresentationKind kind = RepresentationKind::Quantized;
    uint32_t           quantType = 0;  // GGML type id when quantized
};

struct NumericContract {
    // Exact semantics required. "Deep2_Q4_K_GEMV" is a DIFFERENT kernel from
    // "Deep2_F32_GEMV" even though both compute y = W x. The contract name is
    // part of the identity, so a generated form for one may never satisfy the
    // other.
    std::string contractName;
    uint64_t    contractHash = 0;
};

struct KernelIdentity {
    Operation           operation   = Operation::MatrixVector;
    NumericContract     contract;
    RepresentationClass representation;
    TensorIdentity      weight;      // WHICH tensor (not where)

    bool operator==(const KernelIdentity&) const noexcept = default;
};

struct ExecutionConstraints {
    bool     forbidGPU          = false;
    bool     requireDualGPU     = false;
    bool     requireResident    = false;
    bool     allowStreaming     = true;
    uint64_t minFreeBytes       = 0;
    uint64_t maxLatencyNs       = 0;
};

// ---------------------------------------------------------------------------
// BackingRef — HOW the identity's bytes can currently be recovered.
// This is the replacement for wt.data in every consumer outside the resolver.
// ---------------------------------------------------------------------------
enum class BackingSource : uint8_t {
    GGUF_MMAP      = 0,  // alias into the retained GGUF mapping
    PREPARED_F32   = 1,  // persistent host-side F32 expansion
    GPU_RESIDENT   = 2,  // live device allocation
    STREAMING      = 3,  // would require a transfer
    UNRESOLVED     = 4,  // fail-closed: identity is known, bytes are not
};

struct BackingRef {
    BackingSource source = BackingSource::UNRESOLVED;

    // --- GGUF_MMAP provenance, populated from the real binder ---
    uint32_t  shardId        = 0;
    uint64_t  fileOffset     = 0;
    uint64_t  byteLength     = 0;
    uint32_t  quantType      = 0;
    uint64_t  rows           = 0;
    uint64_t  cols           = 0;
    std::string tensorName;

    // --- PREPARED_F32 ---
    uint64_t  preparedKey    = 0;
    bool      preparedValid  = false;

    // --- GPU_RESIDENT ---
    uint32_t  deviceId       = 0;
    uint64_t  allocationId   = 0;

    // --- ephemeral residency facts; NOT part of identity ---
    uint64_t  generation     = 0;
    uint64_t  freeBytesOnDevice = 0;

    // True only when the bytes are addressable RIGHT NOW without movement.
    bool immediatelyAddressable() const noexcept {
        return source == BackingSource::GGUF_MMAP ||
               source == BackingSource::PREPARED_F32 ||
               source == BackingSource::GPU_RESIDENT;
    }
};

// ---------------------------------------------------------------------------
// BackingDirectory — identity -> BackingRef, populated from the REAL binder.
// ---------------------------------------------------------------------------
class BackingDirectory {
public:
    static BackingDirectory& Instance();

    // Called by the loader at the exact site where a WeightTensor is bound.
    // shardId/fileOffset/byteLength/quantType are read from the WeightTensor,
    // which the loader populated from the real GGUFTensor. Nothing is inferred.
    void registerBinding(const TensorIdentity& id, const BackingRef& ref);

    std::optional<BackingRef> lookup(const TensorIdentity& id) const;

    // Prepared-F32 availability is a RUNTIME fact and changes; it is registered
    // separately so it can be invalidated without touching identity.
    void markPrepared(const TensorIdentity& id, uint64_t preparedKey);
    void clearPrepared(const TensorIdentity& id);

    size_t size() const;
    size_t preparedCount() const;

    // Monotonic generation. Bumped on any residency-relevant change. A
    // generated KernelForm is stale when its beaconGeneration differs.
    uint64_t generation() const;
    void     bumpGeneration();

    void clear();

private:
    BackingDirectory() = default;
    mutable std::mutex mtx_;
    std::unordered_map<uint64_t, BackingRef> refs_;
    std::unordered_map<uint64_t, uint64_t>    prepared_;
    uint64_t generation_ = 1;
};

// ---------------------------------------------------------------------------
// Heartbeat — INSIDE reality, exported as facts only.
// BEACON_CONTAINS_PHYSICAL_POINTER = 0: no field here is a pointer.
// ---------------------------------------------------------------------------
struct DeviceBeacon {
    uint32_t    deviceId   = 0;
    std::string name;
    uint64_t    totalBytes = 0;
    uint64_t    freeBytes  = 0;
    bool        peerReachable = false;
    uint64_t    generation = 0;
};

struct CpuBeacon {
    bool     avx2    = false;
    bool     avx512f = false;
    bool     fma     = false;
    bool     f16c    = false;
    uint64_t generation = 0;
};

struct Heartbeat {
    uint64_t               generation = 0;
    CpuBeacon              cpu;
    std::vector<DeviceBeacon> devices;

    bool     hasGPU()   const noexcept { return !devices.empty(); }
    bool     hasDualGPU() const noexcept { return devices.size() >= 2; }
    uint64_t freeBytes() const noexcept;
    const DeviceBeacon* device(uint32_t id) const noexcept;
};

// Real hardware truth. Populated from CPUID via QuantKernelRegistry::ProbeCPU
// state and from live VulkanCompute slots. Absent hardware is reported as
// absent, never as a positive.
Heartbeat publishHeartbeat();

// Device registration, called from the engine at real residency transitions.
// publishDevice() must be given numbers Vulkan actually reported.
// withdrawDevice() is called when a device is lost. A machine with no
// published device publishes ZERO devices, which makes every GPU form
// unreachable — the fail-closed direction.
void        publishDevice(const DeviceBeacon& b);
void        withdrawDevice(uint32_t deviceId);
void        withdrawAllDevices();

const char* deviceCountUnavailableReason(bool vulkanInitialized,
                                          size_t deviceCount,
                                          bool strictNoCpuFallback);

// ---------------------------------------------------------------------------
// NanoAddress — the REVERSE output. Contains NO physical address.
// ---------------------------------------------------------------------------
struct NanoAddress {
    KernelIdentity       identity;
    ExecutionConstraints constraints;
    BackingRef           backing;
    Heartbeat            heartbeat;     // snapshot used for form selection
    uint64_t             formGeneration = 0;
    uint32_t             leaseGeneration = 0;
    uint64_t             leaseOwner      = 0;
};

// ---------------------------------------------------------------------------
// PrimitiveGraph — semantic decomposition. Addressless by construction.
// ---------------------------------------------------------------------------
enum class PrimitiveOp : uint8_t {
    LOAD_BLOCK = 0,
    DEQUANT    = 1,
    DOT        = 2,
    ACCUMULATE = 3,
    STORE      = 4,
    ACTIVATE   = 5,
    ROPE       = 6,
    RMSNORM    = 7,
    SOFTMAX    = 8,
};

struct PrimitiveNode {
    PrimitiveOp   op = PrimitiveOp::DOT;
    uint32_t      blockElements = 0;
    uint32_t      blockBytes    = 0;
    uint32_t      quantType     = 0;
    float         eps           = 0.0f;
    float         theta         = 0.0f;
    float         scaling       = 1.0f;
};

struct PrimitiveGraph {
    std::vector<PrimitiveNode> nodes;
    uint32_t entry = 0;
    uint32_t exit  = 0;
};

// ---------------------------------------------------------------------------
// BackendForm — one semantic kernel, many generated forms.
// ---------------------------------------------------------------------------
enum class BackendForm : uint8_t {
    CPU_AVX2        = 0,
    CPU_AVX512      = 1,
    CPU_SCALAR      = 2,
    VULKAN_SINGLE   = 3,
    VULKAN_DUAL_ROW = 4,
    VULKAN_RESIDENT = 5,
    NONE_AVAILABLE  = 6,   // fail-closed: reality permits no form
};

const char* backendFormName(BackendForm f);

// ---------------------------------------------------------------------------
// ReverseLayer
// ---------------------------------------------------------------------------
class ReverseLayer {
public:
    // OUTSIDE -> INSIDE. Returns nullopt when identity is unknown OR when
    // reality permits no legal form. It never returns a degraded address.
    static std::optional<NanoAddress> resolve(
        const KernelIdentity& intent,
        const ExecutionConstraints& constraints,
        const Heartbeat& hb);

    static std::optional<BackingRef> resolveBacking(const TensorIdentity& id);

    static PrimitiveGraph decompose(const KernelIdentity& intent);

    static BackendForm selectForm(const KernelIdentity& intent,
                                  const BackingRef& backing,
                                  const Heartbeat& hb,
                                  const ExecutionConstraints& c);

    // Counters are for the receipt, not for a verdict.
    struct Stats {
        uint64_t resolveCalls        = 0;
        uint64_t resolveIdentityMiss = 0;
        uint64_t resolveNoForm       = 0;
        uint64_t resolveSucceeded    = 0;
        uint64_t forms[7]            = {0,0,0,0,0,0,0};
    };
    static Stats statsSnapshot();
    static void  statsReset();
};

// ---------------------------------------------------------------------------
// TensorIdentity hashing for directory keys, and name hashing for provenance.
// Both are over BYTES AND IDS ONLY. Neither may ever be handed a pointer:
// hashing an address would make identity change when the mapping moves, which
// is the exact failure this layer exists to prevent.
// ---------------------------------------------------------------------------
uint64_t hashIdentity(const TensorIdentity& id) noexcept;
uint64_t fnv1a64Bytes(const void* data, size_t n) noexcept;
inline uint64_t fnv1a64Name(const char* p, size_t n) noexcept {
    return fnv1a64Bytes(p, n);
}

} // namespace Deep2
