// ReverseLayer.cpp — RAWRXD_REVERSE_001
// Real implementation. No simulated devices, no invented generations.
//
// Every field written here is either (a) copied from a structure the loader
// really populated, (b) read from real CPUID, or (c) read from a real
// VulkanCompute slot. Nothing is defaulted into a positive.

#include "ReverseLayer.hpp"
#include "QuantKernelRegistry.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Observation counters. These exist so the receipt can report what the layer
// actually did. None of them can produce a verdict: a caller that never calls
// resolve() reads zeros, which is indistinguishable from "nothing was
// attempted", so a receipt built on them must also carry the check results.
// ---------------------------------------------------------------------------
namespace {
std::atomic<uint64_t> g_resolveCalls{0};
std::atomic<uint64_t> g_identityMiss{0};
std::atomic<uint64_t> g_noForm{0};
std::atomic<uint64_t> g_succeeded{0};
std::atomic<uint64_t> g_decomposeBlockOverflow{0};
std::atomic<uint64_t> g_forms[7]{};
} // namespace

uint64_t fnv1a64Bytes(const void* data, size_t n) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

// ---------------------------------------------------------------------------
// Identity hash — FNV-1a 64 over the identity fields.
// Deliberately NOT over any pointer: identity must survive remapping.
// ---------------------------------------------------------------------------
uint64_t hashIdentity(const TensorIdentity& id) noexcept {
    uint64_t h = 14695981039346656037ull;
    auto mix = [&h](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            h ^= static_cast<uint8_t>(v >> (i * 8));
            h *= 1099511628211ull;
        }
    };
    mix(id.model);
    mix(id.tensor);
    mix(static_cast<uint64_t>(id.layer) |
        (static_cast<uint64_t>(id.role)   << 32) |
        (static_cast<uint64_t>(id.variant) << 48));
    return h;
}

// ---------------------------------------------------------------------------
// BackingDirectory
// ---------------------------------------------------------------------------
BackingDirectory& BackingDirectory::Instance() {
    static BackingDirectory d;
    return d;
}

void BackingDirectory::registerBinding(const TensorIdentity& id,
                                       const BackingRef& ref) {
    const uint64_t k = hashIdentity(id);
    std::lock_guard<std::mutex> g(mtx_);
    auto it = refs_.find(k);
    if (it == refs_.end()) {
        refs_.emplace(k, ref);
    } else {
        // Re-registration updates provenance but never the identity key.
        const bool prepared = it->second.preparedValid;
        const uint64_t  pkey = it->second.preparedKey;
        it->second = ref;
        it->second.preparedValid = prepared;
        it->second.preparedKey   = pkey;
    }
    ++generation_;
}

std::optional<BackingRef> BackingDirectory::lookup(const TensorIdentity& id) const {
    const uint64_t k = hashIdentity(id);
    std::lock_guard<std::mutex> g(mtx_);
    auto it = refs_.find(k);
    if (it == refs_.end()) return std::nullopt;
    BackingRef r = it->second;
    auto p = prepared_.find(k);
    if (p != prepared_.end()) {
        r.preparedValid = true;
        r.preparedKey   = p->second;
        // A prepared F32 expansion is the cheapest addressable form when it
        // exists; the mmap provenance is retained so the form is regenerable.
        r.source = BackingSource::PREPARED_F32;
    }
    r.generation = generation_;
    return r;
}

void BackingDirectory::markPrepared(const TensorIdentity& id, uint64_t preparedKey) {
    const uint64_t k = hashIdentity(id);
    std::lock_guard<std::mutex> g(mtx_);
    prepared_[k] = preparedKey;
    ++generation_;
}

void BackingDirectory::clearPrepared(const TensorIdentity& id) {
    const uint64_t k = hashIdentity(id);
    std::lock_guard<std::mutex> g(mtx_);
    prepared_.erase(k);
    ++generation_;
}

size_t BackingDirectory::size() const {
    std::lock_guard<std::mutex> g(mtx_);
    return refs_.size();
}

size_t BackingDirectory::preparedCount() const {
    std::lock_guard<std::mutex> g(mtx_);
    return prepared_.size();
}

uint64_t BackingDirectory::generation() const {
    std::lock_guard<std::mutex> g(mtx_);
    return generation_;
}

void BackingDirectory::bumpGeneration() {
    std::lock_guard<std::mutex> g(mtx_);
    ++generation_;
}

void BackingDirectory::clear() {
    std::lock_guard<std::mutex> g(mtx_);
    refs_.clear();
    prepared_.clear();
    ++generation_;
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------
uint64_t Heartbeat::freeBytes() const noexcept {
    uint64_t t = 0;
    for (const auto& d : devices) t += d.freeBytes;
    return t;
}

const DeviceBeacon* Heartbeat::device(uint32_t id) const noexcept {
    for (const auto& d : devices) if (d.deviceId == id) return &d;
    return nullptr;
}

const char* backendFormName(BackendForm f) {
    switch (f) {
        case BackendForm::CPU_AVX2:        return "CPU_AVX2";
        case BackendForm::CPU_AVX512:      return "CPU_AVX512";
        case BackendForm::CPU_SCALAR:      return "CPU_SCALAR";
        case BackendForm::VULKAN_SINGLE:   return "VULKAN_SINGLE";
        case BackendForm::VULKAN_DUAL_ROW: return "VULKAN_DUAL_ROW";
        case BackendForm::VULKAN_RESIDENT: return "VULKAN_RESIDENT";
        case BackendForm::NONE_AVAILABLE:  return "NONE_AVAILABLE";
    }
    return "UNKNOWN";
}

const char* deviceCountUnavailableReason(bool vulkanInitialized,
                                          size_t deviceCount,
                                          bool strictNoCpuFallback) {
    if (!vulkanInitialized) return "VULKAN_NOT_INITIALIZED";
    if (deviceCount == 0)    return "ZERO_DEVICES";
    if (deviceCount < 2)     return "SINGLE_DEVICE_NO_PEER";
    (void)strictNoCpuFallback;
    return "NONE";
}

// ---------------------------------------------------------------------------
// ReverseLayer::decompose — pure semantic lowering, no device, no address.
// ---------------------------------------------------------------------------
PrimitiveGraph ReverseLayer::decompose(const KernelIdentity& intent) {
    PrimitiveGraph g;
    switch (intent.operation) {
    case Operation::MatrixVector: {
        const uint32_t qt = intent.representation.quantType;
        // Block geometry is read from the SAME descriptor table LinearW uses
        // (packedBytesRequired -> LookupQuantType), so the graph cannot claim a
        // block shape the production kernel would not accept.
        PrimitiveNode load;
        load.op = PrimitiveOp::LOAD_BLOCK;
        load.quantType = qt;
        if (const auto* d = LookupQuantType(qt)) {
            // Explicit narrowing, with saturation rather than silent truncation:
            // a block geometry that does not fit in uint32_t is a geometry the
            // generated kernel could not address correctly, so it must fail
            // closed here rather than wrap into a plausible wrong number.
            if (d->blockBytes    > 0xFFFFFFFFu ||
                d->blockElements > 0xFFFFFFFFu) {
                g_decomposeBlockOverflow++;
                break;
            }
            load.blockBytes    = static_cast<uint32_t>(d->blockBytes);
            load.blockElements = static_cast<uint32_t>(d->blockElements);
        }
        PrimitiveNode deq; deq.op = PrimitiveOp::DEQUANT; deq.quantType = qt;
        PrimitiveNode dot; dot.op = PrimitiveOp::DOT;
        PrimitiveNode acc; acc.op = PrimitiveOp::ACCUMULATE;
        PrimitiveNode st;  st.op  = PrimitiveOp::STORE;
        g.nodes = {load, deq, dot, acc, st};
        g.entry = 0; g.exit = 4;
        break;
    }
    case Operation::RMSNorm: {
        PrimitiveNode n; n.op = PrimitiveOp::RMSNORM; n.eps = 1e-5f;
        PrimitiveNode s; s.op = PrimitiveOp::STORE;
        g.nodes = {n, s};
        g.entry = 0; g.exit = 1;
        break;
    }
    case Operation::RoPE: {
        PrimitiveNode r; r.op = PrimitiveOp::ROPE; r.theta = 10000.0f;
        PrimitiveNode s; s.op = PrimitiveOp::STORE;
        g.nodes = {r, s};
        g.entry = 0; g.exit = 1;
        break;
    }
    case Operation::SwiGLU: {
        PrimitiveNode d; d.op = PrimitiveOp::DOT;
        PrimitiveNode a; a.op = PrimitiveOp::ACTIVATE;
        PrimitiveNode s; s.op = PrimitiveOp::STORE;
        g.nodes = {d, a, s};
        g.entry = 0; g.exit = 2;
        break;
    }
    case Operation::Attention: {
        PrimitiveNode d; d.op = PrimitiveOp::DOT;
        PrimitiveNode m; m.op = PrimitiveOp::SOFTMAX;
        PrimitiveNode s; s.op = PrimitiveOp::STORE;
        g.nodes = {d, m, s};
        g.entry = 0; g.exit = 2;
        break;
    }
    case Operation::Softmax:
    case Operation::CacheRead:
    case Operation::CacheWrite:
    default: {
        PrimitiveNode s; s.op = PrimitiveOp::STORE;
        g.nodes = {s};
        g.entry = 0; g.exit = 0;
        break;
    }
    }
    return g;
}

// ---------------------------------------------------------------------------
// ReverseLayer::resolveBacking
// ---------------------------------------------------------------------------
std::optional<BackingRef> ReverseLayer::resolveBacking(const TensorIdentity& id) {
    return BackingDirectory::Instance().lookup(id);
}

// ---------------------------------------------------------------------------
// ReverseLayer::selectForm — reality decides. No form is invented.
// ---------------------------------------------------------------------------
BackendForm ReverseLayer::selectForm(const KernelIdentity& intent,
                                      const BackingRef& backing,
                                      const Heartbeat& hb,
                                      const ExecutionConstraints& c) {
    // A form that cannot address bytes now is not selectable, regardless of
    // how attractive the device looks.
    const bool bytesReady = backing.immediatelyAddressable();

    // ---- GPU forms, gated on REAL device presence ----
    if (!c.forbidGPU && hb.hasGPU() && bytesReady) {
        const bool needsPacked = intent.representation.kind == RepresentationKind::Quantized;
        if (c.requireDualGPU) {
            if (!hb.hasDualGPU()) return BackendForm::NONE_AVAILABLE;
            if (hb.freeBytes() < c.minFreeBytes) return BackendForm::NONE_AVAILABLE;
            return BackendForm::VULKAN_DUAL_ROW;
        }
        if (c.requireResident) {
            if (hb.freeBytes() < backing.byteLength + c.minFreeBytes)
                return BackendForm::NONE_AVAILABLE;
            return BackendForm::VULKAN_RESIDENT;
        }
        if (needsPacked) {
            // A packed weight can be dispatched without an F32 expansion only
            // on the packed-device path. A prepared F32 also makes the dense
            // path legal; absence of preparation does NOT forbid single GPU.
            return BackendForm::VULKAN_SINGLE;
        }
        return BackendForm::VULKAN_SINGLE;
    }
    if (c.requireDualGPU || c.requireResident) return BackendForm::NONE_AVAILABLE;

    // ---- CPU forms, gated on REAL CPUID ----
    if (!bytesReady) return BackendForm::NONE_AVAILABLE;
    if (hb.cpu.avx512f) return BackendForm::CPU_AVX512;
    if (hb.cpu.avx2)    return BackendForm::CPU_AVX2;
    return BackendForm::CPU_SCALAR;
}

// ---------------------------------------------------------------------------
// ReverseLayer::resolve
// ---------------------------------------------------------------------------
std::optional<NanoAddress> ReverseLayer::resolve(
    const KernelIdentity& intent,
    const ExecutionConstraints& constraints,
    const Heartbeat& hb) {

    ++g_resolveCalls;

    auto backing = resolveBacking(intent.weight);
    if (!backing) {
        ++g_identityMiss;
        return std::nullopt;   // fail closed: unknown identity
    }

    const BackendForm form = selectForm(intent, *backing, hb, constraints);
    if (form == BackendForm::NONE_AVAILABLE) {
        ++g_noForm;
        return std::nullopt;   // fail closed: reality permits nothing legal
    }

    NanoAddress na;
    na.identity           = intent;
    na.constraints         = constraints;
    na.backing             = *backing;
    na.heartbeat           = hb;
    na.formGeneration      = hb.generation;
    na.leaseGeneration     = static_cast<uint32_t>(backing->generation);
    na.leaseOwner          = 0;   // the INSIDE resolver owns realization
    ++g_forms[static_cast<int>(form)];
    ++g_succeeded;
    return na;
}

ReverseLayer::Stats ReverseLayer::statsSnapshot() {
    Stats s;
    s.resolveCalls        = g_resolveCalls.load();
    s.resolveIdentityMiss = g_identityMiss.load();
    s.resolveNoForm       = g_noForm.load();
    s.resolveSucceeded    = g_succeeded.load();
    for (int i = 0; i < 7; ++i) s.forms[i] = g_forms[i].load();
    return s;
}

void ReverseLayer::statsReset() {
    g_resolveCalls = 0; g_identityMiss = 0; g_noForm = 0; g_succeeded = 0;
    for (int i = 0; i < 7; ++i) g_forms[i] = 0;
}

} // namespace Deep2
