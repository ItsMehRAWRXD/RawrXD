#pragma once
// rawrxd_uncoherent_fabric.hpp
//
// Coherence-indifferent tensor fabric for discrete CPU/GPU memory domains.
// No CUDA/Vulkan dependency: the backend is supplied through function pointers.
//
// Core rule:
//   logical object identity + generation + lease are authoritative;
//   physical addresses are only replica payload.
//
// Four authoritative types only:
//   TensorObject / Replica / Lease / NodeObject
// Former UCF-001..014 collapse into those — not a 14-rule protocol.
//
// C++20, standard library only.

#include <atomic>
#include <cstdint>

namespace rawrxd::ucf {

using u8  = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

static constexpr u32 kMaxNodes    = 16;
static constexpr u32 kMaxReplicas = 16;

enum class Error : u32 {
    Ok = 0,
    BadArgument,
    NoNode,
    NoHostNode,
    NoReplicaSlot,
    NoCurrentReplica,
    AllocationFailed,
    CopyFailed,
    DispatchFailed,
    GenerationMismatch,
    WriterBusy,
    LeaseBusy,
    CapabilityMismatch
};

enum class NodeKind : u8 {
    Host,
    Gpu,
    Uma,
    Storage
};

enum Access : u32 {
    Read  = 1u << 0,
    Write = 1u << 1,
    RW    = Read | Write
};

enum Capability : u64 {
    CapCompute      = 1ull << 0,
    CapDeviceMemory = 1ull << 1,
    CapHostMemory   = 1ull << 2,
    CapAsyncCopy    = 1ull << 3,
    CapDirectPeer   = 1ull << 4
};

struct PhysicalBlock {
    // Opaque backend-owned allocation token. Never a tensor identity.
    std::uintptr_t handle = 0;
    u64 bytes = 0;

    explicit operator bool() const noexcept { return handle != 0; }
};

struct Fence {
    // Opaque backend fence/timeline value.
    u64 value = 0;
};

struct Node;

using AllocFn = Error (*)(
    Node& node,
    u64 bytes,
    PhysicalBlock& out) noexcept;

using FreeFn = void (*)(
    Node& node,
    PhysicalBlock block) noexcept;

using CopyFn = Error (*)(
    Node& dstNode,
    PhysicalBlock dst,
    const Node& srcNode,
    PhysicalBlock src,
    u64 bytes,
    Fence& outFence) noexcept;

using WaitFn = Error (*)(
    Node& node,
    Fence fence) noexcept;

using DispatchFn = Error (*)(
    Node& node,
    PhysicalBlock weights,
    PhysicalBlock input,
    PhysicalBlock output,
    void* user,
    Fence& outFence) noexcept;

struct NodeBackend {
    AllocFn alloc = nullptr;
    FreeFn free = nullptr;
    CopyFn copy = nullptr;
    WaitFn wait = nullptr;
    DispatchFn dispatch = nullptr;
};

struct Node {
    // Stable fabric object identity, unrelated to CUDA/Vulkan adapter index.
    u64 objectId = 0;
    NodeKind kind = NodeKind::Gpu;
    u64 capabilities = 0;

    u64 capacityBytes = 0;
    u64 usableBytes = 0;

    // Measured values, not vendor assumptions.
    u64 readBytesPerSec = 0;
    u64 writeBytesPerSec = 0;
    u64 computeScore = 0;

    NodeBackend backend{};
    void* backendState = nullptr;
};

struct Replica {
    Node* node = nullptr;
    PhysicalBlock block{};

    // A replica is current iff replica.generation == Tensor::generation().
    u64 generation = 0;

    std::atomic<u32> leases{0};
    std::atomic<u8> evicting{0};

    Fence ready{};
    u8 present = 0;
};

struct Tensor {
    // Authoritative logical identity.
    u64 objectId = 0;
    u64 bytes = 0;

    // Published committed generation.
    std::atomic<u64> committedGeneration{1};

    // Single writer reservation. Readers may coexist.
    std::atomic<u8> writerReserved{0};

    Replica replicas[kMaxReplicas]{};

    u64 generation() const noexcept {
        return committedGeneration.load(std::memory_order_acquire);
    }
};

struct Lease {
    Tensor* tensor = nullptr;
    Replica* replica = nullptr;
    Node* node = nullptr;

    u64 expectedGeneration = 0;
    u64 writeGeneration = 0;

    u32 access = 0;
    u8 active = 0;

    PhysicalBlock physical() const noexcept {
        return replica ? replica->block : PhysicalBlock{};
    }
};

struct Fabric {
    Node* nodes[kMaxNodes]{};
    u32 nodeCount = 0;

    Node* host = nullptr;

    // Object-list cursor only; never a physical GPU adapter/index contract.
    std::atomic<u32> bounceCursor{0};

    Error attach(Node& node) noexcept {
        if (nodeCount >= kMaxNodes) return Error::NoNode;
        nodes[nodeCount++] = &node;
        if (!host && (node.kind == NodeKind::Host || node.kind == NodeKind::Uma))
            host = &node;
        return Error::Ok;
    }

    Node* find_node(u64 objectId) const noexcept {
        for (u32 i = 0; i < nodeCount; ++i)
            if (nodes[i] && nodes[i]->objectId == objectId)
                return nodes[i];
        return nullptr;
    }

    Node* next_compute_node(Node* avoid = nullptr) noexcept {
        if (!nodeCount) return nullptr;

        const u32 start = bounceCursor.fetch_add(1, std::memory_order_relaxed);
        for (u32 n = 0; n < nodeCount; ++n) {
            Node* p = nodes[(start + n) % nodeCount];
            if (!p || p == avoid) continue;
            if ((p->capabilities & CapCompute) == 0) continue;
            if (!p->backend.dispatch) continue;
            return p;
        }

        // If only one compute object exists, using it is correct.
        for (u32 n = 0; n < nodeCount; ++n) {
            Node* p = nodes[(start + n) % nodeCount];
            if (!p) continue;
            if ((p->capabilities & CapCompute) && p->backend.dispatch)
                return p;
        }
        return nullptr;
    }
};

inline Replica* find_replica(Tensor& t, Node& node) noexcept {
    for (u32 i = 0; i < kMaxReplicas; ++i)
        if (t.replicas[i].node == &node)
            return &t.replicas[i];
    return nullptr;
}

inline const Replica* find_current_replica(const Tensor& t) noexcept {
    const u64 g = t.generation();
    for (u32 i = 0; i < kMaxReplicas; ++i) {
        const Replica& r = t.replicas[i];
        if (r.present && r.node && r.generation == g)
            return &r;
    }
    return nullptr;
}

inline Replica* ensure_replica_slot(Tensor& t, Node& node) noexcept {
    if (Replica* r = find_replica(t, node))
        return r;

    for (u32 i = 0; i < kMaxReplicas; ++i) {
        Replica& r = t.replicas[i];
        if (!r.node && !r.present && r.leases.load(std::memory_order_relaxed) == 0) {
            r.node = &node;
            return &r;
        }
    }
    return nullptr;
}

inline Error allocate_replica(Tensor& t, Node& node, Replica*& out) noexcept {
    out = ensure_replica_slot(t, node);
    if (!out) return Error::NoReplicaSlot;

    if (!out->block) {
        if (!node.backend.alloc) return Error::AllocationFailed;
        Error e = node.backend.alloc(node, t.bytes, out->block);
        if (e != Error::Ok) return e;
    }
    return Error::Ok;
}

inline Error wait_ready(Replica& r) noexcept {
    if (!r.ready.value) return Error::Ok;
    if (!r.node || !r.node->backend.wait) return Error::Ok;
    Error e = r.node->backend.wait(*r.node, r.ready);
    if (e == Error::Ok)
        r.ready = {};
    return e;
}

inline Error direct_copy(
    Replica& dst,
    const Replica& src,
    u64 bytes) noexcept
{
    if (!dst.node || !src.node || !dst.node->backend.copy)
        return Error::CopyFailed;

    Fence f{};
    Error e = dst.node->backend.copy(
        *dst.node, dst.block,
        *src.node, src.block,
        bytes, f);

    if (e != Error::Ok) return e;
    dst.ready = f;
    return Error::Ok;
}

inline Error materialize_current(
    Fabric& fabric,
    Tensor& t,
    Node& target,
    Replica*& out) noexcept
{
    const u64 current = t.generation();

    Replica* dst = nullptr;
    Error e = allocate_replica(t, target, dst);
    if (e != Error::Ok) return e;

    if (dst->present && dst->generation == current) {
        e = wait_ready(*dst);
        if (e != Error::Ok) return e;
        out = dst;
        return Error::Ok;
    }

    const Replica* src = find_current_replica(t);
    if (!src) return Error::NoCurrentReplica;

    // First try the backend's best direct path. P2P is merely an optimization.
    e = direct_copy(*dst, *src, t.bytes);

    if (e != Error::Ok) {
        // Universal fallback: materialize the same generation through host.
        if (!fabric.host) return Error::NoHostNode;

        Replica* stage = nullptr;
        Error a = allocate_replica(t, *fabric.host, stage);
        if (a != Error::Ok) return a;

        if (!(stage->present && stage->generation == current)) {
            a = direct_copy(*stage, *src, t.bytes);
            if (a != Error::Ok) return a;
            a = wait_ready(*stage);
            if (a != Error::Ok) return a;
            stage->generation = current;
            stage->present = 1;
        }

        e = direct_copy(*dst, *stage, t.bytes);
        if (e != Error::Ok) return e;
    }

    e = wait_ready(*dst);
    if (e != Error::Ok) return e;

    dst->generation = current;
    dst->present = 1;
    out = dst;
    return Error::Ok;
}

inline Error acquire_read(
    Fabric& fabric,
    Tensor& t,
    Node& node,
    u64 expectedGeneration,
    Lease& out) noexcept
{
    if (t.generation() != expectedGeneration)
        return Error::GenerationMismatch;

    Replica* r = nullptr;
    Error e = materialize_current(fabric, t, node, r);
    if (e != Error::Ok) return e;

    if (r->evicting.load(std::memory_order_acquire))
        return Error::LeaseBusy;

    r->leases.fetch_add(1, std::memory_order_acq_rel);

    // Re-check after leasing. If a writer committed concurrently, fail closed.
    if (t.generation() != expectedGeneration ||
        r->generation != expectedGeneration)
    {
        r->leases.fetch_sub(1, std::memory_order_acq_rel);
        return Error::GenerationMismatch;
    }

    out = {};
    out.tensor = &t;
    out.replica = r;
    out.node = &node;
    out.expectedGeneration = expectedGeneration;
    out.access = Read;
    out.active = 1;
    return Error::Ok;
}

inline Error begin_rw(
    Fabric& fabric,
    Tensor& t,
    Node& node,
    u64 expectedGeneration,
    Lease& out) noexcept
{
    // RW(expectedGeneration)
    //   mismatch → GenerationMismatch
    //   success  → reserve expectedGeneration + 1 (not visible until commit)
    if (t.generation() != expectedGeneration)
        return Error::GenerationMismatch;

    u8 expectedWriter = 0;
    if (!t.writerReserved.compare_exchange_strong(
            expectedWriter, 1,
            std::memory_order_acq_rel,
            std::memory_order_acquire))
        return Error::WriterBusy;

    if (t.generation() != expectedGeneration) {
        t.writerReserved.store(0, std::memory_order_release);
        return Error::GenerationMismatch;
    }

    Replica* r = nullptr;
    Error e = materialize_current(fabric, t, node, r);
    if (e != Error::Ok) {
        t.writerReserved.store(0, std::memory_order_release);
        return e;
    }

    if (r->evicting.load(std::memory_order_acquire)) {
        t.writerReserved.store(0, std::memory_order_release);
        return Error::LeaseBusy;
    }

    r->leases.fetch_add(1, std::memory_order_acq_rel);

    out = {};
    out.tensor = &t;
    out.replica = r;
    out.node = &node;
    out.expectedGeneration = expectedGeneration;
    out.writeGeneration = expectedGeneration + 1;
    out.access = RW;
    out.active = 1;
    return Error::Ok;
}

inline Error commit_rw(Lease& lease, Fence producedBy = {}) noexcept {
    if (!lease.active || !lease.tensor || !lease.replica)
        return Error::BadArgument;
    if ((lease.access & Write) == 0)
        return Error::BadArgument;

    Tensor& t = *lease.tensor;
    Replica& r = *lease.replica;

    // Nobody may publish over a generation other than the one we reserved.
    if (t.generation() != lease.expectedGeneration) {
        r.leases.fetch_sub(1, std::memory_order_acq_rel);
        t.writerReserved.store(0, std::memory_order_release);
        lease.active = 0;
        return Error::GenerationMismatch;
    }

    r.ready = producedBy;
    Error e = wait_ready(r);
    if (e != Error::Ok) {
        r.leases.fetch_sub(1, std::memory_order_acq_rel);
        t.writerReserved.store(0, std::memory_order_release);
        lease.active = 0;
        return e;
    }

    // Publish replica first, then logical generation.
    r.generation = lease.writeGeneration;
    r.present = 1;

    t.committedGeneration.store(
        lease.writeGeneration,
        std::memory_order_release);

    r.leases.fetch_sub(1, std::memory_order_acq_rel);
    t.writerReserved.store(0, std::memory_order_release);
    lease.active = 0;
    return Error::Ok;
}

inline void release(Lease& lease) noexcept {
    if (!lease.active) return;

    if (lease.replica)
        lease.replica->leases.fetch_sub(1, std::memory_order_acq_rel);

    if (lease.tensor && (lease.access & Write))
        lease.tensor->writerReserved.store(0, std::memory_order_release);

    lease.active = 0;
}

inline Error try_evict(Replica& r) noexcept {
    u8 expected = 0;
    if (!r.evicting.compare_exchange_strong(
            expected, 1,
            std::memory_order_acq_rel,
            std::memory_order_acquire))
        return Error::LeaseBusy;

    if (r.leases.load(std::memory_order_acquire) != 0) {
        r.evicting.store(0, std::memory_order_release);
        return Error::LeaseBusy;
    }

    if (r.present && r.node && r.node->backend.free && r.block)
        r.node->backend.free(*r.node, r.block);

    r.block = {};
    r.generation = 0;
    r.ready = {};
    r.present = 0;
    r.evicting.store(0, std::memory_order_release);
    return Error::Ok;
}

struct Layer {
    Tensor* weights = nullptr;
    void* user = nullptr;
};

struct ChainResult {
    Error error = Error::Ok;
    u32 layer = 0;
    u64 generation = 0;
    u64 nodeObjectId = 0;
};

// Bounces a streamed model across symmetric compute objects.
// activation is one logical object; realizations move A↔B (4'6 dribble).
inline ChainResult dispatch_bounce_chain(
    Fabric& fabric,
    Layer* layers,
    u32 layerCount,
    Tensor& activation) noexcept
{
    ChainResult result{};
    Node* previous = nullptr;

    for (u32 i = 0; i < layerCount; ++i) {
        if (!layers[i].weights) {
            result.error = Error::BadArgument;
            result.layer = i;
            return result;
        }

        Node* node = fabric.next_compute_node(previous);
        if (!node) {
            result.error = Error::NoNode;
            result.layer = i;
            return result;
        }

        Tensor& w = *layers[i].weights;

        const u64 wg = w.generation();
        Lease weights{};
        Error e = acquire_read(fabric, w, *node, wg, weights);
        if (e != Error::Ok) {
            result.error = e;
            result.layer = i;
            result.generation = wg;
            result.nodeObjectId = node->objectId;
            return result;
        }

        const u64 expected = activation.generation();

        Lease state{};
        e = begin_rw(fabric, activation, *node, expected, state);
        if (e != Error::Ok) {
            release(weights);
            result.error = e;
            result.layer = i;
            result.generation = expected;
            result.nodeObjectId = node->objectId;
            return result;
        }

        Fence done{};
        e = node->backend.dispatch(
            *node,
            weights.physical(),
            state.physical(),
            state.physical(),
            layers[i].user,
            done);

        release(weights);

        if (e != Error::Ok) {
            release(state); // generation is NOT published on failed dispatch.
            result.error = Error::DispatchFailed;
            result.layer = i;
            result.generation = expected;
            result.nodeObjectId = node->objectId;
            return result;
        }

        e = commit_rw(state, done);
        if (e != Error::Ok) {
            result.error = e;
            result.layer = i;
            result.generation = expected;
            result.nodeObjectId = node->objectId;
            return result;
        }

        previous = node;
        result.layer = i;
        result.generation = activation.generation();
        result.nodeObjectId = node->objectId;
    }

    return result;
}

} // namespace rawrxd::ucf
