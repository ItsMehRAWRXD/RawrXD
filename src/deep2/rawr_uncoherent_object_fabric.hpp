#pragma once
// rawr_uncoherent_object_fabric.hpp
//
// Coherence-indifferent tensor dispatch for physically discrete memory domains.
//
// Design:
//   - TensorObject is the identity. Never a physical pointer.
//   - DeviceObject is an opaque execution/memory domain. Never "GPU index 0/1" policy.
//   - Replica is a local incarnation of a TensorObject.
//   - Generation is truth. A stale replica is not "wrong"; it is simply not selected.
//   - Dispatch resolves objects to the chosen device just-in-time.
//   - Transport routing is capability-based. P2P is only one possible edge.
//   - Hardware-coherent memory may be represented as an alias/zero-copy edge.
//
// The scheduler sees TensorRef + DeviceSelector only.
// Backend code sees PhysicalView only while a FabricLease is alive.
//
// Stream bounce: A→B→A… via BounceChain + dispatchRWExpected(+RW++).
// Stale writer: GenerationMismatch(expected, observed).
//
// Generation is an authority receipt first (scratch ticket), not a bare counter.
// See UcfGenerationTicket.hpp — Reverse Manifest fingerprints this header's law.
// AUTHORITY CHAIN (never reverse):
//   AGENTS.md → toolchain → this header → Reverse Manifest → Ticket
//     → Halo/sparkUnified(G) → BounceChain.obj / zipline
// BounceChain.obj / MASM / zipline mechanics MUST NOT redefine:
//   acquire, generation, host fallback, GPU identity, or coherence.
// Halo creates temporary unified execution memory (mem+ory); it does not
// claim physical coherence. Bounce is an internal shuttle, not the model.
// If MASM and this header disagree: MASM = defect, header = authority.
//
// Acquisition law:
//   READ  acquireRead:        materialize newest → receipt(requested, acquired=current)
//   WRITE acquireWrite:       reserve current+1 → publish only on successful commit
//   STRICT acquireExpected:   BounceChain / certs — mismatch fails (no silent converge)
//
// materialized ≠ acquired; resident ≠ current; current ≠ writable.
//
// C++20, standard library only.

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>
#include <algorithm>

namespace rawr::fabric {

using ObjectId   = std::uint64_t;
using DeviceId   = std::uint64_t;
using Generation = std::uint64_t;
using FenceValue = std::uint64_t;

enum class DeviceKind : std::uint8_t {
    Host,
    Accelerator,
    Storage,
    Unified
};

enum class Access : std::uint8_t {
    Read,
    Write,
    ReadWrite
};

enum class ReplicaState : std::uint8_t {
    Absent,
    Materializing,
    Present,
    Retiring,
    Failed
};

enum Capability : std::uint64_t {
    CapNone          = 0,
    CapCompute       = 1ull << 0,
    CapHostVisible   = 1ull << 1,
    CapDeviceLocal   = 1ull << 2,
    CapAsyncCopy     = 1ull << 3,
    CapPeerCopy      = 1ull << 4,
    CapUnifiedAlias  = 1ull << 5,
    CapStorage       = 1ull << 6
};

struct TensorRef {
    ObjectId id = 0;
    std::uint64_t offset = 0;
    std::uint64_t bytes = 0;

    explicit operator bool() const noexcept { return id != 0; }
};

struct DeviceObject {
    DeviceId id = 0;
    DeviceKind kind = DeviceKind::Host;
    std::uint64_t capabilities = CapNone;

    std::uint64_t capacityBytes = 0;
    std::uint64_t usableBytes = 0;

    std::uint64_t localReadBytesPerSec = 0;
    std::uint64_t localWriteBytesPerSec = 0;

    std::string label;

    bool has(std::uint64_t cap) const noexcept {
        return (capabilities & cap) == cap;
    }
};

struct PhysicalView {
    DeviceId device = 0;
    std::uintptr_t opaqueAddress = 0;
    std::uint64_t bytes = 0;
    Generation generation = 0;

    explicit operator bool() const noexcept {
        return opaqueAddress != 0 || bytes == 0;
    }
};

struct MigrationTicket {
    ObjectId object = 0;
    DeviceId source = 0;
    DeviceId destination = 0;
    Generation generation = 0;
    FenceValue fence = 0;

    explicit operator bool() const noexcept {
        return object != 0 && destination != 0;
    }
};

class GenerationMismatch final : public std::runtime_error {
public:
    GenerationMismatch(Generation expected, Generation observed)
        : std::runtime_error("fabric generation mismatch"),
          expected_(expected),
          observed_(observed)
    {}

    Generation expected() const noexcept { return expected_; }
    Generation observed() const noexcept { return observed_; }

private:
    Generation expected_ = 0;
    Generation observed_ = 0;
};

// Receipt never overwrites requested with acquired — convergence stays observable.
struct AcquireReceipt {
    ObjectId tensorId = 0;
    Generation requestedGeneration = 0; // caller intent
    Generation acquiredGeneration = 0;  // fabric grant (read: replica gen; write: reserved G+1)
    PhysicalView physical{};
    std::uint32_t readerReceipt = 0;    // BusyReaders after grant; 0 for writers

    bool converged() const noexcept {
        return requestedGeneration != acquiredGeneration;
    }

    // Read invariant: requested <= acquired.
    bool validConvergence() const noexcept {
        return requestedGeneration <= acquiredGeneration;
    }
};

struct BackendOps {
    std::function<std::uintptr_t(DeviceId, std::uint64_t)> allocate;
    std::function<void(DeviceId, std::uintptr_t, std::uint64_t)> release;
    std::function<FenceValue(
        DeviceId, std::uintptr_t,
        DeviceId, std::uintptr_t,
        std::uint64_t)> copy;
    std::function<std::uintptr_t(
        DeviceId, std::uintptr_t,
        DeviceId, std::uint64_t)> alias;
    std::function<void(FenceValue)> wait;
};

struct TransportEdge {
    DeviceId from = 0;
    DeviceId to = 0;

    bool direct = false;
    bool aliasable = false;

    std::uint64_t measuredBytesPerSec = 0;
    std::uint64_t fixedLatencyNs = 0;

    double estimatedSeconds(std::uint64_t bytes) const noexcept {
        if (aliasable)
            return 0.0;
        if (measuredBytesPerSec == 0)
            return std::numeric_limits<double>::infinity();

        return (static_cast<double>(fixedLatencyNs) / 1.0e9) +
               (static_cast<double>(bytes) /
                static_cast<double>(measuredBytesPerSec));
    }
};

class Topology {
public:
    void upsertDevice(DeviceObject d) {
        std::lock_guard lock(mu_);
        devices_[d.id] = std::move(d);
    }

    void upsertEdge(TransportEdge e) {
        std::lock_guard lock(mu_);
        for (auto& cur : edges_) {
            if (cur.from == e.from && cur.to == e.to) {
                cur = e;
                return;
            }
        }
        edges_.push_back(e);
    }

    std::optional<DeviceObject> device(DeviceId id) const {
        std::lock_guard lock(mu_);
        auto it = devices_.find(id);
        if (it == devices_.end())
            return std::nullopt;
        return it->second;
    }

    std::vector<DeviceObject> devices() const {
        std::lock_guard lock(mu_);
        std::vector<DeviceObject> out;
        out.reserve(devices_.size());
        for (const auto& [_, d] : devices_)
            out.push_back(d);
        return out;
    }

    std::optional<TransportEdge> edge(DeviceId from, DeviceId to) const {
        if (from == to) {
            TransportEdge local;
            local.from = from;
            local.to = to;
            local.direct = true;
            local.aliasable = true;
            return local;
        }

        std::lock_guard lock(mu_);
        for (const auto& e : edges_)
            if (e.from == from && e.to == to)
                return e;
        return std::nullopt;
    }

    std::optional<DeviceId> bestSource(
        std::span<const DeviceId> sources,
        DeviceId destination,
        std::uint64_t bytes) const
    {
        std::optional<DeviceId> best;
        double bestCost = std::numeric_limits<double>::infinity();

        for (DeviceId src : sources) {
            const auto e = edge(src, destination);
            if (!e)
                continue;
            const double cost = e->estimatedSeconds(bytes);
            if (cost < bestCost) {
                bestCost = cost;
                best = src;
            }
        }
        return best;
    }

    std::optional<DeviceObject> chooseComputeDevice(
        std::uint64_t requiredCaps,
        std::uint64_t bytesRequired = 0) const
    {
        auto ds = devices();
        std::optional<DeviceObject> best;
        long double bestScore = -1.0L;

        for (const auto& d : ds) {
            if (!d.has(CapCompute) || !d.has(requiredCaps))
                continue;
            if (bytesRequired && d.usableBytes < bytesRequired)
                continue;

            const long double bandwidth =
                static_cast<long double>(d.localReadBytesPerSec);
            const long double headroom =
                static_cast<long double>(d.usableBytes);

            const long double score = bandwidth + headroom / 1024.0L;
            if (!best || score > bestScore) {
                best = d;
                bestScore = score;
            }
        }
        return best;
    }

    std::vector<DeviceId> acceleratorIds() const {
        std::vector<DeviceId> out;
        for (const auto& d : devices())
            if (d.kind == DeviceKind::Accelerator && d.has(CapCompute))
                out.push_back(d.id);
        return out;
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<DeviceId, DeviceObject> devices_;
    std::vector<TransportEdge> edges_;
};

struct Replica {
    DeviceId device = 0;
    std::atomic<ReplicaState> state { ReplicaState::Absent };

    std::atomic<Generation> generation { 0 };
    std::atomic<std::uint32_t> readers { 0 };
    std::atomic<bool> writer { false };

    std::uintptr_t address = 0;
    std::uint64_t bytes = 0;
    std::atomic<FenceValue> readyFence { 0 };

    mutable std::mutex mu;
};

class TensorObject {
public:
    TensorObject(ObjectId id, std::uint64_t bytes, bool immutable)
        : id_(id), bytes_(bytes), immutable_(immutable)
    {
        if (!id_)
            throw std::invalid_argument("TensorObject: id must be nonzero");
    }

    ObjectId id() const noexcept { return id_; }
    std::uint64_t bytes() const noexcept { return bytes_; }
    bool immutable() const noexcept { return immutable_; }

    Generation generation() const noexcept {
        return generation_.load(std::memory_order_acquire);
    }

    // Strict: expected must equal observed (BounceChain / certs).
    void beginWrite(Generation expected) {
        if (immutable_)
            throw std::logic_error("immutable tensor cannot be write-leased");

        const Generation observed =
            generation_.load(std::memory_order_acquire);
        if (observed != expected)
            throw GenerationMismatch(expected, observed);

        bool unlocked = false;
        if (!writerGate_.compare_exchange_strong(
                unlocked, true,
                std::memory_order_acq_rel))
            throw std::runtime_error("tensor already has an object-level writer");

        const Generation afterGate =
            generation_.load(std::memory_order_acquire);
        if (afterGate != expected) {
            writerGate_.store(false, std::memory_order_release);
            throw GenerationMismatch(expected, afterGate);
        }
    }

    // Reserve path: lock writer on actual current; return observed (CAS base).
    // Caller publishes observed → observed+1; two writers cannot reserve the same successor.
    Generation beginWriteReserved() {
        if (immutable_)
            throw std::logic_error("immutable tensor cannot be write-leased");

        bool unlocked = false;
        if (!writerGate_.compare_exchange_strong(
                unlocked, true,
                std::memory_order_acq_rel))
            throw std::runtime_error("tensor already has an object-level writer");

        return generation_.load(std::memory_order_acquire);
    }

    void endWrite() noexcept {
        writerGate_.store(false, std::memory_order_release);
    }

    Generation publishWrite(Generation expected) {
        if (immutable_)
            throw std::logic_error("immutable tensor cannot publish a write");

        Generation observed = expected;
        if (!generation_.compare_exchange_strong(
                observed, expected + 1,
                std::memory_order_acq_rel))
            throw GenerationMismatch(expected, observed);

        return expected + 1;
    }

    std::shared_ptr<Replica> replica(DeviceId d, bool create) {
        std::lock_guard lock(mu_);
        auto it = replicas_.find(d);
        if (it != replicas_.end())
            return it->second;

        if (!create)
            return {};

        auto r = std::make_shared<Replica>();
        r->device = d;
        r->bytes = bytes_;
        replicas_[d] = r;
        return r;
    }

    std::vector<std::shared_ptr<Replica>> currentReplicas() const {
        const Generation want = generation();
        std::vector<std::shared_ptr<Replica>> out;

        std::lock_guard lock(mu_);
        for (const auto& [_, r] : replicas_) {
            if (r->state.load(std::memory_order_acquire) == ReplicaState::Present &&
                r->generation.load(std::memory_order_acquire) == want)
                out.push_back(r);
        }
        return out;
    }

    std::vector<std::shared_ptr<Replica>> allReplicas() const {
        std::vector<std::shared_ptr<Replica>> out;
        std::lock_guard lock(mu_);
        out.reserve(replicas_.size());
        for (const auto& [_, r] : replicas_)
            out.push_back(r);
        return out;
    }

private:
    ObjectId id_ = 0;
    std::uint64_t bytes_ = 0;
    bool immutable_ = false;

    std::atomic<Generation> generation_ { 1 };
    std::atomic<bool> writerGate_ { false };

    mutable std::mutex mu_;
    std::unordered_map<DeviceId, std::shared_ptr<Replica>> replicas_;
};

class Fabric;

class FabricLease {
public:
    FabricLease() = default;
    FabricLease(const FabricLease&) = delete;
    FabricLease& operator=(const FabricLease&) = delete;

    FabricLease(FabricLease&& other) noexcept {
        moveFrom(std::move(other));
    }

    FabricLease& operator=(FabricLease&& other) noexcept {
        if (this != &other) {
            release();
            moveFrom(std::move(other));
        }
        return *this;
    }

    ~FabricLease() { release(); }

    PhysicalView view() const noexcept {
        if (!replica_)
            return {};
        // Physical generation = leased replica truth (not caller intent).
        return PhysicalView{
            replica_->device,
            replica_->address,
            bytes_,
            replica_->generation.load(std::memory_order_acquire)
        };
    }

    Generation generation() const noexcept { return acquiredGeneration_; }
    Generation requestedGeneration() const noexcept {
        return requestedGeneration_;
    }
    Generation publishBase() const noexcept { return publishBase_; }
    bool converged() const noexcept {
        return requestedGeneration_ != acquiredGeneration_;
    }
    DeviceId device() const noexcept { return replica_ ? replica_->device : 0; }
    Access access() const noexcept { return access_; }
    explicit operator bool() const noexcept { return static_cast<bool>(replica_); }

    Generation commit();

    AcquireReceipt receipt() const noexcept {
        AcquireReceipt r;
        r.tensorId = object_ ? object_->id() : 0;
        r.requestedGeneration = requestedGeneration_;
        r.acquiredGeneration = acquiredGeneration_;
        r.readerReceipt = readerToken_;
        r.physical = view();
        return r;
    }

private:
    friend class Fabric;

    FabricLease(
        Fabric* fabric,
        std::shared_ptr<TensorObject> object,
        std::shared_ptr<Replica> replica,
        Access access,
        Generation requested,
        Generation acquired,
        Generation publishBase,
        std::uint64_t bytes,
        std::uint32_t readerToken = 0)
        : fabric_(fabric),
          object_(std::move(object)),
          replica_(std::move(replica)),
          access_(access),
          requestedGeneration_(requested),
          acquiredGeneration_(acquired),
          publishBase_(publishBase),
          bytes_(bytes),
          readerToken_(readerToken)
    {}

    void release() noexcept;
    void moveFrom(FabricLease&& other) noexcept {
        fabric_ = other.fabric_;
        object_ = std::move(other.object_);
        replica_ = std::move(other.replica_);
        access_ = other.access_;
        requestedGeneration_ = other.requestedGeneration_;
        acquiredGeneration_ = other.acquiredGeneration_;
        publishBase_ = other.publishBase_;
        bytes_ = other.bytes_;
        readerToken_ = other.readerToken_;
        committed_ = other.committed_;
        ownsObjectWriter_ = other.ownsObjectWriter_;

        other.fabric_ = nullptr;
        other.requestedGeneration_ = 0;
        other.acquiredGeneration_ = 0;
        other.publishBase_ = 0;
        other.bytes_ = 0;
        other.readerToken_ = 0;
        other.committed_ = true;
        other.ownsObjectWriter_ = false;
    }

    Fabric* fabric_ = nullptr;
    std::shared_ptr<TensorObject> object_;
    std::shared_ptr<Replica> replica_;
    Access access_ = Access::Read;
    Generation requestedGeneration_ = 0;
    Generation acquiredGeneration_ = 0;
    Generation publishBase_ = 0; // write CAS base; 0 for reads
    std::uint64_t bytes_ = 0;
    std::uint32_t readerToken_ = 0;
    bool committed_ = false;
    bool ownsObjectWriter_ = false;
};

class Fabric {
public:
    explicit Fabric(BackendOps ops)
        : ops_(std::move(ops))
    {}

    Topology& topology() noexcept { return topology_; }
    const Topology& topology() const noexcept { return topology_; }

    TensorRef createTensor(std::uint64_t bytes, bool immutable = true) {
        const ObjectId id = nextObject_.fetch_add(1, std::memory_order_relaxed);
        auto obj = std::make_shared<TensorObject>(id, bytes, immutable);

        {
            std::lock_guard lock(objectsMu_);
            objects_[id] = obj;
        }

        return TensorRef{id, 0, bytes};
    }

    std::shared_ptr<TensorObject> object(TensorRef ref) const {
        std::lock_guard lock(objectsMu_);
        auto it = objects_.find(ref.id);
        if (it == objects_.end())
            throw std::out_of_range("unknown TensorRef");
        return it->second;
    }

    void attachReplica(
        TensorRef ref,
        DeviceId device,
        std::uintptr_t address,
        Generation generation = 1)
    {
        auto obj = object(ref);
        auto r = obj->replica(device, true);

        std::lock_guard lock(r->mu);
        r->address = address;
        r->bytes = obj->bytes();
        r->generation.store(generation, std::memory_order_release);
        r->state.store(ReplicaState::Present, std::memory_order_release);
    }

    // Read-only convenience: snapshots object generation as expected.
    // Write/ReadWrite: use acquireExpected (strict) or acquireWrite (reserve).
    FabricLease acquire(
        TensorRef ref,
        DeviceId destination,
        Access access)
    {
        if (access == Access::Write || access == Access::ReadWrite)
            throw std::logic_error(
                "RW requires acquireExpected or acquireWrite; "
                "generation-less write is forbidden");
        auto obj = object(ref);
        const Generation expected = obj->generation();
        return acquireExpected(ref, destination, access, expected);
    }

    // STRICT: expected != observed → GenerationMismatch (BounceChain / certs).
    FabricLease acquireExpected(
        TensorRef ref,
        DeviceId destination,
        Access access,
        Generation expected)
    {
        auto obj = object(ref);

        const bool writing =
            access == Access::Write || access == Access::ReadWrite;

        if (writing)
            obj->beginWrite(expected);
        else {
            const Generation observed = obj->generation();
            if (observed != expected)
                throw GenerationMismatch(expected, observed);
        }

        try {
            auto dst = ensureCurrent(obj, destination);

            const Generation observed =
                dst->generation.load(std::memory_order_acquire);
            if (observed != expected)
                throw GenerationMismatch(expected, observed);

            std::uint32_t token = 0;
            if (writing) {
                bool unlocked = false;
                if (!dst->writer.compare_exchange_strong(
                        unlocked, true,
                        std::memory_order_acq_rel))
                    throw std::runtime_error("replica already has a writer");

                if (dst->readers.load(std::memory_order_acquire) != 0) {
                    dst->writer.store(false, std::memory_order_release);
                    throw std::runtime_error(
                        "replica currently leased by readers");
                }
            } else {
                if (dst->writer.load(std::memory_order_acquire))
                    throw std::runtime_error(
                        "replica currently leased by writer");
                token = static_cast<std::uint32_t>(
                    dst->readers.fetch_add(1, std::memory_order_acq_rel) + 1);
            }

            FabricLease lease(
                this, std::move(obj), std::move(dst),
                access, expected, expected,
                writing ? expected : 0, ref.bytes, token);
            lease.ownsObjectWriter_ = writing;
            return lease;
        } catch (...) {
            if (writing)
                obj->endWrite();
            throw;
        }
    }

    // CONVERGING READ: stale requested is convergence, not error.
    // Invariant: requested <= acquired && acquired == replica.generation
    FabricLease acquireRead(
        TensorRef ref,
        DeviceId destination,
        Generation requestedGeneration)
    {
        auto obj = object(ref);
        auto dst = ensureCurrent(obj, destination);

        const Generation acquired = obj->generation();
        const Generation repGen =
            dst->generation.load(std::memory_order_acquire);
        if (repGen != acquired)
            throw GenerationMismatch(acquired, repGen);

        if (requestedGeneration > acquired)
            throw GenerationMismatch(requestedGeneration, acquired);

        if (dst->writer.load(std::memory_order_acquire))
            throw std::runtime_error("replica currently leased by writer");

        const auto token = static_cast<std::uint32_t>(
            dst->readers.fetch_add(1, std::memory_order_acq_rel) + 1);

        if (obj->generation() != acquired ||
            dst->generation.load(std::memory_order_acquire) != acquired)
        {
            dst->readers.fetch_sub(1, std::memory_order_acq_rel);
            throw GenerationMismatch(acquired, obj->generation());
        }

        return FabricLease(
            this, std::move(obj), std::move(dst),
            Access::Read, requestedGeneration, acquired, 0, ref.bytes, token);
    }

    // Alias — same converging read law.
    FabricLease acquireReadConverging(
        TensorRef ref,
        DeviceId destination,
        Generation requestedGeneration)
    {
        return acquireRead(ref, destination, requestedGeneration);
    }

    // WRITE reserve: materialize current → exclusive → candidate = current+1.
    // Receipt.acquired = reserved candidate; publishBase = current (CAS).
    FabricLease acquireWrite(
        TensorRef ref,
        DeviceId destination,
        Generation requestedGeneration)
    {
        auto obj = object(ref);
        const Generation current = obj->beginWriteReserved();

        try {
            auto dst = ensureCurrent(obj, destination);
            const Generation repGen =
                dst->generation.load(std::memory_order_acquire);
            if (repGen != current)
                throw GenerationMismatch(current, repGen);

            bool unlocked = false;
            if (!dst->writer.compare_exchange_strong(
                    unlocked, true, std::memory_order_acq_rel))
                throw std::runtime_error("replica already has a writer");

            if (dst->readers.load(std::memory_order_acquire) != 0) {
                dst->writer.store(false, std::memory_order_release);
                throw std::runtime_error(
                    "replica currently leased by readers");
            }

            const Generation reserved = current + 1;
            FabricLease lease(
                this, std::move(obj), std::move(dst),
                Access::ReadWrite, requestedGeneration, reserved,
                current, ref.bytes);
            lease.ownsObjectWriter_ = true;
            return lease;
        } catch (...) {
            obj->endWrite();
            throw;
        }
    }

    FabricLease acquireRWConverging(
        TensorRef ref,
        DeviceId destination,
        Generation requestedGeneration)
    {
        return acquireWrite(ref, destination, requestedGeneration);
    }

    bool retireReplica(TensorRef ref, DeviceId device) {
        auto obj = object(ref);
        auto r = obj->replica(device, false);
        if (!r)
            return true;

        std::lock_guard lock(r->mu);

        if (r->readers.load(std::memory_order_acquire) != 0 ||
            r->writer.load(std::memory_order_acquire))
            return false;

        r->state.store(ReplicaState::Retiring, std::memory_order_release);

        if (r->address && ops_.release)
            ops_.release(device, r->address, r->bytes);

        r->address = 0;
        r->generation.store(0, std::memory_order_release);
        r->readyFence.store(0, std::memory_order_release);
        r->state.store(ReplicaState::Absent, std::memory_order_release);
        return true;
    }

    // Deleted: generation-less dispatch quietly becomes "latest pointer wins".
    template<class Fn>
    void dispatch(
        DeviceId,
        std::span<const TensorRef>,
        std::span<const TensorRef>,
        Fn&&) = delete;

    // +RW++ : expected N → acquire RW → execute → commit → N+1
    template<class Fn>
    Generation dispatchRWExpected(
        DeviceId device,
        std::span<const TensorRef> reads,
        TensorRef state,
        Generation expected,
        Fn&& fn)
    {
        std::vector<FabricLease> readLeases;
        std::vector<PhysicalView> readViews;
        readLeases.reserve(reads.size());
        readViews.reserve(reads.size());

        for (const auto& r : reads) {
            auto obj = object(r);
            const Generation readExpect =
                obj->immutable() ? obj->generation() : expected;
            readLeases.emplace_back(
                acquireExpected(r, device, Access::Read, readExpect));
        }

        for (const auto& l : readLeases)
            readViews.push_back(l.view());

        auto rw = acquireExpected(
            state, device, Access::ReadWrite, expected);

        std::invoke(
            std::forward<Fn>(fn),
            device,
            std::span<const PhysicalView>(readViews),
            rw.view());

        return rw.commit();
    }

private:
    friend class FabricLease;

    std::shared_ptr<Replica> ensureCurrent(
        const std::shared_ptr<TensorObject>& obj,
        DeviceId destination)
    {
        const Generation want = obj->generation();
        auto dst = obj->replica(destination, true);

        if (dst->state.load(std::memory_order_acquire) == ReplicaState::Present &&
            dst->generation.load(std::memory_order_acquire) == want)
            return dst;

        std::lock_guard dstLock(dst->mu);

        if (dst->state.load(std::memory_order_acquire) == ReplicaState::Present &&
            dst->generation.load(std::memory_order_acquire) == want)
            return dst;

        const auto current = obj->currentReplicas();
        if (current.empty())
            throw std::runtime_error("tensor has no current physical incarnation");

        std::vector<DeviceId> sourceIds;
        sourceIds.reserve(current.size());
        for (const auto& r : current)
            sourceIds.push_back(r->device);

        auto sourceId =
            topology_.bestSource(sourceIds, destination, obj->bytes());

        std::shared_ptr<Replica> src;

        if (sourceId) {
            for (const auto& r : current) {
                if (r->device == *sourceId) {
                    src = r;
                    break;
                }
            }
        }

        if (!src) {
            for (const auto& r : current) {
                auto d = topology_.device(r->device);
                if (d && d->has(CapHostVisible)) {
                    src = r;
                    break;
                }
            }
        }

        // UCF-010: if no direct edge and no host-visible *current* replica,
        // relay through any Host domain — promote latest → host → destination.
        if (!src) {
            DeviceId hostId = 0;
            for (const auto& d : topology_.devices()) {
                if (d.kind == DeviceKind::Host && d.has(CapHostVisible)) {
                    hostId = d.id;
                    break;
                }
            }
            if (hostId && hostId != destination) {
                // Materialize current onto host first (recursive one-hop).
                if (!current.empty()) {
                    auto via = ensureCurrent(obj, hostId);
                    src = via;
                }
            }
        }

        if (!src)
            throw std::runtime_error(
                "no direct route and no host-visible current replica");

        dst->state.store(ReplicaState::Materializing, std::memory_order_release);

        const auto e = topology_.edge(src->device, destination);
        if (e && e->aliasable && ops_.alias) {
            const auto alias =
                ops_.alias(
                    src->device,
                    src->address,
                    destination,
                    obj->bytes());

            if (alias) {
                dst->address = alias;
                dst->bytes = obj->bytes();
                dst->generation.store(want, std::memory_order_release);
                dst->readyFence.store(0, std::memory_order_release);
                dst->state.store(ReplicaState::Present, std::memory_order_release);
                return dst;
            }
        }

        if (!ops_.allocate || !ops_.copy)
            throw std::runtime_error("fabric backend lacks allocate/copy");

        if (!dst->address)
            dst->address = ops_.allocate(destination, obj->bytes());

        if (!dst->address) {
            dst->state.store(ReplicaState::Failed, std::memory_order_release);
            throw std::runtime_error("destination allocation failed");
        }

        FenceValue fence =
            ops_.copy(
                src->device, src->address,
                destination, dst->address,
                obj->bytes());

        dst->readyFence.store(fence, std::memory_order_release);

        if (fence && ops_.wait)
            ops_.wait(fence);

        dst->bytes = obj->bytes();
        dst->generation.store(want, std::memory_order_release);
        dst->state.store(ReplicaState::Present, std::memory_order_release);
        return dst;
    }

    void releaseLease(FabricLease& l) noexcept {
        if (!l.replica_)
            return;

        if (l.access_ == Access::Read) {
            l.replica_->readers.fetch_sub(1, std::memory_order_acq_rel);
        } else {
            l.replica_->writer.store(false, std::memory_order_release);
            if (l.ownsObjectWriter_ && l.object_)
                l.object_->endWrite();
            l.ownsObjectWriter_ = false;
        }

        l.replica_.reset();
        l.object_.reset();
        l.fabric_ = nullptr;
    }

    Generation commitLease(FabricLease& l) {
        if (!l.replica_ || !l.object_)
            throw std::logic_error("commit on empty lease");

        if (l.access_ == Access::Read)
            return l.acquiredGeneration_;

        if (l.committed_)
            return l.acquiredGeneration_;

        // Publication uses CAS base (strict expected or reserved current).
        // No successful publish → no generation advance.
        const Generation base =
            l.publishBase_ ? l.publishBase_ : l.acquiredGeneration_;
        const Generation next = l.object_->publishWrite(base);

        l.replica_->generation.store(next, std::memory_order_release);
        l.replica_->state.store(ReplicaState::Present, std::memory_order_release);

        l.acquiredGeneration_ = next;
        l.committed_ = true;
        return next;
    }

    BackendOps ops_;
    Topology topology_;

    std::atomic<ObjectId> nextObject_ { 1 };

    mutable std::mutex objectsMu_;
    std::unordered_map<ObjectId, std::shared_ptr<TensorObject>> objects_;
};

inline Generation FabricLease::commit() {
    if (!fabric_)
        throw std::logic_error("commit on detached lease");
    return fabric_->commitLease(*this);
}

inline void FabricLease::release() noexcept {
    if (fabric_)
        fabric_->releaseLease(*this);
}

struct DeviceSelector {
    std::uint64_t requiredCaps = CapCompute | CapDeviceLocal;
    std::uint64_t bytesRequired = 0;

    std::optional<DeviceObject> resolve(const Topology& t) const {
        return t.chooseComputeDevice(requiredCaps, bytesRequired);
    }
};

// Alternating/ring execution over opaque device objects (not GPU0/GPU1 policy).
class BounceChain {
public:
    BounceChain(Fabric& fabric, std::vector<DeviceId> lane)
        : fabric_(fabric), lane_(std::move(lane))
    {
        if (lane_.empty())
            throw std::invalid_argument("BounceChain requires a non-empty lane");
    }

    DeviceId nextDevice() noexcept {
        const DeviceId d = lane_[cursor_];
        cursor_ = (cursor_ + 1) % lane_.size();
        return d;
    }

    void reset(std::size_t phase = 0) noexcept {
        cursor_ = lane_.empty() ? 0 : phase % lane_.size();
    }

    template<class Fn>
    Generation hop(
        std::span<const TensorRef> layerReads,
        TensorRef streamedState,
        Generation expected,
        Fn&& fn)
    {
        const DeviceId d = nextDevice();

        return fabric_.dispatchRWExpected(
            d,
            layerReads,
            streamedState,
            expected,
            std::forward<Fn>(fn));
    }

private:
    Fabric& fabric_;
    std::vector<DeviceId> lane_;
    std::size_t cursor_ = 0;
};

} // namespace rawr::fabric
