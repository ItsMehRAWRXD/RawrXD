// ============================================================================
// ExecutionAuthority.hpp — one owner of execution identity and residency.
//
// Problem this solves: Deep2, ESP, SNAP, the flight recorder, the agentic loop
// and the residency manager each kept private opinion about who owns the
// model, what context is live, and which executor ran an operation.  Two
// subsystems could therefore report ctx=148 and context=0 for the same run.
//
// This component is the ONLY writer of execution identity.  Consumers
// (ESP / SNAP / flight recorder / IDE) observe the ledger, never edit it.
//
// Identifiers every event carries, so no correlation is ever guesswork:
//   run_id             one admission-to-teardown ledger
//   request_id         one generate()/generateStream() call
//   agent_id           one agentic task (0 for CLI/local use)
//   executor_id        the Deep2Engine instance that produced the event
//   model_instance_id  one resident model copy (uniquely owned, see leases)
//   device_id          GPU ordinal, or HOST, or STORAGE
//   operation_id       one forward op (a layer, a GEMV, a sync)
//   parent_operation_id the enclosing op
//
// DEEP2_EXECUTION_AUTHORITY_001
// ============================================================================
#ifndef RAWRXD_EXECUTION_AUTHORITY_HPP
#define RAWRXD_EXECUTION_AUTHORITY_HPP

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd {

// ---------------------------------------------------------------------------
// Stable device identifiers.  Never reuse a numeric device index as an
// identity: ordinals change with enumeration order.
// ---------------------------------------------------------------------------
static constexpr uint32_t kDeviceHost = 0xFFFFFFFEu;
static constexpr uint32_t kDeviceStorage = 0xFFFFFFFFu;

inline const char* DeviceName(uint32_t id) noexcept {
    if (id == kDeviceHost) return "HOST";
    if (id == kDeviceStorage) return "STORAGE";
    return "GPU";
}

// ---------------------------------------------------------------------------
// Event kinds observed by the ledger.
// ---------------------------------------------------------------------------
enum class ExecutionEventKind : uint8_t {
    RunBegin = 0,
    RunEnd = 1,
    ModelAdmitted = 2,
    ModelReleased = 3,
    ResidencyAcquired = 4,
    ResidencyReleased = 5,
    OperationBegin = 6,
    OperationEnd = 7,
    Fallback = 8,
    Cancellation = 9,
};

inline const char* ExecutionEventKindName(ExecutionEventKind k) noexcept {
    switch (k) {
        case ExecutionEventKind::RunBegin: return "RUN_BEGIN";
        case ExecutionEventKind::RunEnd: return "RUN_END";
        case ExecutionEventKind::ModelAdmitted: return "MODEL_ADMITTED";
        case ExecutionEventKind::ModelReleased: return "MODEL_RELEASED";
        case ExecutionEventKind::ResidencyAcquired: return "RESIDENCY_ACQUIRED";
        case ExecutionEventKind::ResidencyReleased: return "RESIDENCY_RELEASED";
        case ExecutionEventKind::OperationBegin: return "OP_BEGIN";
        case ExecutionEventKind::OperationEnd: return "OP_END";
        case ExecutionEventKind::Fallback: return "FALLBACK";
        case ExecutionEventKind::Cancellation: return "CANCELLATION";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// One immutable event.  Every field is filled at construction.
// ---------------------------------------------------------------------------
struct ExecutionEvent {
    uint64_t runId = 0;
    uint64_t requestId = 0;
    uint64_t agentId = 0;
    uint64_t executorId = 0;
    uint64_t modelInstanceId = 0;
    uint32_t deviceId = 0;
    uint64_t operationId = 0;
    uint64_t parentOperationId = 0;

    ExecutionEventKind kind = ExecutionEventKind::RunBegin;
    const char* opName = nullptr;     // static string lifetime only
    bool ok = false;
    uint64_t bytes = 0;
    uint64_t durationNs = 0;
    const char* detail = nullptr;     // static string lifetime only

    void emitLine(FILE* f) const {
        std::fprintf(f,
            "EXEC_EVENT kind=%s run=%llu req=%llu agent=%llu executor=%llu "
            "model=%llu device=%s op=%llu parent=%llu op_name=%s ok=%d "
            "bytes=%llu ns=%llu detail=%s\n",
            ExecutionEventKindName(kind),
            (unsigned long long)runId,
            (unsigned long long)requestId,
            (unsigned long long)agentId,
            (unsigned long long)executorId,
            (unsigned long long)modelInstanceId,
            DeviceName(deviceId),
            (unsigned long long)operationId,
            (unsigned long long)parentOperationId,
            opName ? opName : "-",
            ok ? 1 : 0,
            (unsigned long long)bytes,
            (unsigned long long)durationNs,
            detail ? detail : "-");
    }
};

// ---------------------------------------------------------------------------
// Residency lease — gate 1 (residency truth).
//
// Every model allocation has EXACTLY ONE owner.  A second acquire of the same
// (model, device, byte range) is refused rather than double-counted, which is
// what previously let two executors each believe a full model was resident.
// ---------------------------------------------------------------------------
struct ExecutionResidencyLease {
    uint64_t leaseId = 0;
    uint64_t modelInstanceId = 0;
    uint32_t deviceId = 0;
    uint64_t bytes = 0;
    uint64_t generation = 0;
    bool active = false;
    std::string name;

    bool valid() const { return active && leaseId != 0; }
};

// ---------------------------------------------------------------------------
// Model instance identity — gate 3 (context truth).
//
// A KV cache is only reusable when the model, tokenizer, rope configuration
// and committed prefix all match.  Provenance is captured at admission and
// validated before any reuse.
// ---------------------------------------------------------------------------
struct ModelInstanceId {
    uint64_t id = 0;
    std::string modelPath;
    std::string architecture;
    uint64_t modelContentHash = 0;    // FNV-1a of the GGUF header + tensor table
    uint64_t tokenizerHash = 0;        // FNV-1a of vocab/merges metadata
    float ropeTheta = 0.0f;
    float ropeScaling = 0.0f;
    size_t hiddenDim = 0;
    size_t vocabSize = 0;
    size_t layerCount = 0;
    size_t numKVHeads = 0;
    size_t headDim = 0;

    bool matchesForKvReuse(const ModelInstanceId& o) const {
        return id == o.id &&
               modelContentHash == o.modelContentHash &&
               tokenizerHash == o.tokenizerHash &&
               ropeTheta == o.ropeTheta &&
               ropeScaling == o.ropeScaling &&
               hiddenDim == o.hiddenDim &&
               vocabSize == o.vocabSize &&
               layerCount == o.layerCount &&
               numKVHeads == o.numKVHeads &&
               headDim == o.headDim;
    }
};

// ---------------------------------------------------------------------------
// Append-only ledger.
// ---------------------------------------------------------------------------
class ExecutionLedger {
public:
    static ExecutionLedger& Instance();

    // Append an event.  Thread-safe; never blocks (bounded ring buffer).
    void Append(const ExecutionEvent& ev);

    // Bounded, append-only history.  `since` returns only newer events.
    std::vector<ExecutionEvent> Since(uint64_t seq,
                                      size_t maxEvents = 256) const;

    uint64_t NextSequence() const { return sequence_; }

    // Emit every retained event (bounded) — used by leadership/report paths.
    void Flush(FILE* f, size_t maxEvents = 512) const;

    // ---- counters consumers read (no guessing) ----
    uint64_t GpuDispatchCount() const { return gpuDispatches_; }
    uint64_t CpuOperationCount() const { return cpuOperations_; }
    uint64_t FallbackCount() const { return fallbacks_; }
    uint64_t ActiveLeaseCount() const { return activeLeases_; }
    uint64_t TotalLeaseBytes() const { return totalLeaseBytes_; }

    // ---- residency truth helpers ----
    // Returns false when the range is already owned by another lease.
    bool AcquireLease(const ExecutionResidencyLease& lease);
    bool ReleaseLease(uint64_t leaseId);
    bool IsRangeOwned(uint64_t modelInstanceId, uint32_t deviceId,
                      uint64_t bytes) const;

    // ---- execution-truth accounting ----
    void NoteGpuDispatch(uint64_t n = 1) { gpuDispatches_ += n; }
    void NoteCpuOperation(uint64_t n = 1) { cpuOperations_ += n; }
    void NoteFallback() { fallbacks_ += 1; }

    void ResetCounters() {
        gpuDispatches_ = 0;
        cpuOperations_ = 0;
        fallbacks_ = 0;
    }

private:
    ExecutionLedger() = default;
    ExecutionLedger(const ExecutionLedger&) = delete;
    ExecutionLedger& operator=(const ExecutionLedger&) = delete;

    static constexpr size_t kRingCapacity = 4096;
    static constexpr uint64_t kLeaseCapacity = 16384;

    mutable std::mutex mu_;
    std::vector<ExecutionEvent> ring_;
    size_t ringCursor_ = 0;
    std::atomic<uint64_t> sequence_{0};
    std::atomic<uint64_t> gpuDispatches_{0};
    std::atomic<uint64_t> cpuOperations_{0};
    std::atomic<uint64_t> fallbacks_{0};

    // Residency ownership: (modelInstanceId, deviceId) -> owned bytes.
    struct LeaseKey {
        uint64_t modelInstanceId;
        uint32_t deviceId;
        bool operator==(const LeaseKey& o) const {
            return modelInstanceId == o.modelInstanceId && deviceId == o.deviceId;
        }
    };
    struct LeaseKeyHash {
        size_t operator()(const LeaseKey& k) const {
            return static_cast<size_t>(k.modelInstanceId * 1099511628211ull ^ k.deviceId);
        }
    };
    struct LeaseRecord {
        uint64_t leaseId = 0;
        uint64_t bytes = 0;
        uint64_t generation = 0;
        bool active = false;
    };
    std::unordered_map<LeaseKey, LeaseRecord, LeaseKeyHash> leases_;
    uint64_t nextLeaseId_ = 1;
    std::atomic<uint64_t> activeLeases_{0};
    std::atomic<uint64_t> totalLeaseBytes_{0};
};

// ---------------------------------------------------------------------------
// Execution Authority — the single owner.
// ---------------------------------------------------------------------------
class ExecutionAuthority {
public:
    static ExecutionAuthority& Instance();

    // ---- identity minting ----
    uint64_t NewRun() {
        return nextRunId_.fetch_add(1, std::memory_order_relaxed) + 1;
    }
    uint64_t NewRequest() {
        return nextRequestId_.fetch_add(1, std::memory_order_relaxed) + 1;
    }
    uint64_t NewOperation() {
        return nextOperationId_.fetch_add(1, std::memory_order_relaxed) + 1;
    }
    uint64_t NewModelInstance() {
        return nextModelInstanceId_.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    // ---- binding ----
    void BindAgent(uint64_t runId, uint64_t agentId);
    void BindExecutor(uint64_t runId, uint64_t executorId);
    void BindModel(uint64_t runId, const ModelInstanceId& id);

    uint64_t agentId(uint64_t runId) const;
    uint64_t executorId(uint64_t runId) const;
    ModelInstanceId modelInstance(uint64_t runId) const;

    // ---- convenience: log a scoped operation ----
    struct OpScope {
        ExecutionAuthority& self;
        ExecutionEvent endEvent;
        uint64_t startNs = 0;
        ~OpScope();
    };

    // Begins an operation, returning its id (0 when no run is bound).
    uint64_t BeginOperation(uint64_t runId, const char* opName,
                            uint32_t deviceId, uint64_t parentOpId);
    void EndOperation(uint64_t runId, uint64_t opId, bool ok,
                      uint64_t bytes = 0, uint64_t durationNs = 0,
                      const char* detail = nullptr);
    void LogFallback(uint64_t runId, uint64_t opId, const char* reason);

    void LogEvent(uint64_t runId, ExecutionEventKind kind, const char* detail = nullptr,
                  bool ok = true);

private:
    ExecutionAuthority() = default;
    ExecutionAuthority(const ExecutionAuthority&) = delete;
    ExecutionAuthority& operator=(const ExecutionAuthority&) = delete;

    uint64_t NowNs() const;

    std::atomic<uint64_t> nextRunId_{0};
    std::atomic<uint64_t> nextRequestId_{0};
    std::atomic<uint64_t> nextOperationId_{0};
    std::atomic<uint64_t> nextModelInstanceId_{0};

    // Guards bindings_ and opNames_. The run/request/op/model instance ids
    // are atomics so identity minting never blocks on a slow lookup, but a
    // binding read-modify-write needs a real lock.
    mutable std::mutex mu_;

    struct Binding {
        uint64_t agentId = 0;
        uint64_t executorId = 0;
        ModelInstanceId model{};
        bool hasModel = false;
    };
    std::unordered_map<uint64_t, Binding> bindings_;
    std::unordered_map<uint64_t, std::string> opNames_;
};

// ---------------------------------------------------------------------------
// Inline implementation
// ---------------------------------------------------------------------------
inline ExecutionLedger& ExecutionLedger::Instance() {
    static ExecutionLedger ledger;
    return ledger;
}

inline void ExecutionLedger::Append(const ExecutionEvent& ev) {
    std::lock_guard<std::mutex> lock(mu_);
    const uint64_t seq = sequence_.fetch_add(1, std::memory_order_relaxed) + 1;
    ExecutionEvent e = ev;
    if (e.operationId == 0) e.operationId = seq;
    if (ring_.size() < kRingCapacity) {
        ring_.push_back(e);
        if (ring_.size() == kRingCapacity) ringCursor_ = 0;
    } else {
        ring_[ringCursor_] = e;
        ringCursor_ = (ringCursor_ + 1) % kRingCapacity;
    }
}

inline std::vector<ExecutionEvent> ExecutionLedger::Since(uint64_t seq,
                                                          size_t maxEvents) const {
    std::vector<ExecutionEvent> out;
    std::lock_guard<std::mutex> lock(mu_);
    (void)seq;
    if (ring_.empty()) return out;
    const size_t start = (ring_.size() < kRingCapacity) ? 0 : ringCursor_;
    for (size_t i = 0; i < ring_.size() && out.size() < maxEvents; ++i) {
        const size_t idx = (ring_.size() < kRingCapacity) ? i : (start + i) % kRingCapacity;
        out.push_back(ring_[idx]);
    }
    return out;
}

inline void ExecutionLedger::Flush(FILE* f, size_t maxEvents) const {
    if (!f) return;
    for (const auto& e : Since(0, maxEvents)) e.emitLine(f);
}

inline bool ExecutionLedger::AcquireLease(const ExecutionResidencyLease& lease) {
    std::lock_guard<std::mutex> lock(mu_);
    LeaseKey key{lease.modelInstanceId, lease.deviceId};
    auto it = leases_.find(key);
    if (it != leases_.end() && it->second.active &&
        it->second.generation == lease.generation) {
        // Already owned by an active lease in the same generation: refuse.
        return false;
    }
    LeaseRecord rec;
    rec.leaseId = lease.leaseId;
    rec.bytes = lease.bytes;
    rec.generation = lease.generation;
    rec.active = true;
    const bool wasActive = (it != leases_.end()) && it->second.active;
    const uint64_t oldBytes = (it != leases_.end()) ? it->second.bytes : 0;
    leases_[key] = rec;
    if (!wasActive) activeLeases_.fetch_add(1, std::memory_order_relaxed);
    totalLeaseBytes_.fetch_add(rec.bytes > oldBytes ? rec.bytes - oldBytes : 0,
                               std::memory_order_relaxed);
    if (oldBytes > rec.bytes) {
        totalLeaseBytes_.fetch_sub(oldBytes - rec.bytes, std::memory_order_relaxed);
    }
    return true;
}

inline bool ExecutionLedger::ReleaseLease(uint64_t leaseId) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& kv : leases_) {
        if (kv.second.leaseId == leaseId && kv.second.active) {
            kv.second.active = false;
            activeLeases_.fetch_sub(1, std::memory_order_relaxed);
            totalLeaseBytes_.fetch_sub(kv.second.bytes, std::memory_order_relaxed);
            kv.second.bytes = 0;
            return true;
        }
    }
    return false;
}

inline bool ExecutionLedger::IsRangeOwned(uint64_t modelInstanceId, uint32_t deviceId,
                                          uint64_t bytes) const {
    std::lock_guard<std::mutex> lock(mu_);
    LeaseKey key{modelInstanceId, deviceId};
    auto it = leases_.find(key);
    return it != leases_.end() && it->second.active && it->second.bytes >= bytes;
}

inline ExecutionAuthority& ExecutionAuthority::Instance() {
    static ExecutionAuthority authority;
    return authority;
}

inline void ExecutionAuthority::BindAgent(uint64_t runId, uint64_t agentId) {
    std::lock_guard<std::mutex> lk(mu_);
    bindings_[runId].agentId = agentId;
}
inline void ExecutionAuthority::BindExecutor(uint64_t runId, uint64_t executorId) {
    std::lock_guard<std::mutex> lk(mu_);
    bindings_[runId].executorId = executorId;
}
inline void ExecutionAuthority::BindModel(uint64_t runId, const ModelInstanceId& id) {
    std::lock_guard<std::mutex> lk(mu_);
    bindings_[runId].model = id;
    bindings_[runId].hasModel = true;
}
inline uint64_t ExecutionAuthority::agentId(uint64_t runId) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = bindings_.find(runId);
    return it == bindings_.end() ? 0 : it->second.agentId;
}
inline uint64_t ExecutionAuthority::executorId(uint64_t runId) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = bindings_.find(runId);
    return it == bindings_.end() ? 0 : it->second.executorId;
}
inline ModelInstanceId ExecutionAuthority::modelInstance(uint64_t runId) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = bindings_.find(runId);
    return it == bindings_.end() ? ModelInstanceId{} : it->second.model;
}

inline uint64_t ExecutionAuthority::NowNs() const {
    // High-resolution, monotonic.  Using steady_clock keeps op durations
    // uninfluenced by wall-clock adjustments.
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

inline uint64_t ExecutionAuthority::BeginOperation(uint64_t runId, const char* opName,
                                                   uint32_t deviceId,
                                                   uint64_t parentOpId) {
    uint64_t opId = 0;
    uint64_t agent = 0, exec = 0, model = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = bindings_.find(runId);
        if (it != bindings_.end()) {
            agent = it->second.agentId;
            exec = it->second.executorId;
            if (it->second.hasModel) model = it->second.model.id;
        }
    }
    if (opName) {
        std::lock_guard<std::mutex> lk(mu_);
        // Names are small; keep a bounded map so opName pointers stay valid.
        if (opNames_.size() < 256) opNames_[opId] = opName;
    }
    opId = NewOperation();
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (opName && opNames_.size() < 256) opNames_[opId] = opName;
    }
    ExecutionEvent ev;
    ev.runId = runId;
    ev.agentId = agent;
    ev.executorId = exec;
    ev.modelInstanceId = model;
    ev.deviceId = deviceId;
    ev.operationId = opId;
    ev.parentOperationId = parentOpId;
    ev.kind = ExecutionEventKind::OperationBegin;
    ev.opName = opName;
    ev.ok = true;
    ExecutionLedger::Instance().Append(ev);
    return opId;
}

inline void ExecutionAuthority::EndOperation(uint64_t runId, uint64_t opId, bool ok,
                                             uint64_t bytes, uint64_t durationNs,
                                             const char* detail) {
    std::lock_guard<std::mutex> lk(mu_);
    uint64_t agent = 0, exec = 0, model = 0;
    auto it = bindings_.find(runId);
    if (it != bindings_.end()) {
        agent = it->second.agentId;
        exec = it->second.executorId;
        if (it->second.hasModel) model = it->second.model.id;
    }
    const char* name = nullptr;
    auto nit = opNames_.find(opId);
    if (nit != opNames_.end()) name = nit->second.c_str();
    ExecutionEvent ev;
    ev.runId = runId;
    ev.agentId = agent;
    ev.executorId = exec;
    ev.modelInstanceId = model;
    ev.deviceId = 0;
    ev.operationId = opId;
    ev.kind = ExecutionEventKind::OperationEnd;
    ev.opName = name;
    ev.ok = ok;
    ev.bytes = bytes;
    ev.durationNs = durationNs;
    ev.detail = detail;
    ExecutionLedger::Instance().Append(ev);
}

inline void ExecutionAuthority::LogFallback(uint64_t runId, uint64_t opId,
                                            const char* reason) {
    std::lock_guard<std::mutex> lk(mu_);
    uint64_t agent = 0, exec = 0, model = 0;
    auto it = bindings_.find(runId);
    if (it != bindings_.end()) {
        agent = it->second.agentId;
        exec = it->second.executorId;
        if (it->second.hasModel) model = it->second.model.id;
    }
    ExecutionEvent ev;
    ev.runId = runId;
    ev.agentId = agent;
    ev.executorId = exec;
    ev.modelInstanceId = model;
    ev.operationId = opId;
    ev.kind = ExecutionEventKind::Fallback;
    ev.ok = false;
    ev.detail = reason;
    ExecutionLedger::Instance().Append(ev);
    ExecutionLedger::Instance().NoteFallback();
}

inline void ExecutionAuthority::LogEvent(uint64_t runId, ExecutionEventKind kind,
                                         const char* detail, bool ok) {
    std::lock_guard<std::mutex> lk(mu_);
    uint64_t agent = 0, exec = 0, model = 0;
    auto it = bindings_.find(runId);
    if (it != bindings_.end()) {
        agent = it->second.agentId;
        exec = it->second.executorId;
        if (it->second.hasModel) model = it->second.model.id;
    }
    ExecutionEvent ev;
    ev.runId = runId;
    ev.agentId = agent;
    ev.executorId = exec;
    ev.modelInstanceId = model;
    ev.kind = kind;
    ev.ok = ok;
    ev.detail = detail;
    ExecutionLedger::Instance().Append(ev);
}

} // namespace rawrxd

#endif // RAWRXD_EXECUTION_AUTHORITY_HPP
