#pragma once
// deep2_ucf_bouncehouse_trace.hpp
//
// Full event trace for:
//   rawr_uncoherent_object_fabric.hpp  = semantic law
//   rawrxd_gpu_zipline.hpp             = mobility
//   deep2_ucf_gpu_ready_e2e            = proof
//
// Purpose:
//   Make a real local-model run observable end-to-end.
//
// No third-party dependencies. C++20.
// Emits line-oriented JSONL plus optional compact text.
// This logger is observational only. It must never define semantic legality.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rawrxd::ucftrace {

using u8  = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

enum class Event : u32 {
    SessionBegin,
    SessionEnd,

    ModelOpenBegin,
    ModelOpenEnd,
    ModelShardOpen,
    ModelMetadata,
    TensorCatalogued,

    ImmutableSourceBind,
    ImmutableSourceReadBegin,
    ImmutableSourceReadEnd,

    GpuProbe,
    GpuReady,
    GpuUnavailable,

    PeerProbe,
    PeerReady,
    PeerUnavailable,

    TopologySealed,
    TopologyDegraded,

    TokenBegin,
    TokenEnd,

    OpBegin,
    OpEnd,

    LaneSelect,
    Bounce,
    BounceSuppressed,
    FreezeRun,
    NoExecutableGpu,

    WeightHit,
    WeightMiss,
    WeightEvict,
    WeightUploadBegin,
    WeightUploadEnd,

    LiveMaterializeBegin,
    LiveMaterializeEnd,
    PeerCopyBegin,
    PeerCopyEnd,

    AcquireRead,
    AcquireWrite,
    AcquireStrict,
    AcquireReject,

    DispatchBegin,
    DispatchEnd,

    FenceWaitBegin,
    FenceWaitEnd,

    PublishBegin,
    PublishCommit,
    PublishAbort,

    SampleBegin,
    SampleEnd,

    HostComputeViolation,
    HostActivationViolation,
    HostKvViolation,

    TruthDrift,
    GenerationDrift,
    PublicationDrift,

    Summary
};

inline const char* event_name(Event e) noexcept {
    switch (e) {
    case Event::SessionBegin: return "SESSION_BEGIN";
    case Event::SessionEnd: return "SESSION_END";
    case Event::ModelOpenBegin: return "MODEL_OPEN_BEGIN";
    case Event::ModelOpenEnd: return "MODEL_OPEN_END";
    case Event::ModelShardOpen: return "MODEL_SHARD_OPEN";
    case Event::ModelMetadata: return "MODEL_METADATA";
    case Event::TensorCatalogued: return "TENSOR_CATALOGUED";
    case Event::ImmutableSourceBind: return "IMMUTABLE_SOURCE_BIND";
    case Event::ImmutableSourceReadBegin: return "IMMUTABLE_SOURCE_READ_BEGIN";
    case Event::ImmutableSourceReadEnd: return "IMMUTABLE_SOURCE_READ_END";
    case Event::GpuProbe: return "GPU_PROBE";
    case Event::GpuReady: return "GPU_READY";
    case Event::GpuUnavailable: return "GPU_UNAVAILABLE";
    case Event::PeerProbe: return "PEER_PROBE";
    case Event::PeerReady: return "PEER_READY";
    case Event::PeerUnavailable: return "PEER_UNAVAILABLE";
    case Event::TopologySealed: return "TOPOLOGY_SEALED";
    case Event::TopologyDegraded: return "TOPOLOGY_DEGRADED";
    case Event::TokenBegin: return "TOKEN_BEGIN";
    case Event::TokenEnd: return "TOKEN_END";
    case Event::OpBegin: return "OP_BEGIN";
    case Event::OpEnd: return "OP_END";
    case Event::LaneSelect: return "LANE_SELECT";
    case Event::Bounce: return "BOUNCE";
    case Event::BounceSuppressed: return "BOUNCE_SUPPRESSED";
    case Event::FreezeRun: return "FREEZE_RUN";
    case Event::NoExecutableGpu: return "NO_EXECUTABLE_GPU";
    case Event::WeightHit: return "WEIGHT_HIT";
    case Event::WeightMiss: return "WEIGHT_MISS";
    case Event::WeightEvict: return "WEIGHT_EVICT";
    case Event::WeightUploadBegin: return "WEIGHT_UPLOAD_BEGIN";
    case Event::WeightUploadEnd: return "WEIGHT_UPLOAD_END";
    case Event::LiveMaterializeBegin: return "LIVE_MATERIALIZE_BEGIN";
    case Event::LiveMaterializeEnd: return "LIVE_MATERIALIZE_END";
    case Event::PeerCopyBegin: return "PEER_COPY_BEGIN";
    case Event::PeerCopyEnd: return "PEER_COPY_END";
    case Event::AcquireRead: return "ACQUIRE_READ";
    case Event::AcquireWrite: return "ACQUIRE_WRITE";
    case Event::AcquireStrict: return "ACQUIRE_STRICT";
    case Event::AcquireReject: return "ACQUIRE_REJECT";
    case Event::DispatchBegin: return "DISPATCH_BEGIN";
    case Event::DispatchEnd: return "DISPATCH_END";
    case Event::FenceWaitBegin: return "FENCE_WAIT_BEGIN";
    case Event::FenceWaitEnd: return "FENCE_WAIT_END";
    case Event::PublishBegin: return "PUBLISH_BEGIN";
    case Event::PublishCommit: return "PUBLISH_COMMIT";
    case Event::PublishAbort: return "PUBLISH_ABORT";
    case Event::SampleBegin: return "SAMPLE_BEGIN";
    case Event::SampleEnd: return "SAMPLE_END";
    case Event::HostComputeViolation: return "HOST_COMPUTE_VIOLATION";
    case Event::HostActivationViolation: return "HOST_ACTIVATION_VIOLATION";
    case Event::HostKvViolation: return "HOST_KV_VIOLATION";
    case Event::TruthDrift: return "TRUTH_DRIFT";
    case Event::GenerationDrift: return "GENERATION_DRIFT";
    case Event::PublicationDrift: return "PUBLICATION_DRIFT";
    case Event::Summary: return "SUMMARY";
    }
    return "UNKNOWN";
}

struct Record {
    Event event = Event::SessionBegin;

    u64 seq = 0;
    u64 us = 0;

    u64 session = 0;
    u64 token = 0;
    u64 op = 0;
    u64 layer = 0;

    u64 tensor = 0;
    u64 replica = 0;
    u64 device = 0;
    u64 peerDevice = 0;

    u64 requestedGen = 0;
    u64 acquiredGen = 0;
    u64 candidateGen = 0;
    u64 publishedGen = 0;

    u64 bytes = 0;
    u64 fence = 0;
    u64 ticket = 0;

    u64 aux0 = 0;
    u64 aux1 = 0;

    const char* text = nullptr;
};

struct Counters {
    std::atomic<u64> events{0};

    std::atomic<u64> tokenCount{0};
    std::atomic<u64> opCount{0};

    std::atomic<u64> r9700Ops{0};
    std::atomic<u64> rx7800xtOps{0};

    std::atomic<u64> bounceCount{0};
    std::atomic<u64> bounceSuppressed{0};
    std::atomic<u64> freezeRun{0};

    std::atomic<u64> weightHits{0};
    std::atomic<u64> weightMisses{0};
    std::atomic<u64> weightEvictions{0};
    std::atomic<u64> weightUploadBytes{0};

    std::atomic<u64> peerCopyBytes{0};

    std::atomic<u64> acquireRead{0};
    std::atomic<u64> acquireWrite{0};
    std::atomic<u64> acquireStrict{0};
    std::atomic<u64> acquireReject{0};

    std::atomic<u64> publishCommit{0};
    std::atomic<u64> publishAbort{0};

    std::atomic<u64> hostCompute{0};
    std::atomic<u64> hostActivationBytes{0};
    std::atomic<u64> hostKvBytes{0};

    std::atomic<u64> truthDrift{0};
    std::atomic<u64> generationDrift{0};
    std::atomic<u64> publicationDrift{0};

    std::atomic<u64> noExecutableGpu{0};
};

class Trace {
public:
    Trace() = default;

    ~Trace() {
        close();
    }

    bool open(const char* jsonlPath, const char* compactPath = nullptr) noexcept {
        close();

        if (jsonlPath) {
#if defined(_MSC_VER)
            fopen_s(&json_, jsonlPath, "wb");
#else
            json_ = std::fopen(jsonlPath, "wb");
#endif
        }

        if (compactPath) {
#if defined(_MSC_VER)
            fopen_s(&compact_, compactPath, "wb");
#else
            compact_ = std::fopen(compactPath, "wb");
#endif
        }

        start_ = clock::now();
        return json_ != nullptr || compact_ != nullptr;
    }

    void close() noexcept {
        if (json_) {
            std::fflush(json_);
            std::fclose(json_);
            json_ = nullptr;
        }
        if (compact_) {
            std::fflush(compact_);
            std::fclose(compact_);
            compact_ = nullptr;
        }
    }

    Counters& counters() noexcept { return counters_; }

    u64 now_us() const noexcept {
        const auto d = std::chrono::duration_cast<std::chrono::microseconds>(
            clock::now() - start_);
        return static_cast<u64>(d.count());
    }

    void emit(Record r) noexcept {
        r.seq = seq_.fetch_add(1, std::memory_order_relaxed);
        r.us = now_us();

        bump(r);

        if (json_)
            emit_json(r);

        if (compact_)
            emit_compact(r);
    }

    void session_begin(u64 session, const char* model) noexcept {
        Record r{};
        r.event = Event::SessionBegin;
        r.session = session;
        r.text = model;
        emit(r);
    }

    void session_end(u64 session) noexcept {
        Record r{};
        r.event = Event::SessionEnd;
        r.session = session;
        emit(r);
        emit_summary(session);
    }

    void model_open_begin(u64 session, const char* path) noexcept {
        Record r{};
        r.event = Event::ModelOpenBegin;
        r.session = session;
        r.text = path;
        emit(r);
    }

    void model_open_end(
        u64 session,
        u64 tensors,
        u64 bytes,
        const char* modelName) noexcept
    {
        Record r{};
        r.event = Event::ModelOpenEnd;
        r.session = session;
        r.aux0 = tensors;
        r.bytes = bytes;
        r.text = modelName;
        emit(r);
    }

    void gpu_ready(
        u64 deviceId,
        const char* name,
        u64 vramBytes) noexcept
    {
        Record r{};
        r.event = Event::GpuReady;
        r.device = deviceId;
        r.bytes = vramBytes;
        r.text = name;
        emit(r);
    }

    void peer_ready(
        u64 from,
        u64 to,
        u64 measuredBytesPerSec) noexcept
    {
        Record r{};
        r.event = Event::PeerReady;
        r.device = from;
        r.peerDevice = to;
        r.aux0 = measuredBytesPerSec;
        emit(r);
    }

    void token_begin(u64 token, u64 generation) noexcept {
        Record r{};
        r.event = Event::TokenBegin;
        r.token = token;
        r.acquiredGen = generation;
        emit(r);
    }

    void token_end(
        u64 token,
        u64 generation,
        u64 sampledToken) noexcept
    {
        Record r{};
        r.event = Event::TokenEnd;
        r.token = token;
        r.publishedGen = generation;
        r.aux0 = sampledToken;
        emit(r);
    }

    void lane_select(
        u64 token,
        u64 op,
        u64 device,
        u64 previousDevice) noexcept
    {
        Record r{};
        r.event = Event::LaneSelect;
        r.token = token;
        r.op = op;
        r.device = device;
        r.peerDevice = previousDevice;
        emit(r);
    }

    void bounce(
        u64 token,
        u64 op,
        u64 from,
        u64 to,
        u64 generation) noexcept
    {
        Record r{};
        r.event = Event::Bounce;
        r.token = token;
        r.op = op;
        r.device = from;
        r.peerDevice = to;
        r.acquiredGen = generation;
        emit(r);
    }

    void suppress_and_freeze(
        u64 token,
        u64 op,
        u64 current,
        u64 failedDestination,
        u64 generation,
        const char* reason) noexcept
    {
        Record s{};
        s.event = Event::BounceSuppressed;
        s.token = token;
        s.op = op;
        s.device = current;
        s.peerDevice = failedDestination;
        s.acquiredGen = generation;
        s.text = reason;
        emit(s);

        Record f{};
        f.event = Event::FreezeRun;
        f.token = token;
        f.op = op;
        f.device = current;
        f.peerDevice = failedDestination;
        f.acquiredGen = generation;
        f.text = reason;
        emit(f);
    }

    void weight_hit(
        u64 token,
        u64 op,
        u64 tensor,
        u64 device,
        u64 bytes) noexcept
    {
        Record r{};
        r.event = Event::WeightHit;
        r.token = token;
        r.op = op;
        r.tensor = tensor;
        r.device = device;
        r.bytes = bytes;
        emit(r);
    }

    void weight_miss(
        u64 token,
        u64 op,
        u64 tensor,
        u64 device,
        u64 bytes) noexcept
    {
        Record r{};
        r.event = Event::WeightMiss;
        r.token = token;
        r.op = op;
        r.tensor = tensor;
        r.device = device;
        r.bytes = bytes;
        emit(r);
    }

    void weight_upload(
        bool begin,
        u64 token,
        u64 op,
        u64 tensor,
        u64 device,
        u64 bytes,
        u64 sourceOffset) noexcept
    {
        Record r{};
        r.event = begin ? Event::WeightUploadBegin
                        : Event::WeightUploadEnd;
        r.token = token;
        r.op = op;
        r.tensor = tensor;
        r.device = device;
        r.bytes = bytes;
        r.aux0 = sourceOffset;
        emit(r);
    }

    void peer_copy(
        bool begin,
        u64 token,
        u64 op,
        u64 tensor,
        u64 from,
        u64 to,
        u64 generation,
        u64 bytes,
        u64 fence = 0) noexcept
    {
        Record r{};
        r.event = begin ? Event::PeerCopyBegin
                        : Event::PeerCopyEnd;
        r.token = token;
        r.op = op;
        r.tensor = tensor;
        r.device = from;
        r.peerDevice = to;
        r.acquiredGen = generation;
        r.bytes = bytes;
        r.fence = fence;
        emit(r);
    }

    void acquire(
        Event acquireEvent,
        u64 token,
        u64 op,
        u64 tensor,
        u64 replica,
        u64 device,
        u64 requested,
        u64 acquired,
        u64 candidate,
        u64 ticket) noexcept
    {
        Record r{};
        r.event = acquireEvent;
        r.token = token;
        r.op = op;
        r.tensor = tensor;
        r.replica = replica;
        r.device = device;
        r.requestedGen = requested;
        r.acquiredGen = acquired;
        r.candidateGen = candidate;
        r.ticket = ticket;
        emit(r);
    }

    void dispatch(
        bool begin,
        u64 token,
        u64 op,
        u64 layer,
        u64 device,
        u64 generation,
        u64 bytes,
        u64 fence = 0) noexcept
    {
        Record r{};
        r.event = begin ? Event::DispatchBegin
                        : Event::DispatchEnd;
        r.token = token;
        r.op = op;
        r.layer = layer;
        r.device = device;
        r.acquiredGen = generation;
        r.bytes = bytes;
        r.fence = fence;
        emit(r);
    }

    void publish(
        bool commit,
        u64 token,
        u64 op,
        u64 tensor,
        u64 device,
        u64 acquired,
        u64 candidate,
        u64 published,
        u64 ticket,
        u64 fence) noexcept
    {
        Record r{};
        r.event = commit ? Event::PublishCommit
                         : Event::PublishAbort;
        r.token = token;
        r.op = op;
        r.tensor = tensor;
        r.device = device;
        r.acquiredGen = acquired;
        r.candidateGen = candidate;
        r.publishedGen = published;
        r.ticket = ticket;
        r.fence = fence;
        emit(r);
    }

    void drift(
        Event which,
        u64 tensor,
        u64 expected,
        u64 observed,
        const char* detail) noexcept
    {
        Record r{};
        r.event = which;
        r.tensor = tensor;
        r.requestedGen = expected;
        r.acquiredGen = observed;
        r.text = detail;
        emit(r);
    }

    void no_executable_gpu(
        u64 token,
        u64 op,
        const char* reason) noexcept
    {
        Record r{};
        r.event = Event::NoExecutableGpu;
        r.token = token;
        r.op = op;
        r.text = reason;
        emit(r);
    }

    void host_violation(Event kind, u64 bytes, const char* detail) noexcept {
        Record r{};
        r.event = kind;
        r.bytes = bytes;
        r.text = detail;
        emit(r);
    }

    void emit_summary(u64 session) noexcept {
        Record r{};
        r.event = Event::Summary;
        r.session = session;
        emit(r);

        if (compact_) {
            std::fprintf(
                compact_,
                "SUMMARY "
                "tokens=%llu ops=%llu "
                "r9700=%llu rx7800xt=%llu "
                "bounce=%llu suppressed=%llu freeze=%llu "
                "whit=%llu wmiss=%llu wevict=%llu wupload=%llu "
                "peerBytes=%llu "
                "acqR=%llu acqW=%llu acqStrict=%llu reject=%llu "
                "pub=%llu abort=%llu "
                "hostCompute=%llu hostAct=%llu hostKv=%llu "
                "truthDrift=%llu genDrift=%llu pubDrift=%llu "
                "noGpu=%llu\n",
                ull(counters_.tokenCount.load()),
                ull(counters_.opCount.load()),
                ull(counters_.r9700Ops.load()),
                ull(counters_.rx7800xtOps.load()),
                ull(counters_.bounceCount.load()),
                ull(counters_.bounceSuppressed.load()),
                ull(counters_.freezeRun.load()),
                ull(counters_.weightHits.load()),
                ull(counters_.weightMisses.load()),
                ull(counters_.weightEvictions.load()),
                ull(counters_.weightUploadBytes.load()),
                ull(counters_.peerCopyBytes.load()),
                ull(counters_.acquireRead.load()),
                ull(counters_.acquireWrite.load()),
                ull(counters_.acquireStrict.load()),
                ull(counters_.acquireReject.load()),
                ull(counters_.publishCommit.load()),
                ull(counters_.publishAbort.load()),
                ull(counters_.hostCompute.load()),
                ull(counters_.hostActivationBytes.load()),
                ull(counters_.hostKvBytes.load()),
                ull(counters_.truthDrift.load()),
                ull(counters_.generationDrift.load()),
                ull(counters_.publicationDrift.load()),
                ull(counters_.noExecutableGpu.load()));
            std::fflush(compact_);
        }
    }

private:
    using clock = std::chrono::steady_clock;

    static unsigned long long ull(u64 v) noexcept {
        return static_cast<unsigned long long>(v);
    }

    static void json_string(FILE* f, const char* s) noexcept {
        if (!s) {
            std::fputs("null", f);
            return;
        }

        std::fputc('"', f);
        for (; *s; ++s) {
            const unsigned char c = static_cast<unsigned char>(*s);
            switch (c) {
            case '"':  std::fputs("\\\"", f); break;
            case '\\': std::fputs("\\\\", f); break;
            case '\n': std::fputs("\\n", f); break;
            case '\r': std::fputs("\\r", f); break;
            case '\t': std::fputs("\\t", f); break;
            default:
                if (c < 0x20)
                    std::fprintf(f, "\\u%04x", static_cast<unsigned>(c));
                else
                    std::fputc(c, f);
            }
        }
        std::fputc('"', f);
    }

    void emit_json(const Record& r) noexcept {
        std::fprintf(
            json_,
            "{\"seq\":%llu,\"us\":%llu,\"event\":\"%s\","
            "\"session\":%llu,\"token\":%llu,\"op\":%llu,\"layer\":%llu,"
            "\"tensor\":%llu,\"replica\":%llu,"
            "\"device\":%llu,\"peerDevice\":%llu,"
            "\"requested\":%llu,\"acquired\":%llu,"
            "\"candidate\":%llu,\"published\":%llu,"
            "\"bytes\":%llu,\"fence\":%llu,\"ticket\":%llu,"
            "\"aux0\":%llu,\"aux1\":%llu,\"text\":",
            ull(r.seq),
            ull(r.us),
            event_name(r.event),
            ull(r.session),
            ull(r.token),
            ull(r.op),
            ull(r.layer),
            ull(r.tensor),
            ull(r.replica),
            ull(r.device),
            ull(r.peerDevice),
            ull(r.requestedGen),
            ull(r.acquiredGen),
            ull(r.candidateGen),
            ull(r.publishedGen),
            ull(r.bytes),
            ull(r.fence),
            ull(r.ticket),
            ull(r.aux0),
            ull(r.aux1));

        json_string(json_, r.text);
        std::fputs("}\n", json_);
        std::fflush(json_);
    }

    void emit_compact(const Record& r) noexcept {
        std::fprintf(
            compact_,
            "%08llu +%09lluus %-24s "
            "tok=%llu op=%llu L=%llu "
            "dev=%llu peer=%llu "
            "T=%llu R=%llu "
            "req=%llu acq=%llu cand=%llu pub=%llu "
            "bytes=%llu fence=%llu ticket=%llu",
            ull(r.seq),
            ull(r.us),
            event_name(r.event),
            ull(r.token),
            ull(r.op),
            ull(r.layer),
            ull(r.device),
            ull(r.peerDevice),
            ull(r.tensor),
            ull(r.replica),
            ull(r.requestedGen),
            ull(r.acquiredGen),
            ull(r.candidateGen),
            ull(r.publishedGen),
            ull(r.bytes),
            ull(r.fence),
            ull(r.ticket));

        if (r.text)
            std::fprintf(compact_, " [%s]", r.text);

        std::fputc('\n', compact_);
        std::fflush(compact_);
    }

    void bump(const Record& r) noexcept {
        counters_.events.fetch_add(1, std::memory_order_relaxed);

        switch (r.event) {
        case Event::TokenEnd:
            counters_.tokenCount.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::OpEnd:
            counters_.opCount.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::Bounce:
            counters_.bounceCount.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::BounceSuppressed:
            counters_.bounceSuppressed.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::FreezeRun:
            counters_.freezeRun.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::WeightHit:
            counters_.weightHits.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::WeightMiss:
            counters_.weightMisses.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::WeightEvict:
            counters_.weightEvictions.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::WeightUploadEnd:
            counters_.weightUploadBytes.fetch_add(r.bytes, std::memory_order_relaxed);
            break;

        case Event::PeerCopyEnd:
            counters_.peerCopyBytes.fetch_add(r.bytes, std::memory_order_relaxed);
            break;

        case Event::AcquireRead:
            counters_.acquireRead.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::AcquireWrite:
            counters_.acquireWrite.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::AcquireStrict:
            counters_.acquireStrict.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::AcquireReject:
            counters_.acquireReject.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::PublishCommit:
            counters_.publishCommit.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::PublishAbort:
            counters_.publishAbort.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::HostComputeViolation:
            counters_.hostCompute.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::HostActivationViolation:
            counters_.hostActivationBytes.fetch_add(r.bytes, std::memory_order_relaxed);
            break;

        case Event::HostKvViolation:
            counters_.hostKvBytes.fetch_add(r.bytes, std::memory_order_relaxed);
            break;

        case Event::TruthDrift:
            counters_.truthDrift.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::GenerationDrift:
            counters_.generationDrift.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::PublicationDrift:
            counters_.publicationDrift.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::NoExecutableGpu:
            counters_.noExecutableGpu.fetch_add(1, std::memory_order_relaxed);
            break;

        case Event::DispatchEnd:
            // Convention for the current strict test topology:
            // device 0 = R9700, device 1 = RX7800XT.
            if (r.device == 0)
                counters_.r9700Ops.fetch_add(1, std::memory_order_relaxed);
            else if (r.device == 1)
                counters_.rx7800xtOps.fetch_add(1, std::memory_order_relaxed);
            break;

        default:
            break;
        }
    }

    FILE* json_ = nullptr;
    FILE* compact_ = nullptr;

    clock::time_point start_ = clock::now();
    std::atomic<u64> seq_{0};
    Counters counters_{};
};

// Bounce-house++ rotation policy — mobility only.
// Does not determine generation legality, receipt validity, or publication.
struct LaneState {
    bool gpuReady[2]{false, false};
    bool peerReady[2][2]{
        {true,  false},
        {false, true}
    };
};

enum class MobilityDecision : u8 {
    Bounce,
    FreezeRun,
    SwitchSurvivor,
    NoExecutableGpu
};

struct MobilityReceipt {
    MobilityDecision decision = MobilityDecision::NoExecutableGpu;
    u32 from = 0;
    u32 to = 0;
    u32 executeOn = 0;
};

inline MobilityReceipt bounce_house_pp(
    const LaneState& lanes,
    u32 currentGpu) noexcept
{
    const u32 current = currentGpu & 1u;
    const u32 other = current ^ 1u;

    if (lanes.gpuReady[current]) {
        if (lanes.gpuReady[other] &&
            lanes.peerReady[current][other])
        {
            return {
                MobilityDecision::Bounce,
                current,
                other,
                other
            };
        }

        return {
            MobilityDecision::FreezeRun,
            current,
            other,
            current
        };
    }

    if (lanes.gpuReady[other]) {
        return {
            MobilityDecision::SwitchSurvivor,
            current,
            other,
            other
        };
    }

    return {
        MobilityDecision::NoExecutableGpu,
        current,
        other,
        current
    };
}

inline void trace_mobility(
    Trace& tr,
    const MobilityReceipt& m,
    u64 token,
    u64 op,
    u64 generation,
    const char* degradedReason = "lane-not-ready") noexcept
{
    switch (m.decision) {
    case MobilityDecision::Bounce:
        tr.bounce(token, op, m.from, m.to, generation);
        tr.lane_select(token, op, m.executeOn, m.from);
        break;

    case MobilityDecision::FreezeRun:
        tr.suppress_and_freeze(
            token,
            op,
            m.from,
            m.to,
            generation,
            degradedReason);
        tr.lane_select(token, op, m.executeOn, m.from);
        break;

    case MobilityDecision::SwitchSurvivor:
        tr.suppress_and_freeze(
            token,
            op,
            m.to,
            m.from,
            generation,
            "current-gpu-unavailable/switch-survivor");
        tr.lane_select(token, op, m.executeOn, m.from);
        break;

    case MobilityDecision::NoExecutableGpu:
        tr.no_executable_gpu(
            token,
            op,
            "both-gpu-lanes-unavailable");
        break;
    }
}

} // namespace rawrxd::ucftrace
