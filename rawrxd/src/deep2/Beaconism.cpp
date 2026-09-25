// ============================================================================
// Beaconism.cpp — Universal Causal Observation Layer Implementation
// ============================================================================

#include "Beaconism.hpp"
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static uint64_t nowNs() noexcept {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

static const char* eventName(BeaconEvent e) {
    switch (e) {
        case BeaconEvent::TOKEN_BEGIN: return "TOKEN_BEGIN";
        case BeaconEvent::TOKEN_LAYER_BEGIN: return "TOKEN_LAYER_BEGIN";
        case BeaconEvent::TOKEN_LAYER_END: return "TOKEN_LAYER_END";
        case BeaconEvent::TOKEN_END: return "TOKEN_END";
        case BeaconEvent::GPU_SUBMIT: return "GPU_SUBMIT";
        case BeaconEvent::GPU_COMPLETE: return "GPU_COMPLETE";
        case BeaconEvent::GPU_IDLE: return "GPU_IDLE";
        case BeaconEvent::GPU_HANDOFF_BEGIN: return "GPU_HANDOFF_BEGIN";
        case BeaconEvent::GPU_HANDOFF_END: return "GPU_HANDOFF_END";
        case BeaconEvent::GPU_QUEUE_DEPTH: return "GPU_QUEUE_DEPTH";
        case BeaconEvent::GPU_RESIDENCY_UPDATE: return "GPU_RESIDENCY_UPDATE";
        case BeaconEvent::TOOL_CALL_BEGIN: return "TOOL_CALL_BEGIN";
        case BeaconEvent::TOOL_CALL_END: return "TOOL_CALL_END";
        case BeaconEvent::TOOL_CALL_FAIL: return "TOOL_CALL_FAIL";
        case BeaconEvent::TOOL_CALL_REJECT: return "TOOL_CALL_REJECT";
        case BeaconEvent::AGENT_CREATE: return "AGENT_CREATE";
        case BeaconEvent::AGENT_DESTROY: return "AGENT_DESTROY";
        case BeaconEvent::AGENT_TASK_BEGIN: return "AGENT_TASK_BEGIN";
        case BeaconEvent::AGENT_TASK_END: return "AGENT_TASK_END";
        case BeaconEvent::AGENT_TOOL_REQUEST: return "AGENT_TOOL_REQUEST";
        case BeaconEvent::AGENT_TOOL_RESULT: return "AGENT_TOOL_RESULT";
        case BeaconEvent::VALIDATOR_BEGIN: return "VALIDATOR_BEGIN";
        case BeaconEvent::VALIDATOR_PASS: return "VALIDATOR_PASS";
        case BeaconEvent::VALIDATOR_FAIL: return "VALIDATOR_FAIL";
        case BeaconEvent::PS_BEGIN: return "PS_BEGIN";
        case BeaconEvent::PS_PASS: return "PS_PASS";
        case BeaconEvent::PS_FAIL: return "PS_FAIL";
        case BeaconEvent::PY_BEGIN: return "PY_BEGIN";
        case BeaconEvent::PY_PASS: return "PY_PASS";
        case BeaconEvent::PY_FAIL: return "PY_FAIL";
        case BeaconEvent::SCHEDULER_SELECT: return "SCHEDULER_SELECT";
        case BeaconEvent::SCHEDULER_SCORE: return "SCHEDULER_SCORE";
        case BeaconEvent::SCHEDULER_DECISION: return "SCHEDULER_DECISION";
        case BeaconEvent::MANIFEST_GPU0_IDLE_WITH_READY_WORK: return "MANIFEST_GPU0_IDLE_WITH_READY_WORK";
        case BeaconEvent::MANIFEST_GPU1_IDLE_WITH_READY_WORK: return "MANIFEST_GPU1_IDLE_WITH_READY_WORK";
        case BeaconEvent::MANIFEST_BAD_DEVICE_SELECTION: return "MANIFEST_BAD_DEVICE_SELECTION";
        case BeaconEvent::MANIFEST_EXCESSIVE_HANDOFF: return "MANIFEST_EXCESSIVE_HANDOFF";
        case BeaconEvent::MANIFEST_GPU_QUEUE_IMBALANCE: return "MANIFEST_GPU_QUEUE_IMBALANCE";
        case BeaconEvent::MANIFEST_GPU_RESIDENCY_MISS: return "MANIFEST_GPU_RESIDENCY_MISS";
        case BeaconEvent::MANIFEST_CROSS_GPU_COPY_STALL: return "MANIFEST_CROSS_GPU_COPY_STALL";
        case BeaconEvent::MANIFEST_CPU_FALLBACK: return "MANIFEST_CPU_FALLBACK";
        case BeaconEvent::MANIFEST_SSM_IDENTITY_FALLBACK: return "MANIFEST_SSM_IDENTITY_FALLBACK";
        case BeaconEvent::SSM_BEGIN: return "SSM_BEGIN";
        case BeaconEvent::SSM_GPU_DISPATCH: return "SSM_GPU_DISPATCH";
        case BeaconEvent::SSM_CPU_FALLBACK: return "SSM_CPU_FALLBACK";
        case BeaconEvent::SSM_IDENTITY_FALLBACK: return "SSM_IDENTITY_FALLBACK";
        case BeaconEvent::SSM_COMPLETE: return "SSM_COMPLETE";
        default: return "UNKNOWN";
    }
}

// ---------------------------------------------------------------------------
// BeaconRecord
// ---------------------------------------------------------------------------
std::string BeaconRecord::toString() const {
    std::ostringstream oss;
    oss << "BEACON seq=" << seq
        << " ts=" << timestampNs
        << " event=" << eventName(event)
        << " parent=" << parentSeq;
    if (!requestId.empty()) oss << " req=" << requestId;
    if (!agentId.empty()) oss << " agent=" << agentId;
    if (!toolId.empty()) oss << " tool=" << toolId;
    if (tokenId != 0) oss << " token=" << tokenId;
    if (layerId != 0) oss << " layer=" << layerId;
    if (!deviceId.empty()) oss << " device=" << deviceId;
    if (!eventPhase.empty()) oss << " phase=" << eventPhase;
    if (!result.empty()) oss << " result=" << result;
    if (!reason.empty()) oss << " reason=" << reason;
    if (bytes != 0) oss << " bytes=" << bytes;
    if (durationNs != 0) oss << " dur_ns=" << durationNs;
    for (const auto& kv : fields) {
        oss << " " << kv.first << "=" << kv.second;
    }
    return oss.str();
}

std::string BeaconRecord::toCompactString() const {
    std::ostringstream oss;
    oss << "BEACON|SEQ=" << seq
        << "|EVENT=" << eventName(event)
        << "|PARENT=" << parentSeq;
    if (!result.empty()) oss << "|RESULT=" << result;
    if (!reason.empty()) oss << "|REASON=" << reason;
    if (bytes != 0) oss << "|BYTES=" << bytes;
    if (durationNs != 0) oss << "|DUR_NS=" << durationNs;
    for (const auto& kv : fields) {
        oss << "|" << kv.first << "=" << kv.second;
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// BeaconismAuthority
// ---------------------------------------------------------------------------
BeaconismAuthority& BeaconismAuthority::Instance() {
    static BeaconismAuthority instance;
    return instance;
}

bool BeaconismAuthority::enabledGlobally() {
    static const bool enabled = [] {
        const char* v = std::getenv("DEEP2_BEACONISM");
        return v && v[0] == '1';
    }();
    return enabled;
}

bool BeaconismAuthority::open(const char* csvPath, const char* jsonlPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (csvPath) {
        csvFp_ = std::fopen(csvPath, "a");
        if (csvFp_) {
            std::fprintf(csvFp_, "seq,timestamp_ns,event,parent_seq,request_id,agent_id,tool_id,token_id,layer_id,device_id,phase,result,reason,bytes,duration_ns\n");
            std::fflush(csvFp_);
        }
    }
    if (jsonlPath) {
        jsonlFp_ = std::fopen(jsonlPath, "a");
    }
    ringBuffer_.reserve(kRingSize);
    return true;
}

void BeaconismAuthority::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (csvFp_) { std::fclose(csvFp_); csvFp_ = nullptr; }
    if (jsonlFp_) { std::fclose(jsonlFp_); jsonlFp_ = nullptr; }
}

void BeaconismAuthority::emit(const BeaconRecord& rec) {
    if (!enabledGlobally()) return;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (csvFp_) writeCsv(rec);
        if (jsonlFp_) writeJsonl(rec);
        pushRing(rec);
    }
    // Also mirror to stderr for real-time observation
    if (std::getenv("DEEP2_BEACONISM_STDERR")) {
        std::fprintf(stderr, "%s\n", rec.toCompactString().c_str());
        std::fflush(stderr);
    }
}

void BeaconismAuthority::emit(BeaconEvent event,
                               uint64_t parentSeq,
                               const char* result,
                               const char* reason,
                               uint64_t bytes,
                               uint64_t durationNs) {
    BeaconRecord rec;
    rec.seq = nextSeq();
    rec.timestampNs = nowNs();
    rec.event = event;
    rec.parentSeq = parentSeq;
    if (result) rec.result = result;
    if (reason) rec.reason = reason;
    rec.bytes = bytes;
    rec.durationNs = durationNs;
    emit(rec);
}

void BeaconismAuthority::manifest(BeaconEvent manifestationType,
                                 const char* alternateDevice,
                                 const char* detail) {
    BeaconRecord rec;
    rec.seq = nextSeq();
    rec.timestampNs = nowNs();
    rec.event = manifestationType;
    if (alternateDevice) rec.fields["alternate_device"] = alternateDevice;
    if (detail) rec.fields["detail"] = detail;
    emit(rec);
}

uint64_t BeaconismAuthority::currentSeq() const {
    return seq_.load();
}

uint64_t BeaconismAuthority::nextSeq() {
    return ++seq_;
}

std::vector<BeaconRecord> BeaconismAuthority::recentBeacons(size_t maxCount) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<BeaconRecord> out;
    out.reserve(std::min(maxCount, ringCount_));
    for (size_t i = 0; i < std::min(maxCount, ringCount_); ++i) {
        size_t idx = (ringHead_ + kRingSize - 1 - i) % kRingSize;
        out.push_back(ringBuffer_[idx]);
    }
    return out;
}

void BeaconismAuthority::writeCsv(const BeaconRecord& rec) {
    std::fprintf(csvFp_, "%llu,%llu,%s,%llu,%s,%s,%s,%u,%u,%s,%s,%s,%s,%llu,%llu\n",
        (unsigned long long)rec.seq,
        (unsigned long long)rec.timestampNs,
        eventName(rec.event),
        (unsigned long long)rec.parentSeq,
        rec.requestId.c_str(),
        rec.agentId.c_str(),
        rec.toolId.c_str(),
        rec.tokenId,
        rec.layerId,
        rec.deviceId.c_str(),
        rec.eventPhase.c_str(),
        rec.result.c_str(),
        rec.reason.c_str(),
        (unsigned long long)rec.bytes,
        (unsigned long long)rec.durationNs);
    std::fflush(csvFp_);
}

void BeaconismAuthority::writeJsonl(const BeaconRecord& rec) {
    std::fprintf(jsonlFp_, "{\"seq\":%llu,\"ts\":%llu,\"event\":\"%s\",\"parent\":%llu",
        (unsigned long long)rec.seq,
        (unsigned long long)rec.timestampNs,
        eventName(rec.event),
        (unsigned long long)rec.parentSeq);
    if (!rec.result.empty()) std::fprintf(jsonlFp_, ",\"result\":\"%s\"", rec.result.c_str());
    if (!rec.reason.empty()) std::fprintf(jsonlFp_, ",\"reason\":\"%s\"", rec.reason.c_str());
    if (rec.bytes != 0) std::fprintf(jsonlFp_, ",\"bytes\":%llu", (unsigned long long)rec.bytes);
    if (rec.durationNs != 0) std::fprintf(jsonlFp_, ",\"dur_ns\":%llu", (unsigned long long)rec.durationNs);
    for (const auto& kv : rec.fields) {
        std::fprintf(jsonlFp_, ",\"%s\":\"%s\"", kv.first.c_str(), kv.second.c_str());
    }
    std::fprintf(jsonlFp_, "}\n");
    std::fflush(jsonlFp_);
}

void BeaconismAuthority::pushRing(const BeaconRecord& rec) {
    if (ringBuffer_.size() < kRingSize) {
        ringBuffer_.push_back(rec);
        ringHead_ = ringBuffer_.size() - 1;
    } else {
        ringHead_ = (ringHead_ + 1) % kRingSize;
        ringBuffer_[ringHead_] = rec;
    }
    if (ringCount_ < kRingSize) ++ringCount_;
}

// ---------------------------------------------------------------------------
// Scheduler Loss Analysis
// ---------------------------------------------------------------------------
BeaconismAuthority::SchedulerLossReport BeaconismAuthority::analyzeSchedulerLoss() const {
    std::lock_guard<std::mutex> lock(mutex_);
    SchedulerLossReport r;
    uint64_t gpu0BusyNs = 0, gpu1BusyNs = 0;
    uint64_t gpu1IdleWithReadyWorkNs = 0;
    uint64_t lastGpu0SubmitNs = 0, lastGpu1SubmitNs = 0;
    uint64_t handoffCount = 0, handoffNs = 0;
    uint64_t tokenCount = 0;

    for (const auto& rec : ringBuffer_) {
        switch (rec.event) {
            case BeaconEvent::TOKEN_BEGIN:
                ++tokenCount;
                break;
            case BeaconEvent::GPU_SUBMIT:
                if (rec.deviceId == "R9700") lastGpu0SubmitNs = rec.timestampNs;
                else if (rec.deviceId == "7800XT") lastGpu1SubmitNs = rec.timestampNs;
                break;
            case BeaconEvent::GPU_COMPLETE:
                if (rec.deviceId == "R9700" && rec.durationNs > 0) gpu0BusyNs += rec.durationNs;
                else if (rec.deviceId == "7800XT" && rec.durationNs > 0) gpu1BusyNs += rec.durationNs;
                break;
            case BeaconEvent::MANIFEST_GPU1_IDLE_WITH_READY_WORK:
                gpu1IdleWithReadyWorkNs += rec.durationNs;
                break;
            case BeaconEvent::GPU_HANDOFF_BEGIN:
                ++handoffCount;
                break;
            case BeaconEvent::GPU_HANDOFF_END:
                if (rec.durationNs > 0) handoffNs += rec.durationNs;
                break;
            default:
                break;
        }
    }

    r.tokenCount = tokenCount;
    r.gpu0UsefulBusyUs = gpu0BusyNs / 1000;
    r.gpu1UsefulBusyUs = gpu1BusyNs / 1000;
    r.gpu1IdleWithReadyWorkUs = gpu1IdleWithReadyWorkNs / 1000;
    r.crossGpuHandoffs = handoffCount;
    r.handoffCostUs = handoffNs / 1000;
    r.schedulerLossUs = r.gpu1IdleWithReadyWorkUs + r.handoffCostUs;

    if (r.gpu1IdleWithReadyWorkUs > r.handoffCostUs * 2) {
        r.recommendedPolicy = "AGENT_AFFINITY_PLUS_EXPERT_STEAL";
    } else if (r.handoffCostUs > r.gpu1IdleWithReadyWorkUs) {
        r.recommendedPolicy = "SINGLE_GPU_RESIDENT";
    } else {
        r.recommendedPolicy = "PIPELINE_LAYER";
    }

    return r;
}

// ---------------------------------------------------------------------------
// ScopedBeacon
// ---------------------------------------------------------------------------
ScopedBeacon::ScopedBeacon(BeaconEvent event, uint64_t parentSeq, const char* result)
    : rec_{}, closed_(false) {
    rec_.seq = BeaconismAuthority::Instance().nextSeq();
    rec_.timestampNs = nowNs();
    rec_.event = event;
    rec_.parentSeq = parentSeq;
    if (result) rec_.result = result;
    BeaconismAuthority::Instance().emit(rec_);
}

ScopedBeacon::~ScopedBeacon() {
    if (!closed_) {
        rec_.eventPhase = "END";
        rec_.durationNs = nowNs() - rec_.timestampNs;
        BeaconismAuthority::Instance().emit(rec_);
    }
}

void ScopedBeacon::setResult(const char* result) { rec_.result = result; }
void ScopedBeacon::setBytes(uint64_t bytes) { rec_.bytes = bytes; }
void ScopedBeacon::setDurationNs(uint64_t ns) { rec_.durationNs = ns; }
void ScopedBeacon::addField(const char* key, const char* value) { rec_.fields[key] = value; }

// ---------------------------------------------------------------------------
// PowerShellBeacon
// ---------------------------------------------------------------------------
uint64_t PowerShellBeacon::begin(const char* command, uint64_t parentSeq) {
    BeaconRecord rec;
    rec.seq = BeaconismAuthority::Instance().nextSeq();
    rec.timestampNs = nowNs();
    rec.event = BeaconEvent::PS_BEGIN;
    rec.parentSeq = parentSeq;
    rec.fields["command_hash"] = std::to_string(std::hash<std::string>{}(command));
    BeaconismAuthority::Instance().emit(rec);
    return rec.seq;
}

void PowerShellBeacon::pass(uint64_t beaconSeq, uint64_t durationMs) {
    BeaconismAuthority::Instance().emit(BeaconEvent::PS_PASS, beaconSeq, "PASS", nullptr, 0, durationMs * 1000000);
}

void PowerShellBeacon::fail(uint64_t beaconSeq, const char* error, uint64_t durationMs) {
    BeaconismAuthority::Instance().emit(BeaconEvent::PS_FAIL, beaconSeq, "FAIL", error, 0, durationMs * 1000000);
}

// ---------------------------------------------------------------------------
// ValidatorBeacon
// ---------------------------------------------------------------------------
uint64_t ValidatorBeacon::begin(const char* validatorName,
                                const std::unordered_map<std::string, std::string>& expected,
                                uint64_t parentSeq) {
    BeaconRecord rec;
    rec.seq = BeaconismAuthority::Instance().nextSeq();
    rec.timestampNs = nowNs();
    rec.event = BeaconEvent::VALIDATOR_BEGIN;
    rec.parentSeq = parentSeq;
    rec.fields["validator"] = validatorName;
    for (const auto& kv : expected) {
        rec.fields["expected_" + kv.first] = kv.second;
    }
    BeaconismAuthority::Instance().emit(rec);
    return rec.seq;
}

void ValidatorBeacon::pass(uint64_t beaconSeq) {
    BeaconismAuthority::Instance().emit(BeaconEvent::VALIDATOR_PASS, beaconSeq, "PASS");
}

void ValidatorBeacon::fail(uint64_t beaconSeq,
                           const std::unordered_map<std::string, std::string>& observed,
                           const char* reason) {
    BeaconRecord rec;
    rec.seq = BeaconismAuthority::Instance().nextSeq();
    rec.timestampNs = nowNs();
    rec.event = BeaconEvent::VALIDATOR_FAIL;
    rec.parentSeq = beaconSeq;
    rec.reason = reason;
    for (const auto& kv : observed) {
        rec.fields["observed_" + kv.first] = kv.second;
    }
    BeaconismAuthority::Instance().emit(rec);
}

} // namespace Deep2
