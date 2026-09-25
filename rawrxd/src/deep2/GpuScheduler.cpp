// GpuScheduler.cpp — Dual-GPU policy scheduler (fail-closed, not stub)
#include "GpuScheduler.hpp"
#include <cstdio>
#include <cstring>

namespace Deep2 {

GpuScheduler::GpuScheduler() = default;
GpuScheduler::~GpuScheduler() = default;

void GpuScheduler::registerDevice(const GpuDeviceDescriptor& desc) {
    std::lock_guard<std::mutex> lock(mutex_);
    devices_.push_back(desc);
}

void GpuScheduler::clearDevices() {
    std::lock_guard<std::mutex> lock(mutex_);
    devices_.clear();
    agentAffinities_.clear();
    tensorResidency_.clear();
    state_ = {};
}

void GpuScheduler::setPolicy(GpuPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    policy_ = policy;
}

void GpuScheduler::setPolicyFromEnv() {
    const char* env = std::getenv("DEEP2_GPU_POLICY");
    if (!env) return;
    std::string s(env);
    if      (s == "FLIP_TOKEN")      setPolicy(GpuPolicy::FLIP_TOKEN);
    else if (s == "FLIP_LAYER")      setPolicy(GpuPolicy::FLIP_LAYER);
    else if (s == "PIPELINE_LAYER")  setPolicy(GpuPolicy::PIPELINE_LAYER);
    else if (s == "SPLIT_EXPERT")    setPolicy(GpuPolicy::SPLIT_EXPERT);
    else if (s == "AGENT_AFFINITY")  setPolicy(GpuPolicy::AGENT_AFFINITY);
    else if (s == "ADAPTIVE")        setPolicy(GpuPolicy::ADAPTIVE);
}

std::string GpuScheduler::schedule(const GpuWorkItem& work) {
    std::string chosen;
    switch (policy_) {
        case GpuPolicy::FLIP_TOKEN:     chosen = scheduleFlipToken(work);     break;
        case GpuPolicy::FLIP_LAYER:     chosen = scheduleFlipLayer(work);     break;
        case GpuPolicy::PIPELINE_LAYER: chosen = schedulePipelineLayer(work); break;
        case GpuPolicy::SPLIT_EXPERT:   chosen = scheduleSplitExpert(work);   break;
        case GpuPolicy::AGENT_AFFINITY: chosen = scheduleAgentAffinity(work); break;
        case GpuPolicy::ADAPTIVE:       chosen = scheduleAdaptive(work);      break;
        default:                        chosen = scheduleSingle(work);        break;
    }
    if (beaconismEnabled_ && !chosen.empty()) {
        emitDecisionBeacon(work, chosen, {});
    }
    return chosen;
}

// FAIL-CLOSED: async submission requires real Vulkan queue — not yet wired
bool GpuScheduler::submitAsync(const GpuWorkItem&, const std::string&) {
    return false;
}

// FAIL-CLOSED: device readiness requires real fence/GPU event — not yet wired
bool GpuScheduler::deviceReady(const std::string&) const {
    return false;
}

// FAIL-CLOSED: handoff requires real GPU→GPU transfer via pinned staging
bool GpuScheduler::handoffTokenState(uint32_t,
                                      const std::string&,
                                      const std::string&) {
    return false;
}

std::vector<std::string> GpuScheduler::scheduleExperts(
    const std::vector<uint32_t>& expertIds, uint32_t) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    if (devices_.empty()) return out;
    for (size_t i = 0; i < expertIds.size(); ++i)
        out.push_back(devices_[i % devices_.size()].name);
    return out;
}

void GpuScheduler::setAgentAffinity(const std::string& agentId,
                                     const std::string& device) {
    std::lock_guard<std::mutex> lock(mutex_);
    agentAffinities_[agentId] = device;
}

std::string GpuScheduler::getAgentAffinity(const std::string& agentId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = agentAffinities_.find(agentId);
    return (it != agentAffinities_.end()) ? it->second : "";
}

void GpuScheduler::markTensorResident(const std::string& tensorName,
                                       const std::string& device) {
    std::lock_guard<std::mutex> lock(mutex_);
    tensorResidency_[tensorName][device] = true;
}

void GpuScheduler::markTensorEvicted(const std::string& tensorName,
                                       const std::string& device) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensorResidency_.find(tensorName);
    if (it != tensorResidency_.end())
        it->second.erase(device);
}

// FAIL-CLOSED: only return true if we have an explicit residency record
bool GpuScheduler::isTensorResident(const std::string& tensorName,
                                       const std::string& device) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensorResidency_.find(tensorName);
    if (it == tensorResidency_.end()) return false;
    auto dit = it->second.find(device);
    return (dit != it->second.end()) && dit->second;
}

DeviceScore GpuScheduler::scoreDevice(const std::string& deviceName,
                                       const GpuWorkItem& work) const {
    std::lock_guard<std::mutex> lock(mutex_);
    DeviceScore ds;
    ds.deviceName = deviceName;
    const auto* dev = findDeviceUnlocked(deviceName);
    if (!dev) return ds;

    ds.tensorResident = isTensorResidentUnlocked(work.requiredTensors.empty() ? "" : work.requiredTensors[0], deviceName);

    // Compute cost model: bytes / computeCapability (higher capability = lower cost)
    ds.computeCost = (work.bytesEstimate > 0 && dev->computeCapability > 0.0f)
        ? static_cast<float>(work.bytesEstimate) / dev->computeCapability
        : 1.0e6f;

    // Transfer cost: non-resident tensors must be moved
    if (!ds.tensorResident && work.bytesEstimate > 0) {
        ds.transferCost = static_cast<float>(work.bytesEstimate) * 0.01f; // ~1% of bytes as penalty
    }

    ds.residencyCost = ds.tensorResident ? 0.0f : ds.transferCost;
    ds.totalScore = ds.computeCost + ds.transferCost + ds.residencyCost + ds.queueDelay;
    return ds;
}

void GpuScheduler::resetState() { state_ = {}; }

std::string GpuScheduler::summary() const {
    std::lock_guard<std::mutex> lock(mutex_);
    char buf[512];
    std::snprintf(buf, sizeof(buf),
        "GpuScheduler[policy=%s devices=%zu gpu0Tokens=%llu gpu1Tokens=%llu handoffs=%llu residencyMisses=%llu]",
        GpuPolicyName(policy_),
        devices_.size(),
        (unsigned long long)state_.gpu0Tokens,
        (unsigned long long)state_.gpu1Tokens,
        (unsigned long long)state_.handoffs,
        (unsigned long long)state_.residencyMisses);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Policy implementations (internal — mutex NOT acquired here; caller holds it)
// ---------------------------------------------------------------------------

std::string GpuScheduler::scheduleSingle(const GpuWorkItem&) {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.empty() ? "" : devices_[0].name;
}

std::string GpuScheduler::scheduleFlipToken(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (devices_.size() < 2) {
        return devices_.empty() ? "" : devices_[0].name;
    }
    const size_t slot = state_.tokensScheduled & 1u; // use bitwise instead of modulo
    ++state_.tokensScheduled;
    if (slot == 0) { ++state_.gpu0Tokens; return devices_[0].name; }
    else           { ++state_.gpu1Tokens; return devices_[1].name; }
}

std::string GpuScheduler::scheduleFlipLayer(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (devices_.size() < 2) {
        return devices_.empty() ? "" : devices_[0].name;
    }
    const bool use0 = (work.layerId & 1u) == 0;
    if (use0) { ++state_.gpu0Tokens; return devices_[0].name; }
    else      { ++state_.gpu1Tokens; return devices_[1].name; }
}

std::string GpuScheduler::schedulePipelineLayer(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: requires real async submission + dependency signaling
    // For now, fail-closed: schedule to GPU0 only
    (void)work;
    return devices_.empty() ? "" : devices_[0].name;
}

std::string GpuScheduler::scheduleSplitExpert(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: requires real expert residency tracking + dual-GPU dispatch
    // For now, fail-closed: schedule to GPU0 only
    (void)work;
    return devices_.empty() ? "" : devices_[0].name;
}

std::string GpuScheduler::scheduleAgentAffinity(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Look up agent affinity first; if none, fall back to SINGLE
    if (!work.targetDevice.empty()) {
        auto it = agentAffinities_.find(work.targetDevice);
        if (it != agentAffinities_.end()) {
            const std::string& devName = it->second;
            const auto* dev = findDeviceUnlocked(devName);
            if (dev && dev->available) return devName;
        }
    }
    return devices_.empty() ? "" : devices_[0].name;
}

std::string GpuScheduler::scheduleAdaptive(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: requires real execution measurements (GPU0_EXEC_US, GPU1_EXEC_US)
    // For now, fail-closed: schedule to GPU0 only
    (void)work;
    return devices_.empty() ? "" : devices_[0].name;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const GpuDeviceDescriptor* GpuScheduler::findDevice(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return findDeviceUnlocked(name);
}

const GpuDeviceDescriptor* GpuScheduler::findDeviceUnlocked(const std::string& name) const {
    for (const auto& d : devices_) {
        if (d.name == name) return &d;
    }
    return nullptr;
}

float GpuScheduler::estimateTransferCost(const std::string& from,
                                          const std::string& to,
                                          size_t bytes) const {
    // TODO: replace with measured PCIe / xGMI bandwidth
    // Conservative estimate: 16 GB/s = 16e9 bytes/s → cost = bytes / 16e9 seconds
    if (from == to) return 0.0f;
    if (bytes == 0) return 0.0f;
    return static_cast<float>(bytes) / 16.0e9f; // seconds
}

void GpuScheduler::emitDecisionBeacon(const GpuWorkItem& work,
                                       const std::string& chosenDevice,
                                       const std::vector<DeviceScore>& scores) {
    if (!beaconismEnabled_) return;
    // Minimal beacon emission — expanded when real async submission is wired
    BeaconismAuthority::Instance().emit(
        BeaconEvent::SCHEDULER_DECISION,
        work.tokenId,
        (std::string("POLICY=") + GpuPolicyName(policy_) +
         " DEVICE=" + chosenDevice +
         " LAYER=" + std::to_string(work.layerId) +
         " SCORES=" + std::to_string(scores.size())).c_str(),
        nullptr, 0, 0);
}

bool GpuScheduler::isTensorResidentUnlocked(const std::string& tensorName,
                                             const std::string& device) const {
    auto it = tensorResidency_.find(tensorName);
    if (it == tensorResidency_.end()) return false;
    auto dit = it->second.find(device);
    return (dit != it->second.end()) && dit->second;
}

} // namespace Deep2
