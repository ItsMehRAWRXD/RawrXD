// GpuScheduler.cpp — stub implementation
#include "GpuScheduler.hpp"

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
}

void GpuScheduler::setPolicy(GpuPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    policy_ = policy;
}

void GpuScheduler::setPolicyFromEnv() {
    const char* env = std::getenv("DEEP2_GPU_POLICY");
    if (!env) return;
    std::string s(env);
    if (s == "FLIP_TOKEN")      setPolicy(GpuPolicy::FLIP_TOKEN);
    else if (s == "FLIP_LAYER") setPolicy(GpuPolicy::FLIP_LAYER);
    else if (s == "PIPELINE_LAYER") setPolicy(GpuPolicy::PIPELINE_LAYER);
    else if (s == "SPLIT_EXPERT")     setPolicy(GpuPolicy::SPLIT_EXPERT);
    else if (s == "AGENT_AFFINITY")   setPolicy(GpuPolicy::AGENT_AFFINITY);
    else if (s == "ADAPTIVE")         setPolicy(GpuPolicy::ADAPTIVE);
}

std::string GpuScheduler::schedule(const GpuWorkItem& work) {
    switch (policy_) {
        case GpuPolicy::FLIP_TOKEN:    return scheduleFlipToken(work);
        case GpuPolicy::FLIP_LAYER:    return scheduleFlipLayer(work);
        case GpuPolicy::PIPELINE_LAYER: return schedulePipelineLayer(work);
        case GpuPolicy::SPLIT_EXPERT:  return scheduleSplitExpert(work);
        case GpuPolicy::AGENT_AFFINITY:return scheduleAgentAffinity(work);
        case GpuPolicy::ADAPTIVE:      return scheduleAdaptive(work);
        default:                       return scheduleSingle(work);
    }
}

bool GpuScheduler::submitAsync(const GpuWorkItem&, const std::string&) { return true; }
bool GpuScheduler::deviceReady(const std::string&) const { return true; }
bool GpuScheduler::handoffTokenState(uint32_t, const std::string&, const std::string&) { return true; }
std::vector<std::string> GpuScheduler::scheduleExperts(const std::vector<uint32_t>& expertIds, uint32_t) {
    std::vector<std::string> out;
    if (devices_.empty()) return out;
    for (size_t i = 0; i < expertIds.size(); ++i) out.push_back(devices_[i % devices_.size()].name);
    return out;
}
void GpuScheduler::setAgentAffinity(const std::string&, const std::string&) {}
std::string GpuScheduler::getAgentAffinity(const std::string&) const { return ""; }
void GpuScheduler::markTensorResident(const std::string&, const std::string&) {}
void GpuScheduler::markTensorEvicted(const std::string&, const std::string&) {}
bool GpuScheduler::isTensorResident(const std::string&, const std::string&) const { return true; }
DeviceScore GpuScheduler::scoreDevice(const std::string&, const GpuWorkItem&) const { return {}; }
void GpuScheduler::resetState() { state_ = {}; }
std::string GpuScheduler::summary() const { return "GpuScheduler[stub]"; }

std::string GpuScheduler::scheduleSingle(const GpuWorkItem&) {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.empty() ? "" : devices_[0].name;
}
std::string GpuScheduler::scheduleFlipToken(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (devices_.size() < 2) return scheduleSingle(work);
    const bool use0 = (state_.tokensScheduled % 2) == 0;
    ++state_.tokensScheduled;
    if (use0) { ++state_.gpu0Tokens; return devices_[0].name; }
    else      { ++state_.gpu1Tokens; return devices_[1].name; }
}
std::string GpuScheduler::scheduleFlipLayer(const GpuWorkItem& work) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (devices_.size() < 2) return scheduleSingle(work);
    const bool use0 = (work.layerId % 2) == 0;
    if (use0) { ++state_.gpu0Tokens; return devices_[0].name; }
    else      { ++state_.gpu1Tokens; return devices_[1].name; }
}
std::string GpuScheduler::schedulePipelineLayer(const GpuWorkItem&) {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.empty() ? "" : devices_[0].name;
}
std::string GpuScheduler::scheduleSplitExpert(const GpuWorkItem&) {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.empty() ? "" : devices_[0].name;
}
std::string GpuScheduler::scheduleAgentAffinity(const GpuWorkItem&) {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.empty() ? "" : devices_[0].name;
}
std::string GpuScheduler::scheduleAdaptive(const GpuWorkItem&) {
    std::lock_guard<std::mutex> lock(mutex_);
    return devices_.empty() ? "" : devices_[0].name;
}
const GpuDeviceDescriptor* GpuScheduler::findDevice(const std::string&) const { return nullptr; }
float GpuScheduler::estimateTransferCost(const std::string&, const std::string&, size_t) const { return 0.0f; }
void GpuScheduler::emitDecisionBeacon(const GpuWorkItem&, const std::string&, const std::vector<DeviceScore>&) {}

} // namespace Deep2
