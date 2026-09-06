// SelfModel.cpp — performance profile from GpuDecodeEfficiencyAuthority
#include "SelfModel.hpp"
#include "../core/GpuDecodeEfficiency.hpp"

namespace RawrXD {
namespace MetaCognition {

std::unique_ptr<ISelfModelEngine> g_self_model_engine;

LocalSelfModelEngine::LocalSelfModelEngine() = default;
LocalSelfModelEngine::~LocalSelfModelEngine() = default;

bool LocalSelfModelEngine::Initialize(const std::string& config_path) {
    (void)config_path;
    initialized_ = true;
    return true;
}

void LocalSelfModelEngine::Shutdown() { initialized_ = false; }

SelfModel LocalSelfModelEngine::GenerateSelfModel() {
    SynchronizeWithTelemetry();
    SelfModel m;
    m.model_id = "local";
    m.generated_at = std::chrono::system_clock::now();
    m.current_performance = current_performance_;
    return m;
}

std::string LocalSelfModelEngine::SerializeSelfModel(const SelfModel& model) {
    (void)model;
    return "{}";
}

std::optional<SelfModel> LocalSelfModelEngine::DeserializeSelfModel(
    const std::string& serialized) {
    (void)serialized;
    return std::nullopt;
}

bool LocalSelfModelEngine::RegisterCapability(const Capability& capability) {
    capabilities_[capability.type] = capability;
    return true;
}

bool LocalSelfModelEngine::UpdateCapability(CapabilityType type,
                                            const Capability& capability) {
    capabilities_[type] = capability;
    return true;
}

bool LocalSelfModelEngine::EnableCapability(CapabilityType type) {
    if (auto it = capabilities_.find(type); it != capabilities_.end()) {
        it->second.is_enabled = true;
        return true;
    }
    return false;
}

bool LocalSelfModelEngine::DisableCapability(CapabilityType type) {
    if (auto it = capabilities_.find(type); it != capabilities_.end()) {
        it->second.is_enabled = false;
        return true;
    }
    return false;
}

std::optional<Capability> LocalSelfModelEngine::GetCapability(CapabilityType type) {
    if (auto it = capabilities_.find(type); it != capabilities_.end())
        return it->second;
    return std::nullopt;
}

std::vector<Capability> LocalSelfModelEngine::ListCapabilities() {
    std::vector<Capability> out;
    for (const auto& kv : capabilities_) out.push_back(kv.second);
    return out;
}

std::vector<Capability> LocalSelfModelEngine::ListAvailableCapabilities() {
    return ListCapabilities();
}

bool LocalSelfModelEngine::CheckCapability(CapabilityType type) {
    return capabilities_.count(type) > 0;
}

std::string LocalSelfModelEngine::AddLimitation(const Limitation& limitation) {
    limitations_[limitation.id] = limitation;
    return limitation.id;
}

bool LocalSelfModelEngine::RemoveLimitation(const std::string& limitation_id) {
    return limitations_.erase(limitation_id) > 0;
}

bool LocalSelfModelEngine::UpdateLimitation(const Limitation& limitation) {
    limitations_[limitation.id] = limitation;
    return true;
}

std::vector<Limitation> LocalSelfModelEngine::ListLimitations() {
    std::vector<Limitation> out;
    for (const auto& kv : limitations_) out.push_back(kv.second);
    return out;
}

std::vector<Limitation> LocalSelfModelEngine::ListBlockingLimitations() {
    return {};
}

bool LocalSelfModelEngine::IsCapabilityBlocked(CapabilityType type) {
    (void)type;
    return false;
}

void LocalSelfModelEngine::RecordPerformance(const PerformanceProfile& profile) {
    current_performance_ = profile;
    performance_history_.push_back(profile);
    PrunePerformanceHistory();
}

PerformanceProfile LocalSelfModelEngine::GetCurrentPerformance() {
    SynchronizeWithTelemetry();
    return current_performance_;
}

std::vector<PerformanceProfile> LocalSelfModelEngine::GetPerformanceHistory(
    std::chrono::hours lookback) {
    (void)lookback;
    return performance_history_;
}

PerformanceProfile LocalSelfModelEngine::GetPerformanceBaseline() {
    return baseline_performance_;
}

bool LocalSelfModelEngine::DetectPerformanceRegression() { return false; }

bool LocalSelfModelEngine::CanExecute(const std::string& task_type) {
    (void)task_type;
    return true;
}

std::vector<std::string> LocalSelfModelEngine::GetExecutionRequirements(
    const std::string& task_type) {
    (void)task_type;
    return {};
}

double LocalSelfModelEngine::EstimateExecutionCost(const std::string& task_type) {
    (void)task_type;
    return 0.0;
}

std::vector<std::string> LocalSelfModelEngine::SuggestAlternativeApproaches(
    const std::string& task_type) {
    (void)task_type;
    return {};
}

bool LocalSelfModelEngine::ValidateSelfModel(const SelfModel& model) {
    (void)model;
    return true;
}

std::vector<std::string> LocalSelfModelEngine::GetModelDiscrepancies() {
    return {};
}

bool LocalSelfModelEngine::SynchronizeWithTelemetry() {
    const auto& eff = rawrxd::GpuDecodeEfficiencyAuthority::Instance().Last();
    current_performance_.measured_at = std::chrono::system_clock::now();
    current_performance_.throughput_tokens_per_sec = eff.decode_tps;
    current_performance_.tokens_per_watt_gpu =
        eff.power_valid ? eff.tokens_per_watt_gpu : -1.0;
    current_performance_.tokens_per_watt_system = -1.0;
    return true;
}

bool LocalSelfModelEngine::ProbeCapability(CapabilityType type) {
    (void)type;
    return false;
}

double LocalSelfModelEngine::CalculateHealthScore() { return 1.0; }

bool LocalSelfModelEngine::CheckDependencies(CapabilityType type) {
    (void)type;
    return true;
}

void LocalSelfModelEngine::PrunePerformanceHistory() {
    if (performance_history_.size() > 1024)
        performance_history_.erase(performance_history_.begin(),
                                   performance_history_.begin() + 512);
}

bool InitializeSelfModelEngine(const std::string& config_path) {
    g_self_model_engine = std::make_unique<LocalSelfModelEngine>();
    return g_self_model_engine->Initialize(config_path);
}

void ShutdownSelfModelEngine() {
    if (g_self_model_engine) g_self_model_engine->Shutdown();
    g_self_model_engine.reset();
}

bool IsSelfModelEngineEnabled() { return g_self_model_engine != nullptr; }

std::string CapabilityTypeToString(CapabilityType type) {
    (void)type;
    return "unknown";
}

CapabilityType CapabilityTypeFromString(const std::string& str) {
    (void)str;
    return CapabilityType::INFERENCE_MODEL;
}

} // namespace MetaCognition
} // namespace RawrXD
