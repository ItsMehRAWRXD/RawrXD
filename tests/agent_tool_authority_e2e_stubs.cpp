// =============================================================================
// agent_tool_authority_e2e_stubs.cpp
// Stub implementations for E2E HARNESS linking (E2E_002 only)
// =============================================================================
// HARD GUARD: This file must NEVER participate in the product E2E test.
// If RAWRXD_AUTHORITY_PRODUCT_E2E is defined, compilation fails immediately.
#if defined(RAWRXD_AUTHORITY_PRODUCT_E2E)
#error "Authority PRODUCT_E2E must not compile link stubs — STUBS=0 required"
#endif

// Provides minimal stub implementations of the subsystem symbols that
// ToolRegistry.cpp references but that are not needed for the authority
// gate selftest. These stubs allow the E2E selftest to link and run
// without pulling in the full product dependency chain.
//
// All stubs are no-ops or return safe defaults. They are NOT used in
// production builds — only for the standalone E2E selftest.
// =============================================================================

#include "agentic_observability.h"
#include "rawrxd_subsystem_api.hpp"
#include "core/unified_hotpatch_manager.hpp"
#include "agentic/RawrXD_ToolRegistry.h"
#include "agentic/DiskRecoveryAgent.h"

#include <string>
#include <vector>

using nlohmann::json;

// ---------------------------------------------------------------------------
// AgenticObservability stubs
// ---------------------------------------------------------------------------
AgenticObservability::AgenticObservability() {}
AgenticObservability::~AgenticObservability() {}

void AgenticObservability::log(LogLevel, const std::string&, const std::string&, const json&) {}
void AgenticObservability::logDebug(const std::string&, const std::string&, const json&) {}
void AgenticObservability::logInfo(const std::string&, const std::string&, const json&) {}
void AgenticObservability::logWarn(const std::string&, const std::string&, const json&) {}
void AgenticObservability::logError(const std::string&, const std::string&, const json&) {}
void AgenticObservability::logCritical(const std::string&, const std::string&, const json&) {}

std::vector<AgenticObservability::LogEntry> AgenticObservability::getLogs(int, LogLevel, const std::string&) const { return {}; }
std::vector<AgenticObservability::LogEntry> AgenticObservability::getLogsByTimeRange(const TimePoint&, const TimePoint&, LogLevel) const { return {}; }

void AgenticObservability::recordMetric(const std::string&, float, const json&, const std::string&) {}
void AgenticObservability::incrementCounter(const std::string&, int, const json&) {}
float AgenticObservability::getCounterValue(const std::string&) const { return 0.0f; }
void AgenticObservability::setGauge(const std::string&, float, const json&) {}
float AgenticObservability::getGaugeValue(const std::string&) const { return 0.0f; }
void AgenticObservability::recordHistogram(const std::string&, float, const json&) {}
json AgenticObservability::getHistogramStats(const std::string&) const { return json::object(); }
std::vector<AgenticObservability::MetricPoint> AgenticObservability::getMetrics(const std::string&, int) const { return {}; }
json AgenticObservability::getMetricsSummary() const { return json::object(); }
json AgenticObservability::getPercentiles(const std::string&) const { return json::object(); }

AgenticObservability::TimingGuard::TimingGuard(AgenticObservability*, const std::string&) {}
AgenticObservability::TimingGuard::~TimingGuard() {}
std::unique_ptr<AgenticObservability::TimingGuard> AgenticObservability::measureDuration(const std::string&) { return nullptr; }

std::string AgenticObservability::startTrace(const std::string&) { return ""; }
std::string AgenticObservability::startSpan(const std::string&, const std::string&) { return ""; }
void AgenticObservability::endSpan(const std::string&, bool, const std::string&, int) {}

// ---------------------------------------------------------------------------
// SubsystemRegistry stubs (instance() is inline in header — only need ctor)
// ---------------------------------------------------------------------------
SubsystemRegistry::SubsystemRegistry() {}
SubsystemResult SubsystemRegistry::invoke(const SubsystemParams&) {
    SubsystemResult r;
    r.success = false;
    return r;
}
SubsystemResult SubsystemRegistry::invokeBySwitch(const char*) {
    SubsystemResult r;
    r.success = false;
    return r;
}
bool SubsystemRegistry::isAvailable(SubsystemId) const { return false; }
const char* SubsystemRegistry::getSwitchName(SubsystemId) const { return nullptr; }
SubsystemRegistry::ModeStats SubsystemRegistry::getStats(SubsystemId) const { return {}; }

// ---------------------------------------------------------------------------
// Subsystem mode handler stubs (extern "C" — red team/security tools)
// These are not needed for the authority gate test.
// ---------------------------------------------------------------------------
extern "C" {
    void CompileMode(void) {}
    void EncryptMode(void) {}
    void InjectMode(void) {}
    void UACBypassMode(void) {}
    void PersistenceMode(void) {}
    void SideloadMode(void) {}
    void AVScanMode(void) {}
    void EntropyMode(void) {}
    void StubGenMode(void) {}
    void TraceEngineMode(void) {}
    void AgenticMode(void) {}
    void BasicBlockCovMode(void) {}
    void CovFusionMode(void) {}
    void DynTraceMode(void) {}
    void AgentTraceMode(void) {}
    void GapFuzzMode(void) {}
    void IntelPTMode(void) {}
    void DiffCovMode(void) {}
    void AD_ProcessGGUF(void) {}
    void SO_LoadExecFile(void) {}
    void SO_InitializeVulkan(void) {}
    void SO_CreateMemoryArena(void) {}
    void SO_CreateComputePipelines(void) {}
    void SO_PrintStatistics(void) {}
    void SO_InitializeStreaming(void) {}
}

// ---------------------------------------------------------------------------
// UnifiedHotpatchManager stubs
// ---------------------------------------------------------------------------
UnifiedHotpatchManager& UnifiedHotpatchManager::instance() {
    static UnifiedHotpatchManager inst;
    return inst;
}
UnifiedHotpatchManager::UnifiedHotpatchManager() {}
UnifiedHotpatchManager::~UnifiedHotpatchManager() {}
UnifiedResult UnifiedHotpatchManager::apply_memory_patch(void*, size_t, const void*) {
    UnifiedResult r;
    r.result.success = false;
    return r;
}
UnifiedResult UnifiedHotpatchManager::apply_byte_search_patch(const char*, const std::vector<uint8_t>&, const std::vector<uint8_t>&) {
    UnifiedResult r;
    r.result.success = false;
    return r;
}
UnifiedResult UnifiedHotpatchManager::remove_server_patch(const char*) {
    UnifiedResult r;
    r.result.success = false;
    return r;
}

// ---------------------------------------------------------------------------
// Legacy RawrXD::Agent::ToolRegistry stubs
// ---------------------------------------------------------------------------
namespace RawrXD { namespace Agent {
ToolRegistry& ToolRegistry::Instance() {
    static ToolRegistry inst;
    return inst;
}
ToolRegistry::ToolRegistry() {}
ToolRegistry::~ToolRegistry() {}
ToolResult ToolRegistry::Execute(const std::string&, const std::string&, std::string& output) {
    output = "[stub] legacy ToolRegistry::Execute";
    return ToolResult::ExecutionError;
}
}} // namespace

// ---------------------------------------------------------------------------
// DiskRecoveryAsmAgent stubs
// ---------------------------------------------------------------------------
namespace RawrXD { namespace Recovery {
DiskRecoveryAsmAgent::~DiskRecoveryAsmAgent() {}
DiskRecoveryAsmAgent::DiskRecoveryAsmAgent(DiskRecoveryAsmAgent&&) noexcept {}
DiskRecoveryAsmAgent& DiskRecoveryAsmAgent::operator=(DiskRecoveryAsmAgent&&) noexcept { return *this; }
int DiskRecoveryAsmAgent::FindDrive() { return -1; }
AsmRecoveryResult DiskRecoveryAsmAgent::Initialize(int) {
    AsmRecoveryResult r; r.success = false; return r;
}
AsmRecoveryResult DiskRecoveryAsmAgent::ExtractEncryptionKey() {
    AsmRecoveryResult r; r.success = false; return r;
}
AsmRecoveryResult DiskRecoveryAsmAgent::RunRecovery() {
    AsmRecoveryResult r; r.success = false; return r;
}
void DiskRecoveryAsmAgent::Abort() {}
AsmRecoveryStats DiskRecoveryAsmAgent::GetStats() const { return {}; }
}} // namespace