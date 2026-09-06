// Fail-closed HeadlessIDE — linked only when RAWRXD_OPTIONAL_CLOUD=OFF
// (and Ollama adapters OFF). Real TU: HeadlessIDE.cpp (optional adapter target).
#include "HeadlessIDE.h"

class HeadlessIDE::ConversationManager {
public:
    ConversationManager() = default;
    ~ConversationManager() = default;
};

void AgentHistoryDeleter::operator()(AgentHistoryRecorder* ptr) const
{
    delete ptr;
}

HeadlessIDE::HeadlessIDE() = default;

HeadlessIDE::~HeadlessIDE()
{
    m_shutdownRequested.store(true);
    m_running.store(false);
    m_conversationManager.reset();
}

void HeadlessIDE::safeAppendOutput(const char*, OutputSeverity) {}
void HeadlessIDE::safeOnAgentStarted(const char*, const char*) {}
void HeadlessIDE::safeOnAgentCompleted(const char*, const char*, int) {}
void HeadlessIDE::safeOnAgentFailed(const char*, const char*) {}
void HeadlessIDE::safeOnStreamStart(const char*) {}
void HeadlessIDE::safeOnStreamEnd(const char*, bool) {}
void HeadlessIDE::safeOnStreamingToken(const char*, size_t, StreamTokenOrigin) {}
void HeadlessIDE::safeOnStatusUpdate(const char*, const char*) {}

HeadlessResult HeadlessIDE::initialize(int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (argv[i] && std::string(argv[i]) == "--help")
            return HeadlessResult::error("OPTIONAL_CLOUD=OFF", 0);
    }
    return initialize(HeadlessConfig{});
}

HeadlessResult HeadlessIDE::initialize(const HeadlessConfig& config)
{
    m_config = config;
    m_config.enableServer = false;
    return HeadlessResult::ok("OPTIONAL_CLOUD=OFF: headless adapter not linked");
}

int HeadlessIDE::run()
{
    m_running.store(true);
    m_running.store(false);
    return 1;
}

void HeadlessIDE::requestShutdown() noexcept
{
    m_shutdownRequested.store(true);
}

void HeadlessIDE::setOutputSink(std::unique_ptr<IOutputSink> sink)
{
    m_outputSink = std::move(sink);
}

std::string HeadlessIDE::getGovernorStatusJson() const
{
    return "{\"governor_activated\":false,\"optional_cloud\":0}";
}

std::string HeadlessIDE::getHotpatchStatusJson() const
{
    return "{\"hotpatch70b_activated\":false,\"layer_eviction_activated\":false,\"optional_cloud\":0}";
}

std::string HeadlessIDE::routeWithIntelligence(const std::string&) { return {}; }
std::string HeadlessIDE::getRouterStatusString() const { return {}; }
std::string HeadlessIDE::getCostLatencyHeatmapString() const { return {}; }
std::string HeadlessIDE::executeWithFailureDetection(const std::string&) { return {}; }
std::string HeadlessIDE::getFailureDetectorStats() const { return {}; }
std::string HeadlessIDE::getFailureIntelligenceStatsString() const { return {}; }
std::string HeadlessIDE::getAgentHistoryStats() const { return {}; }
void HeadlessIDE::recordSimpleEvent(const std::string&) {}
void HeadlessIDE::parseAsmFile(const std::string&) {}
void HeadlessIDE::parseAsmDirectory(const std::string&, bool) {}
std::string HeadlessIDE::getAsmSymbolTableString() const { return {}; }
std::string HeadlessIDE::getAsmSemanticStatsString() const { return {}; }
std::string HeadlessIDE::getLSPStatusString() const { return {}; }
std::string HeadlessIDE::getHybridBridgeStatusString() const { return {}; }
std::string HeadlessIDE::getGovernorStatus() const { return {}; }
std::string HeadlessIDE::getSafetyStatus() const { return {}; }
std::string HeadlessIDE::getReplayStatus() const { return {}; }
std::string HeadlessIDE::getConfidenceStatus() const { return {}; }
std::string HeadlessIDE::getSwarmStatus() const { return {}; }
std::string HeadlessIDE::getNativeDebugStatus() const { return {}; }
std::string HeadlessIDE::getHotpatchStatus() const { return {}; }
void HeadlessIDE::loadSettings(const std::string&) {}
void HeadlessIDE::saveSettings(const std::string&) {}
std::string HeadlessIDE::getSettingsFilePath() const { return {}; }
void HeadlessIDE::startServer() {}
void HeadlessIDE::stopServer() {}
bool HeadlessIDE::isServerRunning() const { return false; }
std::string HeadlessIDE::getServerStatus() const { return "OPTIONAL_CLOUD=OFF"; }
std::string HeadlessIDE::getFeatureManifestMarkdown() const { return {}; }
std::string HeadlessIDE::getFeatureManifestJSON() const { return "{}"; }
std::string HeadlessIDE::getQuantumStatusJson() const { return "{}"; }
std::string HeadlessIDE::getModelsJson() const { return "[]"; }
std::string HeadlessIDE::getModelsOllamaJson() const { return "[]"; }
std::string HeadlessIDE::getEngineCapabilitiesJson() const { return "{}"; }
std::string HeadlessIDE::performCloudInference(const std::string&, const std::string&,
                                              const std::string&, const std::string&)
{
    return {};
}
std::string HeadlessIDE::getFullStatusDump() const { return "OPTIONAL_CLOUD=OFF"; }
std::string HeadlessIDE::getVersionString() const { return {}; }
uint64_t HeadlessIDE::getUptimeMs() const { return 0; }
std::string HeadlessIDE::getInstructionsContent() const { return {}; }
