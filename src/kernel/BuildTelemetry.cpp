// Build System Telemetry - Implementation
// Converts compiler/linker output into structured events

#include "BuildTelemetry.hpp"
#include "AgentKernel.hpp"

#include <sstream>
#include <regex>
#include <chrono>

namespace RawrXD {
namespace Kernel {

// ============================================================================
// Utility Functions
// ============================================================================

const char* BuildEventTypeToString(BuildEventType type) {
    switch (type) {
        case BuildEventType::PROCESS_STARTED: return "PROCESS_STARTED";
        case BuildEventType::PROCESS_COMPLETED: return "PROCESS_COMPLETED";
        case BuildEventType::PROCESS_FAILED: return "PROCESS_FAILED";
        case BuildEventType::PROCESS_CANCELLED: return "PROCESS_CANCELLED";
        case BuildEventType::COMPILATION_STARTED: return "COMPILATION_STARTED";
        case BuildEventType::COMPILATION_PROGRESS: return "COMPILATION_PROGRESS";
        case BuildEventType::COMPILATION_COMPLETED: return "COMPILATION_COMPLETED";
        case BuildEventType::COMPILATION_WARNING: return "COMPILATION_WARNING";
        case BuildEventType::COMPILATION_ERROR: return "COMPILATION_ERROR";
        case BuildEventType::LINK_STARTED: return "LINK_STARTED";
        case BuildEventType::LINK_PROGRESS: return "LINK_PROGRESS";
        case BuildEventType::LINK_COMPLETED: return "LINK_COMPLETED";
        case BuildEventType::LINK_ERROR: return "LINK_ERROR";
        case BuildEventType::STATIC_ANALYSIS_STARTED: return "STATIC_ANALYSIS_STARTED";
        case BuildEventType::STATIC_ANALYSIS_WARNING: return "STATIC_ANALYSIS_WARNING";
        case BuildEventType::STATIC_ANALYSIS_ERROR: return "STATIC_ANALYSIS_ERROR";
        case BuildEventType::STATIC_ANALYSIS_COMPLETED: return "STATIC_ANALYSIS_COMPLETED";
        case BuildEventType::DEPENDENCY_SCAN_STARTED: return "DEPENDENCY_SCAN_STARTED";
        case BuildEventType::DEPENDENCY_DISCOVERED: return "DEPENDENCY_DISCOVERED";
        case BuildEventType::DEPENDENCY_RESOLVED: return "DEPENDENCY_RESOLVED";
        case BuildEventType::DEPENDENCY_MISSING: return "DEPENDENCY_MISSING";
        case BuildEventType::TARGET_STARTED: return "TARGET_STARTED";
        case BuildEventType::TARGET_COMPLETED: return "TARGET_COMPLETED";
        case BuildEventType::TARGET_FAILED: return "TARGET_FAILED";
        case BuildEventType::TARGET_SKIPPED: return "TARGET_SKIPPED";
        case BuildEventType::MEMORY_PRESSURE: return "MEMORY_PRESSURE";
        case BuildEventType::DISK_IO_HIGH: return "DISK_IO_HIGH";
        case BuildEventType::CPU_THROTTLE: return "CPU_THROTTLE";
        case BuildEventType::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

static uint64_t GetTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

// ============================================================================
// BuildEvent Implementation
// ============================================================================

std::string BuildEvent::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"eventId\":" << eventId << ",";
    ss << "\"type\":\"" << BuildEventTypeToString(type) << "\",";
    ss << "\"timestamp\":" << timestamp << ",";
    ss << "\"processId\":" << processId << ",";
    ss << "\"sourceFile\":\"" << sourceFile << "\",";
    ss << "\"lineNumber\":" << lineNumber << ",";
    ss << "\"columnNumber\":" << columnNumber << ",";
    ss << "\"severity\":" << static_cast<int>(severity) << ",";
    ss << "\"message\":\"" << message << "\",";
    ss << "\"toolName\":\"" << toolName << "\",";
    ss << "\"targetName\":\"" << targetName << "\",";
    ss << "\"progressPercent\":" << progressPercent << ",";
    ss << "\"memoryUsageMB\":" << memoryUsageMB << ",";
    ss << "\"durationMs\":" << durationMs;
    ss << "}";
    return ss.str();
}

// ============================================================================
// BuildTelemetryCollector Implementation
// ============================================================================

BuildTelemetryCollector& BuildTelemetryCollector::Instance() {
    static BuildTelemetryCollector instance;
    return instance;
}

void BuildTelemetryCollector::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Register built-in parsers
    parsers_.push_back(std::make_unique<MSVCErrorParser>());
    parsers_.push_back(std::make_unique<ClangErrorParser>());
    parsers_.push_back(std::make_unique<CMakeProgressParser>());
    parsers_.push_back(std::make_unique<NinjaProgressParser>());
    parsers_.push_back(std::make_unique<LinkerErrorParser>());
    
    isInitialized_.store(true);
}

void BuildTelemetryCollector::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    parsers_.clear();
    isInitialized_.store(false);
}

void BuildTelemetryCollector::RegisterParser(std::unique_ptr<BuildOutputParser> parser) {
    std::lock_guard<std::mutex> lock(mutex_);
    parsers_.push_back(std::move(parser));
}

std::vector<BuildEvent> BuildTelemetryCollector::ParseOutput(
    const std::string& rawOutput,
    uint64_t processId
) {
    std::vector<BuildEvent> events;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Try each parser
    for (auto& parser : parsers_) {
        auto parserEvents = parser->Parse(rawOutput, processId);
        events.insert(events.end(), parserEvents.begin(), parserEvents.end());
    }
    
    // Sort by timestamp
    std::sort(events.begin(), events.end(), 
        [](const BuildEvent& a, const BuildEvent& b) {
            return a.timestamp < b.timestamp;
        });
    
    return events;
}

void BuildTelemetryCollector::EmitEvent(const BuildEvent& event) {
    // Send to Beacon Bus
    BeaconEvent beacon;
    beacon.eventId = event.eventId;
    beacon.type = BeaconType::BUILD_STARTED; // Map from BuildEventType
    beacon.timestamp = std::chrono::steady_clock::now();
    beacon.sourceAgent = 0; // System agent
    beacon.associatedIntent = 0;
    beacon.metadata["buildEvent"] = event.ToJson();
    
    // Publish to subscribers
    for (auto& callback : eventCallbacks_) {
        callback(event);
    }
}

void BuildTelemetryCollector::SubscribeToEvents(BuildEventCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    eventCallbacks_.push_back(callback);
}

// ============================================================================
// MSVC Error Parser
// ============================================================================

std::vector<BuildEvent> MSVCErrorParser::Parse(
    const std::string& output,
    uint64_t processId
) {
    std::vector<BuildEvent> events;
    
    // MSVC error pattern: file(line,column): error/warning CXXXX: message
    std::regex msvcPattern(R"((.+?)\((\d+),(\d+)\):\s*(error|warning)\s+(\w+\d+):\s*(.+))");
    
    std::sregex_iterator iter(output.begin(), output.end(), msvcPattern);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        const std::smatch& match = *iter;
        
        BuildEvent event;
        event.eventId = nextEventId_++;
        event.timestamp = GetTimestamp();
        event.processId = processId;
        event.sourceFile = match[1].str();
        event.lineNumber = std::stoul(match[2].str());
        event.columnNumber = std::stoul(match[3].str());
        event.severity = (match[4].str() == "error") 
            ? Severity::ERROR 
            : Severity::WARNING;
        event.errorCode = match[5].str();
        event.message = match[6].str();
        event.toolName = "cl.exe";
        event.type = (event.severity == Severity::ERROR) 
            ? BuildEventType::COMPILATION_ERROR 
            : BuildEventType::COMPILATION_WARNING;
        
        events.push_back(event);
    }
    
    return events;
}

// ============================================================================
// Clang Error Parser
// ============================================================================

std::vector<BuildEvent> ClangErrorParser::Parse(
    const std::string& output,
    uint64_t processId
) {
    std::vector<BuildEvent> events;
    
    // Clang error pattern: file:line:column: error/warning: message
    std::regex clangPattern(R"((.+?):(\d+):(\d+):\s*(error|warning|note):\s*(.+))");
    
    std::sregex_iterator iter(output.begin(), output.end(), clangPattern);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        const std::smatch& match = *iter;
        
        BuildEvent event;
        event.eventId = nextEventId_++;
        event.timestamp = GetTimestamp();
        event.processId = processId;
        event.sourceFile = match[1].str();
        event.lineNumber = std::stoul(match[2].str());
        event.columnNumber = std::stoul(match[3].str());
        
        std::string severityStr = match[4].str();
        if (severityStr == "error") {
            event.severity = Severity::ERROR;
            event.type = BuildEventType::COMPILATION_ERROR;
        } else if (severityStr == "warning") {
            event.severity = Severity::WARNING;
            event.type = BuildEventType::COMPILATION_WARNING;
        } else {
            event.severity = Severity::INFO;
            event.type = BuildEventType::CUSTOM;
        }
        
        event.message = match[5].str();
        event.toolName = "clang";
        
        events.push_back(event);
    }
    
    return events;
}

// ============================================================================
// CMake Progress Parser
// ============================================================================

std::vector<BuildEvent> CMakeProgressParser::Parse(
    const std::string& output,
    uint64_t processId
) {
    std::vector<BuildEvent> events;
    
    // CMake configure progress: -- Configuring done
    if (output.find("-- Configuring done") != std::string::npos) {
        BuildEvent event;
        event.eventId = nextEventId_++;
        event.timestamp = GetTimestamp();
        event.processId = processId;
        event.type = BuildEventType::TARGET_COMPLETED;
        event.severity = Severity::INFO;
        event.message = "CMake configuration completed";
        event.toolName = "cmake";
        event.targetName = "configure";
        event.progressPercent = 100;
        events.push_back(event);
    }
    
    // CMake build progress: [ 12%] Building CXX object ...
    std::regex progressPattern(R"(\[\s*(\d+)%\])");
    std::sregex_iterator iter(output.begin(), output.end(), progressPattern);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        const std::smatch& match = *iter;
        
        BuildEvent event;
        event.eventId = nextEventId_++;
        event.timestamp = GetTimestamp();
        event.processId = processId;
        event.type = BuildEventType::COMPILATION_PROGRESS;
        event.severity = Severity::INFO;
        event.progressPercent = std::stoul(match[1].str());
        event.toolName = "cmake";
        
        events.push_back(event);
    }
    
    return events;
}

// ============================================================================
// Ninja Progress Parser
// ============================================================================

std::vector<BuildEvent> NinjaProgressParser::Parse(
    const std::string& output,
    uint64_t processId
) {
    std::vector<BuildEvent> events;
    
    // Ninja progress: [42/100] Compiling ...
    std::regex ninjaPattern(R"(\[(\d+)/(\d+)\])");
    std::sregex_iterator iter(output.begin(), output.end(), ninjaPattern);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        const std::smatch& match = *iter;
        
        uint32_t current = std::stoul(match[1].str());
        uint32_t total = std::stoul(match[2].str());
        
        BuildEvent event;
        event.eventId = nextEventId_++;
        event.timestamp = GetTimestamp();
        event.processId = processId;
        event.type = BuildEventType::COMPILATION_PROGRESS;
        event.severity = Severity::INFO;
        event.progressPercent = (total > 0) ? (current * 100 / total) : 0;
        event.toolName = "ninja";
        
        events.push_back(event);
    }
    
    return events;
}

// ============================================================================
// Linker Error Parser
// ============================================================================

std::vector<BuildEvent> LinkerErrorParser::Parse(
    const std::string& output,
    uint64_t processId
) {
    std::vector<BuildEvent> events;
    
    // Linker error patterns
    std::vector<std::pair<std::regex, std::string>> patterns = {
        {std::regex(R"((\w+)\.obj : error LNK\d+: (.+))"), "msvc_link"},
        {std::regex(R"((undefined reference to `(.+)'))"), "ld"},
        {std::regex(R"((cannot find -l(.+)))"), "ld"},
    };
    
    for (const auto& [pattern, tool] : patterns) {
        std::sregex_iterator iter(output.begin(), output.end(), pattern);
        std::sregex_iterator end;
        
        for (; iter != end; ++iter) {
            const std::smatch& match = *iter;
            
            BuildEvent event;
            event.eventId = nextEventId_++;
            event.timestamp = GetTimestamp();
            event.processId = processId;
            event.type = BuildEventType::LINK_ERROR;
            event.severity = Severity::ERROR;
            event.message = match[0].str();
            event.toolName = tool;
            
            events.push_back(event);
        }
    }
    
    return events;
}

// ============================================================================
// Build Process Hook
// ============================================================================

BuildProcessHook::BuildProcessHook(uint64_t processId, const std::string& command)
    : processId_(processId)
    , command_(command)
    , startTime_(GetTimestamp())
{
    // Emit process started event
    BuildEvent event;
    event.eventId = 0;
    event.timestamp = startTime_;
    event.processId = processId_;
    event.type = BuildEventType::PROCESS_STARTED;
    event.severity = Severity::INFO;
    event.message = "Build process started: " + command_;
    event.toolName = "kernel";
    
    BuildTelemetryCollector::Instance().EmitEvent(event);
}

BuildProcessHook::~BuildProcessHook() {
    uint64_t endTime = GetTimestamp();
    
    BuildEvent event;
    event.eventId = 0;
    event.timestamp = endTime;
    event.processId = processId_;
    event.type = success_ ? BuildEventType::PROCESS_COMPLETED 
                          : BuildEventType::PROCESS_FAILED;
    event.severity = success_ ? Severity::INFO : Severity::ERROR;
    event.message = success_ ? "Build process completed successfully" 
                              : "Build process failed";
    event.toolName = "kernel";
    event.durationMs = endTime - startTime_;
    
    BuildTelemetryCollector::Instance().EmitEvent(event);
}

void BuildProcessHook::OnOutput(const std::string& output) {
    auto events = BuildTelemetryCollector::Instance().ParseOutput(output, processId_);
    
    for (const auto& event : events) {
        BuildTelemetryCollector::Instance().EmitEvent(event);
    }
}

void BuildProcessHook::SetSuccess(bool success) {
    success_ = success;
}

} // namespace Kernel
} // namespace RawrXD
