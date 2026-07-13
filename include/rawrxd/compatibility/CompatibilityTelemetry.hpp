#pragma once

#include "rawrxd/compatibility/ArchitectureDetector.hpp"
#include "rawrxd/compatibility/ModelCapabilities.hpp"
#include <string>
#include <vector>
#include <chrono>
#include <memory>

namespace rawrxd {
namespace compatibility {

// Telemetry event types
enum class TelemetryEventType {
    MODEL_LOAD,
    ARCHITECTURE_DETECTED,
    ADAPTER_CREATED,
    KERNEL_SELECTED,
    INFERENCE_START,
    INFERENCE_COMPLETE,
    FALLBACK_TRIGGERED,
    ERROR_OCCURRED,
    WARNING_EMITTED
};

// Single telemetry event
struct TelemetryEvent {
    TelemetryEventType type;
    std::chrono::system_clock::time_point timestamp;
    std::string architecture;
    std::string modelPath;
    std::unordered_map<std::string, std::string> properties;
    float durationMs = 0.0f;
};

// Compatibility telemetry data
struct CompatibilityTelemetryData {
    // Model information
    std::string detectedArchitecture;
    std::string selectedAdapter;
    int contextLength = 0;
    std::string ropeVariant;
    std::string attentionImplementation;
    
    // Capabilities
    ModelCapabilities capabilities;
    
    // Configuration
    std::vector<std::string> compatibilityWarnings;
    std::vector<std::string> selectedKernels;
    std::unordered_map<std::string, std::string> configValues;
    
    // Performance
    float loadTimeMs = 0.0f;
    float adapterInitTimeMs = 0.0f;
    int inferenceCount = 0;
    float avgInferenceTimeMs = 0.0f;
    
    // Issues
    int fallbackCount = 0;
    int errorCount = 0;
    int warningCount = 0;
    std::vector<std::string> recentErrors;
    std::vector<std::string> recentWarnings;
};

// Telemetry emitter for compatibility layer
class CompatibilityTelemetry {
public:
    CompatibilityTelemetry();
    ~CompatibilityTelemetry() = default;

    // Event emission
    void EmitModelLoad(const std::string& modelPath, const std::string& arch, float durationMs);
    void EmitArchitectureDetected(const std::string& arch, float confidence);
    void EmitAdapterCreated(const std::string& adapterType, float durationMs);
    void EmitKernelSelected(const std::string& kernelName, const std::string& reason);
    void EmitInferenceStart(const std::string& modelPath);
    void EmitInferenceComplete(float durationMs, int tokensGenerated);
    void EmitFallbackTriggered(const std::string& reason);
    void EmitError(const std::string& error);
    void EmitWarning(const std::string& warning);
    
    // Set context information
    void SetArchitecture(const std::string& arch);
    void SetModelPath(const std::string& path);
    void SetContextLength(int length);
    void SetRoPEVariant(const std::string& variant);
    void SetAttentionImplementation(const std::string& impl);
    void SetCapabilities(const ModelCapabilities& caps);
    
    // Get telemetry data
    CompatibilityTelemetryData GetData() const { return data_; }
    std::vector<TelemetryEvent> GetEvents() const { return events_; }
    
    // Export formats
    std::string ExportToJSON() const;
    std::string ExportToMarkdown() const;
    std::string GetDebugReport() const;
    
    // Reset
    void Reset();
    
    // Enable/disable
    void SetEnabled(bool enabled) { enabled_ = enabled; }
    bool IsEnabled() const { return enabled_; }

private:
    bool enabled_ = true;
    CompatibilityTelemetryData data_;
    std::vector<TelemetryEvent> events_;
    std::chrono::system_clock::time_point sessionStart_;
    
    void AddEvent(TelemetryEventType type);
    std::string EventTypeToString(TelemetryEventType type) const;
    std::string GetTimestamp() const;
};

// Global telemetry accessor (optional singleton pattern)
class CompatibilityTelemetryManager {
public:
    static CompatibilityTelemetry& GetInstance();
    static void ResetInstance();
    
private:
    static std::unique_ptr<CompatibilityTelemetry> instance_;
};

} // namespace compatibility
} // namespace rawrxd
