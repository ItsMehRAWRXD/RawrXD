#include "rawrxd/compatibility/CompatibilityTelemetry.hpp"
#include <sstream>
#include <iomanip>

namespace rawrxd {
namespace compatibility {

// Static member initialization
std::unique_ptr<CompatibilityTelemetry> CompatibilityTelemetryManager::instance_ = nullptr;

CompatibilityTelemetryManager::GetInstance() {
    if (!instance_) {
        instance_ = std::make_unique<CompatibilityTelemetry>();
    }
    return *instance_;
}

void CompatibilityTelemetryManager::ResetInstance() {
    instance_.reset();
}

CompatibilityTelemetry::CompatibilityTelemetry() {
    sessionStart_ = std::chrono::system_clock::now();
}

void CompatibilityTelemetry::EmitModelLoad(const std::string& modelPath, 
                                           const std::string& arch, 
                                           float durationMs) {
    if (!enabled_) return;
    
    data_.detectedArchitecture = arch;
    data_.loadTimeMs = durationMs;
    
    TelemetryEvent event;
    event.type = TelemetryEventType::MODEL_LOAD;
    event.timestamp = std::chrono::system_clock::now();
    event.architecture = arch;
    event.modelPath = modelPath;
    event.durationMs = durationMs;
    event.properties["architecture"] = arch;
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitArchitectureDetected(const std::string& arch, float confidence) {
    if (!enabled_) return;
    
    data_.detectedArchitecture = arch;
    
    TelemetryEvent event;
    event.type = TelemetryEventType::ARCHITECTURE_DETECTED;
    event.timestamp = std::chrono::system_clock::now();
    event.architecture = arch;
    event.properties["confidence"] = std::to_string(confidence);
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitAdapterCreated(const std::string& adapterType, float durationMs) {
    if (!enabled_) return;
    
    data_.selectedAdapter = adapterType;
    data_.adapterInitTimeMs = durationMs;
    
    TelemetryEvent event;
    event.type = TelemetryEventType::ADAPTER_CREATED;
    event.timestamp = std::chrono::system_clock::now();
    event.durationMs = durationMs;
    event.properties["adapter_type"] = adapterType;
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitKernelSelected(const std::string& kernelName, 
                                                const std::string& reason) {
    if (!enabled_) return;
    
    data_.selectedKernels.push_back(kernelName);
    
    TelemetryEvent event;
    event.type = TelemetryEventType::KERNEL_SELECTED;
    event.timestamp = std::chrono::system_clock::now();
    event.properties["kernel"] = kernelName;
    event.properties["reason"] = reason;
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitInferenceStart(const std::string& modelPath) {
    if (!enabled_) return;
    
    TelemetryEvent event;
    event.type = TelemetryEventType::INFERENCE_START;
    event.timestamp = std::chrono::system_clock::now();
    event.modelPath = modelPath;
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitInferenceComplete(float durationMs, int tokensGenerated) {
    if (!enabled_) return;
    
    data_.inferenceCount++;
    // Update rolling average
    data_.avgInferenceTimeMs = (data_.avgInferenceTimeMs * (data_.inferenceCount - 1) + durationMs) 
                               / data_.inferenceCount;
    
    TelemetryEvent event;
    event.type = TelemetryEventType::INFERENCE_COMPLETE;
    event.timestamp = std::chrono::system_clock::now();
    event.durationMs = durationMs;
    event.properties["tokens_generated"] = std::to_string(tokensGenerated);
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitFallbackTriggered(const std::string& reason) {
    if (!enabled_) return;
    
    data_.fallbackCount++;
    
    TelemetryEvent event;
    event.type = TelemetryEventType::FALLBACK_TRIGGERED;
    event.timestamp = std::chrono::system_clock::now();
    event.properties["reason"] = reason;
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitError(const std::string& error) {
    if (!enabled_) return;
    
    data_.errorCount++;
    data_.recentErrors.push_back(error);
    if (data_.recentErrors.size() > 10) {
        data_.recentErrors.erase(data_.recentErrors.begin());
    }
    
    TelemetryEvent event;
    event.type = TelemetryEventType::ERROR_OCCURRED;
    event.timestamp = std::chrono::system_clock::now();
    event.properties["error"] = error;
    
    events_.push_back(event);
}

void CompatibilityTelemetry::EmitWarning(const std::string& warning) {
    if (!enabled_) return;
    
    data_.warningCount++;
    data_.compatibilityWarnings.push_back(warning);
    data_.recentWarnings.push_back(warning);
    if (data_.recentWarnings.size() > 10) {
        data_.recentWarnings.erase(data_.recentWarnings.begin());
    }
    
    TelemetryEvent event;
    event.type = TelemetryEventType::WARNING_EMITTED;
    event.timestamp = std::chrono::system_clock::now();
    event.properties["warning"] = warning;
    
    events_.push_back(event);
}

void CompatibilityTelemetry::SetArchitecture(const std::string& arch) {
    data_.detectedArchitecture = arch;
}

void CompatibilityTelemetry::SetModelPath(const std::string& path) {
    data_.modelPath = path;
}

void CompatibilityTelemetry::SetContextLength(int length) {
    data_.contextLength = length;
}

void CompatibilityTelemetry::SetRoPEVariant(const std::string& variant) {
    data_.ropeVariant = variant;
}

void CompatibilityTelemetry::SetAttentionImplementation(const std::string& impl) {
    data_.attentionImplementation = impl;
}

void CompatibilityTelemetry::SetCapabilities(const ModelCapabilities& caps) {
    data_.capabilities = caps;
}

std::string CompatibilityTelemetry::ExportToJSON() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"compatibility_telemetry\": {\n";
    json << "    \"session_info\": {\n";
    json << "      \"start_time\": \"" << GetTimestamp() << "\",\n";
    json << "      \"event_count\": " << events_.size() << "\n";
    json << "    },\n";
    
    json << "    \"model_info\": {\n";
    json << "      \"architecture\": \"" << data_.detectedArchitecture << "\",\n";
    json << "      \"adapter\": \"" << data_.selectedAdapter << "\",\n";
    json << "      \"context_length\": " << data_.contextLength << ",\n";
    json << "      \"rope_variant\": \"" << data_.ropeVariant << "\",\n";
    json << "      \"attention_implementation\": \"" << data_.attentionImplementation << "\"\n";
    json << "    },\n";
    
    json << "    \"capabilities\": {\n";
    json << "      \"uses_rope\": " << (data_.capabilities.usesRope ? "true" : "false") << ",\n";
    json << "      \"uses_yarn\": " << (data_.capabilities.usesYarn ? "true" : "false") << ",\n";
    json << "      \"uses_alibi\": " << (data_.capabilities.usesAlibi ? "true" : "false") << ",\n";
    json << "      \"uses_sliding_window\": " << (data_.capabilities.usesSlidingWindow ? "true" : "false") << ",\n";
    json << "      \"uses_gqa\": " << (data_.capabilities.usesGQA ? "true" : "false") << ",\n";
    json << "      \"uses_moe\": " << (data_.capabilities.usesMoE ? "true" : "false") << ",\n";
    json << "      \"supports_long_context\": " << (data_.capabilities.supportsLongContext ? "true" : "false") << ",\n";
    json << "      \"max_context\": " << data_.capabilities.maxContextLength << "\n";
    json << "    },\n";
    
    json << "    \"performance\": {\n";
    json << "      \"load_time_ms\": " << data_.loadTimeMs << ",\n";
    json << "      \"adapter_init_time_ms\": " << data_.adapterInitTimeMs << ",\n";
    json << "      \"inference_count\": " << data_.inferenceCount << ",\n";
    json << "      \"avg_inference_time_ms\": " << std::fixed << std::setprecision(2) << data_.avgInferenceTimeMs << "\n";
    json << "    },\n";
    
    json << "    \"issues\": {\n";
    json << "      \"fallback_count\": " << data_.fallbackCount << ",\n";
    json << "      \"error_count\": " << data_.errorCount << ",\n";
    json << "      \"warning_count\": " << data_.warningCount << ",\n";
    json << "      \"warnings\": [\n";
    for (size_t i = 0; i < data_.compatibilityWarnings.size(); ++i) {
        json << "        \"" << data_.compatibilityWarnings[i] << "\"";
        if (i < data_.compatibilityWarnings.size() - 1) json << ",";
        json << "\n";
    }
    json << "      ]\n";
    json << "    },\n";
    
    json << "    \"selected_kernels\": [\n";
    for (size_t i = 0; i < data_.selectedKernels.size(); ++i) {
        json << "      \"" << data_.selectedKernels[i] << "\"";
        if (i < data_.selectedKernels.size() - 1) json << ",";
        json << "\n";
    }
    json << "    ],\n";
    
    json << "    \"events\": [\n";
    for (size_t i = 0; i < events_.size(); ++i) {
        const auto& event = events_[i];
        json << "      {\n";
        json << "        \"type\": \"" << EventTypeToString(event.type) << "\",\n";
        json << "        \"duration_ms\": " << event.durationMs << "\n";
        json << "      }";
        if (i < events_.size() - 1) json << ",";
        json << "\n";
    }
    json << "    ]\n";
    
    json << "  }\n";
    json << "}";
    
    return json.str();
}

std::string CompatibilityTelemetry::ExportToMarkdown() const {
    std::stringstream md;
    md << "# Compatibility Telemetry Report\n\n";
    md << "**Session Time:** " << GetTimestamp() << "\n\n";
    
    md << "## Model Information\n\n";
    md << "| Property | Value |\n";
    md << "|----------|-------|\n";
    md << "| Architecture | " << data_.detectedArchitecture << " |\n";
    md << "| Adapter | " << data_.selectedAdapter << " |\n";
    md << "| Context Length | " << data_.contextLength << " |\n";
    md << "| RoPE Variant | " << data_.ropeVariant << " |\n";
    md << "| Attention | " << data_.attentionImplementation << " |\n\n";
    
    md << "## Capabilities\n\n";
    md << "| Capability | Status |\n";
    md << "|------------|--------|\n";
    md << "| RoPE | " << (data_.capabilities.usesRope ? "✅" : "❌") << " |\n";
    md << "| YaRN | " << (data_.capabilities.usesYarn ? "✅" : "❌") << " |\n";
    md << "| ALiBi | " << (data_.capabilities.usesAlibi ? "✅" : "❌") << " |\n";
    md << "| Sliding Window | " << (data_.capabilities.usesSlidingWindow ? "✅" : "❌") << " |\n";
    md << "| GQA | " << (data_.capabilities.usesGQA ? "✅" : "❌") << " |\n";
    md << "| MoE | " << (data_.capabilities.usesMoE ? "✅" : "❌") << " |\n";
    md << "| Long Context | " << (data_.capabilities.supportsLongContext ? "✅" : "❌") << " |\n\n";
    
    md << "## Performance\n\n";
    md << "| Metric | Value |\n";
    md << "|--------|-------|\n";
    md << "| Load Time | " << data_.loadTimeMs << " ms |\n";
    md << "| Adapter Init | " << data_.adapterInitTimeMs << " ms |\n";
    md << "| Inferences | " << data_.inferenceCount << " |\n";
    md << "| Avg Inference | " << std::fixed << std::setprecision(2) << data_.avgInferenceTimeMs << " ms |\n\n";
    
    md << "## Issues\n\n";
    md << "| Type | Count |\n";
    md << "|------|-------|\n";
    md << "| Fallbacks | " << data_.fallbackCount << " |\n";
    md << "| Errors | " << data_.errorCount << " |\n";
    md << "| Warnings | " << data_.warningCount << " |\n\n";
    
    if (!data_.compatibilityWarnings.empty()) {
        md << "### Warnings\n\n";
        for (const auto& warning : data_.compatibilityWarnings) {
            md << "- " << warning << "\n";
        }
        md << "\n";
    }
    
    if (!data_.selectedKernels.empty()) {
        md << "## Selected Kernels\n\n";
        for (const auto& kernel : data_.selectedKernels) {
            md << "- " << kernel << "\n";
        }
    }
    
    return md.str();
}

std::string CompatibilityTelemetry::GetDebugReport() const {
    std::stringstream report;
    report << "=== Compatibility Telemetry Debug Report ===\n\n";
    
    report << "Architecture: " << data_.detectedArchitecture << "\n";
    report << "Adapter: " << data_.selectedAdapter << "\n";
    report << "Context Length: " << data_.contextLength << "\n";
    report << "RoPE Variant: " << data_.ropeVariant << "\n";
    report << "Attention: " << data_.attentionImplementation << "\n\n";
    
    report << "Capabilities:\n";
    report << "  RoPE: " << (data_.capabilities.usesRope ? "yes" : "no") << "\n";
    report << "  YaRN: " << (data_.capabilities.usesYarn ? "yes" : "no") << "\n";
    report << "  ALiBi: " << (data_.capabilities.usesAlibi ? "yes" : "no") << "\n";
    report << "  Sliding Window: " << (data_.capabilities.usesSlidingWindow ? "yes" : "no") << "\n";
    report << "  GQA: " << (data_.capabilities.usesGQA ? "yes" : "no") << "\n";
    report << "  MoE: " << (data_.capabilities.usesMoE ? "yes" : "no") << "\n\n";
    
    report << "Performance:\n";
    report << "  Load Time: " << data_.loadTimeMs << " ms\n";
    report << "  Adapter Init: " << data_.adapterInitTimeMs << " ms\n";
    report << "  Inferences: " << data_.inferenceCount << "\n";
    report << "  Avg Time: " << data_.avgInferenceTimeMs << " ms\n\n";
    
    report << "Issues:\n";
    report << "  Fallbacks: " << data_.fallbackCount << "\n";
    report << "  Errors: " << data_.errorCount << "\n";
    report << "  Warnings: " << data_.warningCount << "\n\n";
    
    if (!data_.recentErrors.empty()) {
        report << "Recent Errors:\n";
        for (const auto& error : data_.recentErrors) {
            report << "  - " << error << "\n";
        }
        report << "\n";
    }
    
    if (!data_.recentWarnings.empty()) {
        report << "Recent Warnings:\n";
        for (const auto& warning : data_.recentWarnings) {
            report << "  - " << warning << "\n";
        }
    }
    
    return report.str();
}

void CompatibilityTelemetry::Reset() {
    data_ = CompatibilityTelemetryData();
    events_.clear();
    sessionStart_ = std::chrono::system_clock::now();
}

std::string CompatibilityTelemetry::EventTypeToString(TelemetryEventType type) const {
    switch (type) {
        case TelemetryEventType::MODEL_LOAD: return "MODEL_LOAD";
        case TelemetryEventType::ARCHITECTURE_DETECTED: return "ARCHITECTURE_DETECTED";
        case TelemetryEventType::ADAPTER_CREATED: return "ADAPTER_CREATED";
        case TelemetryEventType::KERNEL_SELECTED: return "KERNEL_SELECTED";
        case TelemetryEventType::INFERENCE_START: return "INFERENCE_START";
        case TelemetryEventType::INFERENCE_COMPLETE: return "INFERENCE_COMPLETE";
        case TelemetryEventType::FALLBACK_TRIGGERED: return "FALLBACK_TRIGGERED";
        case TelemetryEventType::ERROR_OCCURRED: return "ERROR_OCCURRED";
        case TelemetryEventType::WARNING_EMITTED: return "WARNING_EMITTED";
        default: return "UNKNOWN";
    }
}

std::string CompatibilityTelemetry::GetTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

} // namespace compatibility
} // namespace rawrxd
