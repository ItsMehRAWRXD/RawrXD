#include "execution_plan.h"
#include <sstream>
#include <chrono>

namespace RawrXD {

// ============================================================================
// ExecutionPlan Implementation
// ============================================================================

bool ExecutionPlan::isValid() const {
    if (m_stages.empty()) {
        return false;
    }
    
    // Validate stage transitions
    for (size_t i = 0; i < m_stages.size(); ++i) {
        const auto& stage = m_stages[i];
        
        // Check timeout is reasonable
        if (stage.timeoutMs <= 0 || stage.timeoutMs > 300000) {
            return false;
        }
        
        // Check retry count is reasonable
        if (stage.retryCount < 0 || stage.retryCount > 10) {
            return false;
        }
        
        // Validate fallback references
        if (stage.fallbackStage.has_value()) {
            bool found = false;
            for (const auto& s : m_stages) {
                if (s.targetBackend == stage.fallbackStage.value()) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
    }
    
    return true;
}

bool ExecutionPlan::requiresCloud() const {
    for (const auto& stage : m_stages) {
        if (stage.stage == ExecutionStage::REMOTE_CLOUD_CALL) {
            return true;
        }
    }
    return false;
}

bool ExecutionPlan::requiresLocal() const {
    for (const auto& stage : m_stages) {
        if (stage.stage == ExecutionStage::LOCAL_GGUF_LOAD ||
            stage.stage == ExecutionStage::LOCAL_GGUF_INFERENCE ||
            stage.stage == ExecutionStage::LOCAL_OLLAMA_CALL) {
            return true;
        }
    }
    return false;
}

std::string ExecutionPlan::toString() const {
    std::stringstream ss;
    ss << "ExecutionPlan[stages=" << m_stages.size();
    ss << ", fallback=";
    switch (m_fallbackPolicy) {
        case FallbackPolicy::NEVER_FALLBACK: ss << "NEVER_FALLBACK"; break;
        case FallbackPolicy::LOCAL_FIRST: ss << "LOCAL_FIRST"; break;
        case FallbackPolicy::ALLOW_CLOUD: ss << "ALLOW_CLOUD"; break;
        case FallbackPolicy::FULLY_DISTRIBUTED: ss << "FULLY_DISTRIBUTED"; break;
    }
    ss << "]";
    return ss.str();
}

// ============================================================================
// ExecutionPlan::Builder Implementation
// ============================================================================

ExecutionPlan::Builder& ExecutionPlan::Builder::addStage(const StageConfig& stage) {
    m_plan.m_stages.push_back(stage);
    return *this;
}

ExecutionPlan::Builder& ExecutionPlan::Builder::setFallbackPolicy(FallbackPolicy policy) {
    m_plan.m_fallbackPolicy = policy;
    return *this;
}

ExecutionPlan::Builder& ExecutionPlan::Builder::fromModelType(const std::string& modelName) {
    // Auto-generate plan based on model type
    if (modelName.find("gguf") != std::string::npos ||
        modelName.find(".bin") != std::string::npos) {
        // Local GGUF model
        addStage({ExecutionStage::LOCAL_GGUF_LOAD, "gguf", 30000, 0});
        addStage({ExecutionStage::LOCAL_GGUF_INFERENCE, "gguf", 120000, 2});
        setFallbackPolicy(FallbackPolicy::LOCAL_FIRST);
    } else if (modelName.find("ollama") != std::string::npos) {
        // Ollama model
        addStage({ExecutionStage::LOCAL_OLLAMA_CALL, "ollama", 60000, 1});
        setFallbackPolicy(FallbackPolicy::LOCAL_FIRST);
    } else {
        // Cloud model
        addStage({ExecutionStage::REMOTE_CLOUD_CALL, "openai", 30000, 2});
        setFallbackPolicy(FallbackPolicy::ALLOW_CLOUD);
    }
    return *this;
}

std::optional<ExecutionPlan> ExecutionPlan::Builder::build() {
    if (!m_plan.isValid()) {
        return std::nullopt;
    }
    return std::move(m_plan);
}

// ============================================================================
// PlanExecutor Implementation
// ============================================================================

PlanExecutor::PlanExecutor(ExecutionCapability&& cap)
    : m_capability(std::move(cap))
{
}

PlanExecutor::ExecutionResult PlanExecutor::execute(const ExecutionPlan& plan) {
    ExecutionResult result;
    result.success = false;
    
    if (!m_capability.IsValid()) {
        result.error = "Invalid capability token";
        return result;
    }
    
    auto startTime = std::chrono::steady_clock::now();
    
    for (const auto& stage : plan.stages()) {
        auto stageStart = std::chrono::steady_clock::now();
        
        // Record stage start
        std::stringstream trace;
        trace << "Stage " << stageToString(stage.stage) << " started";
        result.executionTrace.push_back(trace.str());
        
        // Execute stage (simplified - would dispatch to actual backends)
        bool stageSuccess = executeStage(stage);
        
        auto stageEnd = std::chrono::steady_clock::now();
        auto stageDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            stageEnd - stageStart).count();
        
        if (stageSuccess) {
            std::stringstream successTrace;
            successTrace << "Stage " << stageToString(stage.stage) << " completed in " 
                        << stageDuration << "ms";
            result.executionTrace.push_back(successTrace.str());
        } else {
            std::stringstream failTrace;
            failTrace << "Stage " << stageToString(stage.stage) << " failed after " 
                      << stageDuration << "ms";
            result.executionTrace.push_back(failTrace.str());
            
            // Handle fallback
            if (stage.fallbackStage.has_value()) {
                std::stringstream fallbackTrace;
                fallbackTrace << "Attempting fallback to " << stage.fallbackStage.value();
                result.executionTrace.push_back(fallbackTrace.str());
                
                // Would execute fallback stage here
            } else if (plan.fallbackPolicy() == FallbackPolicy::NEVER_FALLBACK) {
                result.error = "Stage failed and fallback disabled";
                break;
            }
        }
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.totalLatencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    // Check if all stages succeeded
    result.success = true;
    for (const auto& trace : result.executionTrace) {
        if (trace.find("failed") != std::string::npos) {
            result.success = false;
            break;
        }
    }
    
    return result;
}

bool PlanExecutor::executeStage(const StageConfig& stage) {
    // Simplified stage execution
    // In real implementation, would dispatch to actual backends
    switch (stage.stage) {
        case ExecutionStage::LOCAL_GGUF_LOAD:
            // Would load GGUF model
            return true;
        case ExecutionStage::LOCAL_GGUF_INFERENCE:
            // Would run inference
            return true;
        case ExecutionStage::LOCAL_OLLAMA_CALL:
            // Would call Ollama
            return true;
        case ExecutionStage::REMOTE_CLOUD_CALL:
            // Would call cloud API
            return true;
        case ExecutionStage::FALLBACK_RETRY:
            // Would retry
            return true;
        case ExecutionStage::RESULT_AGGREGATION:
            // Would aggregate results
            return true;
    }
    return false;
}

std::string PlanExecutor::stageToString(ExecutionStage stage) {
    switch (stage) {
        case ExecutionStage::LOCAL_GGUF_LOAD: return "LOCAL_GGUF_LOAD";
        case ExecutionStage::LOCAL_GGUF_INFERENCE: return "LOCAL_GGUF_INFERENCE";
        case ExecutionStage::LOCAL_OLLAMA_CALL: return "LOCAL_OLLAMA_CALL";
        case ExecutionStage::REMOTE_CLOUD_CALL: return "REMOTE_CLOUD_CALL";
        case ExecutionStage::FALLBACK_RETRY: return "FALLBACK_RETRY";
        case ExecutionStage::RESULT_AGGREGATION: return "RESULT_AGGREGATION";
    }
    return "UNKNOWN";
}

} // namespace RawrXD
