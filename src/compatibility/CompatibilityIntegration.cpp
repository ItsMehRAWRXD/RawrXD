#include "rawrxd/compatibility/CompatibilityIntegration.hpp"
#include "rawrxd/compatibility/CompatibilityTelemetry.hpp"
#include <sstream>
#include <chrono>

namespace rawrxd {
namespace compatibility {

CompatibilityIntegration::CompatibilityIntegration() 
    : loader_(std::make_unique<GGUFCompatibilityLoader>()) {
}

bool CompatibilityIntegration::Initialize(const std::string& gguf_path) {
    model_path_ = gguf_path;
    
    auto& telemetry = CompatibilityTelemetryManager::GetInstance();
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!loader_->Load(gguf_path)) {
        telemetry.EmitError("Failed to load model: " + gguf_path);
        return false;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    float loadTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    adapter_ = loader_->GetAdapter();
    initialized_ = true;
    
    // Emit telemetry
    ArchitectureDetector detector;
    std::string archName = detector.GetArchitectureName(loader_->GetArchitecture());
    
    telemetry.EmitModelLoad(gguf_path, archName, loadTimeMs);
    telemetry.SetArchitecture(archName);
    telemetry.SetModelPath(gguf_path);
    
    if (adapter_) {
        auto config = adapter_->GetConfig();
        telemetry.SetContextLength(config.max_position_embeddings);
        
        // Extract capabilities and emit
        auto caps = CapabilityDetector::DetectFromConfig(config);
        telemetry.SetCapabilities(caps);
        telemetry.SetRoPEVariant(caps.GetRoPEVariant());
        
        // Emit warnings for special handling
        if (caps.RequiresSpecialAttention()) {
            telemetry.EmitWarning("Model requires special attention (ALiBi/YaRN/MoE/SlidingWindow)");
        }
        if (caps.supportsLongContext && caps.maxContextLength > 65536) {
            telemetry.EmitWarning("Very long context model - high memory usage expected");
        }
    }
    
    // Emit kernel selection telemetry
    auto kernelConfig = GetKernelConfig();
    telemetry.EmitKernelSelected(kernelConfig.attention_kernel, "auto-selected based on architecture");
    telemetry.SetAttentionImplementation(kernelConfig.attention_kernel);
    
    return true;
}

void CompatibilityIntegration::ConfigureInferenceEngine(InferenceEngine* engine) {
    if (!adapter_ || !engine) {
        return;
    }
    
    auto config = adapter_->GetConfig();
    
    // Configure attention mechanism
    if (config.use_sliding_window) {
        engine->SetAttentionMode(AttentionMode::SLIDING_WINDOW);
        engine->SetSlidingWindowSize(config.sliding_window);
    } else if (config.use_gqa) {
        engine->SetAttentionMode(AttentionMode::GQA);
    }
    
    // Configure position encoding
    if (config.use_rope) {
        engine->SetPositionEncoding(PositionEncoding::ROPE);
        engine->SetRoPETheta(config.rope_theta);
        if (config.rope_scaling != 1.0f) {
            engine->SetRoPEScaling(config.rope_scaling);
        }
    } else if (config.use_alibi) {
        engine->SetPositionEncoding(PositionEncoding::ALIBI);
    }
    
    // Configure KV cache
    engine->SetKVCacheConfig({
        .num_layers = config.num_layers,
        .num_heads = config.num_kv_heads,
        .head_dim = config.head_dim,
        .max_seq_len = config.max_position_embeddings
    });
    
    // Configure special tokens
    engine->SetBOSToken(adapter_->GetBOSToken());
    engine->SetEOSToken(adapter_->GetEOSToken());
    auto stop_tokens = adapter_->GetStopTokens();
    for (int token : stop_tokens) {
        engine->AddStopToken(token);
    }
}

void CompatibilityIntegration::ConfigureTokenizer(Tokenizer* tokenizer) {
    if (!adapter_ || !tokenizer) {
        return;
    }
    
    // Configure special tokens
    tokenizer->SetBOS(adapter_->GetBOSToken());
    tokenizer->SetEOS(adapter_->GetEOSToken());
    tokenizer->SetPAD(adapter_->GetPadToken());
    
    // Architecture-specific token handling
    auto arch = adapter_->GetArchitecture();
    switch (arch) {
        case ModelArchitecture::LLAMA3:
            tokenizer->SetChatTemplate("llama3");
            break;
        case ModelArchitecture::MISTRAL:
        case ModelArchitecture::MIXTRAL:
            tokenizer->SetChatTemplate("mistral");
            break;
        case ModelArchitecture::PHI3:
            tokenizer->SetChatTemplate("phi3");
            break;
        case ModelArchitecture::QWEN2:
            tokenizer->SetChatTemplate("qwen2");
            break;
        default:
            tokenizer->SetChatTemplate("default");
            break;
    }
}

KernelConfig CompatibilityIntegration::GetKernelConfig() const {
    if (!loader_) {
        return KernelConfig();
    }
    return loader_->GetRecommendedKernels();
}

bool CompatibilityIntegration::RequiresSpecialHandling() {
    if (!adapter_) {
        return false;
    }
    
    auto arch = adapter_->GetArchitecture();
    return arch == ModelArchitecture::MIXTRAL ||  // MoE
           arch == ModelArchitecture::DEEPSEEK || // ALiBi
           arch == ModelArchitecture::PHI3;       // Long RoPE
}

int CompatibilityIntegration::GetRecommendedBatchSize() const {
    if (!adapter_) {
        return 1;
    }
    
    auto config = adapter_->GetConfig();
    
    // Recommend batch size based on model size
    size_t model_size_mb = (config.vocab_size * config.hidden_size * 4 +
                            config.num_layers * config.hidden_size * config.hidden_size * 4 * 12) / (1024 * 1024);
    
    if (model_size_mb < 4096) {
        return 8;
    } else if (model_size_mb < 8192) {
        return 4;
    } else if (model_size_mb < 16384) {
        return 2;
    } else {
        return 1;
    }
}

int CompatibilityIntegration::GetRecommendedContextLength() const {
    if (!adapter_) {
        return 4096;
    }
    
    auto config = adapter_->GetConfig();
    
    // For models with known long context support
    if (config.arch == ModelArchitecture::PHI3) {
        return 128000;  // Phi-3 supports 128K
    } else if (config.arch == ModelArchitecture::LLAMA3) {
        return 8192;    // Standard Llama 3
    }
    
    return config.max_position_embeddings;
}

size_t CompatibilityIntegration::GetMemoryRequirements() const {
    if (!adapter_) {
        return 0;
    }
    
    auto config = adapter_->GetConfig();
    
    // Calculate approximate memory requirements
    // Weights + KV cache + activations
    size_t weights = static_cast<size_t>(config.vocab_size) * config.hidden_size * 4 +
                     static_cast<size_t>(config.num_layers) * config.hidden_size * config.hidden_size * 4 * 12;
    
    size_t kv_cache = static_cast<size_t>(config.num_layers) * config.num_kv_heads * 
                      config.max_position_embeddings * config.head_dim * 2 * 4;
    
    size_t activations = static_cast<size_t>(config.hidden_size) * config.max_position_embeddings * 4 * 4;
    
    return weights + kv_cache + activations;
}

bool CompatibilityIntegration::Validate() const {
    if (!initialized_ || !loader_) {
        return false;
    }
    
    return loader_->IsSupported();
}

ModelArchitecture CompatibilityIntegration::GetArchitecture() const {
    if (!loader_) {
        return ModelArchitecture::UNKNOWN;
    }
    return loader_->GetArchitecture();
}

std::string CompatibilityIntegration::GetArchitectureName() const {
    if (!loader_) {
        return "unknown";
    }
    
    ArchitectureDetector detector;
    return detector.GetArchitectureName(loader_->GetArchitecture());
}

// IntegratedInferenceFactory implementation
std::unique_ptr<InferenceEngine> IntegratedInferenceFactory::CreateEngine(
    const std::string& gguf_path,
    const InferenceConfig& config) {
    
    CompatibilityIntegration integration;
    if (!integration.Initialize(gguf_path)) {
        return nullptr;
    }
    
    auto engine = std::make_unique<InferenceEngine>();
    
    // Configure with compatibility settings
    integration.ConfigureInferenceEngine(engine.get());
    
    // Load model
    if (!engine->LoadModel(gguf_path)) {
        return nullptr;
    }
    
    return engine;
}

std::unique_ptr<InferenceEngine> IntegratedInferenceFactory::CreateEngine(
    const std::string& gguf_path,
    ModelArchitecture arch,
    const InferenceConfig& config) {
    
    // Verify architecture matches
    CompatibilityCheck check = CompatibilityChecker::Check(gguf_path, arch);
    if (!check.compatible) {
        return nullptr;
    }
    
    return CreateEngine(gguf_path, config);
}

std::vector<std::unique_ptr<InferenceEngine>> IntegratedInferenceFactory::CreateEngines(
    const std::vector<std::string>& gguf_paths) {
    
    std::vector<std::unique_ptr<InferenceEngine>> engines;
    engines.reserve(gguf_paths.size());
    
    for (const auto& path : gguf_paths) {
        engines.push_back(CreateEngine(path));
    }
    
    return engines;
}

// CompatibilityMonitor implementation
void CompatibilityMonitor::RecordInference(const Metrics& metrics) {
    history_.push_back(metrics);
    
    // Keep only last 1000 entries
    if (history_.size() > 1000) {
        history_.erase(history_.begin());
    }
}

void CompatibilityMonitor::RecordFallback(const std::string& reason) {
    fallbacks_.push_back(reason);
}

void CompatibilityMonitor::RecordError(const std::string& error) {
    errors_.push_back(error);
}

std::vector<std::string> CompatibilityMonitor::GetRecommendations() const {
    std::vector<std::string> recommendations;
    
    if (history_.empty()) {
        return recommendations;
    }
    
    // Calculate average TPS
    float avg_tps = 0.0f;
    for (const auto& m : history_) {
        avg_tps += m.tokens_per_second;
    }
    avg_tps /= history_.size();
    
    // Check for performance issues
    int fallback_count = 0;
    for (const auto& m : history_) {
        if (m.fallback_triggered) {
            fallback_count++;
        }
    }
    
    float fallback_rate = static_cast<float>(fallback_count) / history_.size();
    
    if (fallback_rate > 0.1f) {
        recommendations.push_back("High fallback rate detected - consider using different kernel configuration");
    }
    
    if (avg_tps < 10.0f) {
        recommendations.push_back("Low TPS detected - consider reducing batch size or using quantization");
    }
    
    // Check memory usage
    size_t peak_memory = 0;
    for (const auto& m : history_) {
        peak_memory = std::max(peak_memory, m.memory_peak);
    }
    
    // Add architecture-specific recommendations
    if (!history_.empty()) {
        const auto& last = history_.back();
        if (last.kernel_used.find("fallback") != std::string::npos) {
            recommendations.push_back("Using fallback kernels - consider updating to optimized kernels");
        }
    }
    
    return recommendations;
}

std::string CompatibilityMonitor::ExportJSON() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"inference_count\": " << history_.size() << ",\n";
    json << "  \"fallback_count\": " << fallbacks_.size() << ",\n";
    json << "  \"error_count\": " << errors_.size() << ",\n";
    
    // Calculate averages
    if (!history_.empty()) {
        float avg_tps = 0.0f;
        float avg_time = 0.0f;
        for (const auto& m : history_) {
            avg_tps += m.tokens_per_second;
            avg_time += m.inference_time_ms;
        }
        avg_tps /= history_.size();
        avg_time /= history_.size();
        
        json << "  \"average_tps\": " << avg_tps << ",\n";
        json << "  \"average_time_ms\": " << avg_time << ",\n";
    }
    
    json << "  \"recommendations\": [\n";
    auto recs = GetRecommendations();
    for (size_t i = 0; i < recs.size(); ++i) {
        json << "    \"" << recs[i] << "\"";
        if (i < recs.size() - 1) json << ",";
        json << "\n";
    }
    json << "  ]\n";
    json << "}";
    
    return json.str();
}

void CompatibilityMonitor::Reset() {
    history_.clear();
    fallbacks_.clear();
    errors_.clear();
}

} // namespace compatibility
} // namespace rawrxd
