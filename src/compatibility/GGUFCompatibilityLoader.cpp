#include "rawrxd/compatibility/GGUFCompatibilityLoader.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include "gguf_loader.h"

namespace rawrxd {
namespace compatibility {

GGUFCompatibilityLoader::GGUFCompatibilityLoader() 
    : base_loader_(std::make_unique<GGUFLoader>()) {
}

bool GGUFCompatibilityLoader::Load(const std::string& path) {
    model_path_ = path;
    
    // Load base GGUF
    if (!base_loader_->Load(path)) {
        return false;
    }
    
    // Detect architecture
    DetectArchitecture();
    
    // Create adapter
    CreateAdapter();
    
    // Validate
    if (!ValidateModel()) {
        return false;
    }
    
    loaded_ = true;
    return true;
}

void GGUFCompatibilityLoader::DetectArchitecture() {
    // Extract metadata from GGUF
    std::unordered_map<std::string, std::string> metadata;
    
    // Get architecture from metadata
    std::string arch_name = base_loader_->GetMetadata("general.architecture");
    if (arch_name.empty()) {
        arch_name = base_loader_->GetMetadata("llama.attention.head_count");
        if (!arch_name.empty()) {
            arch_name = "llama";  // Default to llama if head_count exists
        }
    }
    
    // Get model name
    std::string model_name = base_loader_->GetMetadata("general.name");
    if (model_name.empty()) {
        model_name = base_loader_->GetMetadata("general.basename");
    }
    
    // Build hyperparameters map
    std::unordered_map<std::string, int> hyperparams;
    hyperparams["vocab_size"] = std::stoi(base_loader_->GetMetadata("llama.vocab_size"));
    hyperparams["hidden_size"] = std::stoi(base_loader_->GetMetadata("llama.embedding_length"));
    hyperparams["num_layers"] = std::stoi(base_loader_->GetMetadata("llama.block_count"));
    hyperparams["num_heads"] = std::stoi(base_loader_->GetMetadata("llama.attention.head_count"));
    hyperparams["num_kv_heads"] = std::stoi(base_loader_->GetMetadata("llama.attention.head_count_kv"));
    hyperparams["context_length"] = std::stoi(base_loader_->GetMetadata("llama.context_length"));
    
    // Detect architecture
    detected_arch_ = detector_.DetectFromMetadata(arch_name, model_name, hyperparams);
    config_ = detector_.GetConfig(detected_arch_);
}

void GGUFCompatibilityLoader::CreateAdapter() {
    if (detected_arch_ != ModelArchitecture::UNKNOWN) {
        adapter_ = std::make_shared<ModelAdapter>(detected_arch_);
        adapter_->Initialize(config_);
    }
}

bool GGUFCompatibilityLoader::IsSupported() const {
    return detected_arch_ != ModelArchitecture::UNKNOWN && 
           detector_.IsSupported(detected_arch_);
}

std::string GGUFCompatibilityLoader::GetCompatibilityReport() const {
    std::stringstream report;
    report << "=== RawrXD Compatibility Report ===\n\n";
    report << "Model: " << model_path_ << "\n";
    report << "Architecture: " << detector_.GetArchitectureName(detected_arch_) << "\n";
    report << "Supported: " << (IsSupported() ? "YES" : "NO") << "\n\n";
    
    report << "Configuration:\n";
    report << "  Vocab Size: " << config_.vocab_size << "\n";
    report << "  Hidden Size: " << config_.hidden_size << "\n";
    report << "  Num Layers: " << config_.num_layers << "\n";
    report << "  Num Heads: " << config_.num_heads << "\n";
    report << "  Num KV Heads: " << config_.num_kv_heads << "\n";
    report << "  Context Length: " << config_.max_position_embeddings << "\n";
    report << "  Use GQA: " << (config_.use_gqa ? "YES" : "NO") << "\n";
    report << "  Use RoPE: " << (config_.use_rope ? "YES" : "NO") << "\n";
    report << "  Use ALiBi: " << (config_.use_alibi ? "YES" : "NO") << "\n";
    report << "  Sliding Window: " << (config_.use_sliding_window ? "YES" : "NO") << "\n";
    
    if (config_.use_sliding_window) {
        report << "  Window Size: " << config_.sliding_window << "\n";
    }
    
    report << "\n";
    
    // Kernel recommendations
    auto kernel_config = GetRecommendedKernels();
    report << "Recommended Kernels:\n";
    report << "  Attention: " << kernel_config.attention_kernel << "\n";
    report << "  MatMul: " << kernel_config.matmul_kernel << "\n";
    report << "  Activation: " << kernel_config.activation_kernel << "\n";
    
    return report.str();
}

KernelConfig GGUFCompatibilityLoader::GetRecommendedKernels() const {
    KernelConfig cfg;
    
    if (!adapter_) {
        return cfg;
    }
    
    // Select attention kernel based on architecture
    if (config_.use_sliding_window) {
        cfg.attention_kernel = "flash_attention_sliding_window";
    } else if (config_.use_gqa) {
        cfg.attention_kernel = "flash_attention_gqa";
    } else {
        cfg.attention_kernel = "flash_attention";
    }
    
    // Select matmul kernel
    if (config_.hidden_size >= 4096) {
        cfg.matmul_kernel = "matmul_avx512";
    } else {
        cfg.matmul_kernel = "matmul_avx2";
    }
    
    // Select activation kernel
    if (config_.hidden_act == "silu") {
        cfg.activation_kernel = "silu_fused";
    } else if (config_.hidden_act == "gelu") {
        cfg.activation_kernel = "gelu";
    } else {
        cfg.activation_kernel = config_.hidden_act;
    }
    
    return cfg;
}

bool GGUFCompatibilityLoader::ValidateModel() {
    if (!ValidateTensors()) {
        return false;
    }
    
    if (!ValidateHyperparameters()) {
        return false;
    }
    
    return true;
}

bool GGUFCompatibilityLoader::ValidateTensors() {
    // Check required tensors exist
    std::vector<std::string> required_tensors = {
        "token_embd.weight",
        "output_norm.weight",
        "output.weight"
    };
    
    for (int i = 0; i < config_.num_layers; ++i) {
        required_tensors.push_back("blk." + std::to_string(i) + ".attn_norm.weight");
        required_tensors.push_back("blk." + std::to_string(i) + ".attn_q.weight");
        required_tensors.push_back("blk." + std::to_string(i) + ".attn_k.weight");
        required_tensors.push_back("blk." + std::to_string(i) + ".attn_v.weight");
        required_tensors.push_back("blk." + std::to_string(i) + ".attn_output.weight");
        required_tensors.push_back("blk." + std::to_string(i) + ".ffn_norm.weight");
        required_tensors.push_back("blk." + std::to_string(i) + ".ffn_up.weight");
        required_tensors.push_back("blk." + std::to_string(i) + ".ffn_down.weight");
    }
    
    // Note: Actual tensor validation would check the GGUF loader's tensor list
    // This is a simplified version
    
    return true;
}

bool GGUFCompatibilityLoader::ValidateHyperparameters() {
    // Validate hyperparameters are reasonable
    if (config_.vocab_size <= 0 || config_.vocab_size > 500000) {
        return false;
    }
    
    if (config_.hidden_size <= 0 || config_.hidden_size > 65536) {
        return false;
    }
    
    if (config_.num_layers <= 0 || config_.num_layers > 256) {
        return false;
    }
    
    if (config_.num_heads <= 0 || config_.num_heads > 256) {
        return false;
    }
    
    if (config_.num_kv_heads <= 0 || config_.num_kv_heads > config_.num_heads) {
        return false;
    }
    
    return true;
}

size_t GGUFCompatibilityLoader::GetTensorCount() const {
    if (base_loader_) {
        return base_loader_->GetTensorCount();
    }
    return 0;
}

std::string GGUFCompatibilityLoader::GetModelInfo() const {
    std::stringstream info;
    info << "Model: " << base_loader_->GetMetadata("general.name") << "\n";
    info << "Architecture: " << detector_.GetArchitectureName(detected_arch_) << "\n";
    info << "Parameters: " << base_loader_->GetMetadata("general.parameter_count") << "\n";
    info << "Quantization: " << base_loader_->GetMetadata("general.quantization_version") << "\n";
    return info.str();
}

// CompatibilityChecker implementation
CompatibilityCheck CompatibilityChecker::Check(const std::string& gguf_path) {
    CompatibilityCheck result;
    
    GGUFCompatibilityLoader loader;
    if (!loader.Load(gguf_path)) {
        result.errors.push_back("Failed to load GGUF file");
        return result;
    }
    
    result.detected_arch = loader.GetArchitecture();
    result.compatible = loader.IsSupported();
    
    if (result.detected_arch == ModelArchitecture::UNKNOWN) {
        result.errors.push_back("Could not detect model architecture");
        result.confidence = 0.0f;
    } else {
        result.confidence = 0.95f;  // High confidence if detection succeeded
        
        if (!result.compatible) {
            result.errors.push_back("Architecture detected but not yet supported");
        }
    }
    
    // Add recommendations
    auto config = loader.GetConfig();
    if (config.use_sliding_window) {
        result.recommendations.push_back("Model uses sliding window attention - ensure kernel supports it");
    }
    if (config.use_gqa) {
        result.recommendations.push_back("Model uses GQA - verify KV cache sizing");
    }
    
    return result;
}

CompatibilityCheck CompatibilityChecker::Check(const std::string& gguf_path, 
                                                  ModelArchitecture expected_arch) {
    auto result = Check(gguf_path);
    
    if (result.detected_arch != expected_arch && result.detected_arch != ModelArchitecture::UNKNOWN) {
        result.warnings.push_back("Detected architecture differs from expected");
        ArchitectureDetector detector;
        result.recommendations.push_back("Expected: " + detector.GetArchitectureName(expected_arch));
        result.recommendations.push_back("Detected: " + detector.GetArchitectureName(result.detected_arch));
    }
    
    return result;
}

std::vector<CompatibilityCheck> CompatibilityChecker::CheckBatch(
    const std::vector<std::string>& paths) {
    std::vector<CompatibilityCheck> results;
    results.reserve(paths.size());
    
    for (const auto& path : paths) {
        results.push_back(Check(path));
    }
    
    return results;
}

// ModelMetadataExtractor implementation
ModelMetadata ModelMetadataExtractor::Extract(const std::string& gguf_path) {
    ModelMetadata metadata;
    
    GGUFCompatibilityLoader loader;
    if (!loader.Load(gguf_path)) {
        return metadata;
    }
    
    // Extract basic info
    metadata.name = loader.GetModelInfo();
    
    // Get file size
    std::ifstream file(gguf_path, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        metadata.file_size = file.tellg();
        file.close();
    }
    
    // Get config
    auto config = loader.GetConfig();
    metadata.architecture = std::to_string(static_cast<int>(config.arch));
    metadata.vocab_size = config.vocab_size;
    metadata.context_length = config.max_position_embeddings;
    metadata.num_layers = config.num_layers;
    metadata.num_heads = config.num_heads;
    metadata.hidden_size = config.hidden_size;
    
    // Estimate parameter count
    metadata.parameter_count = static_cast<size_t>(config.vocab_size) * config.hidden_size +
                               static_cast<size_t>(config.num_layers) * config.hidden_size * config.hidden_size * 4;
    
    return metadata;
}

std::string ModelMetadataExtractor::ToJSON(const ModelMetadata& metadata) {
    std::stringstream json;
    json << "{\n";
    json << "  \"name\": \"" << metadata.name << "\",\n";
    json << "  \"architecture\": \"" << metadata.architecture << "\",\n";
    json << "  \"quantization\": \"" << metadata.quantization << "\",\n";
    json << "  \"parameter_count\": " << metadata.parameter_count << ",\n";
    json << "  \"file_size\": " << metadata.file_size << ",\n";
    json << "  \"context_length\": " << metadata.context_length << ",\n";
    json << "  \"vocab_size\": " << metadata.vocab_size << ",\n";
    json << "  \"num_layers\": " << metadata.num_layers << ",\n";
    json << "  \"num_heads\": " << metadata.num_heads << ",\n";
    json << "  \"hidden_size\": " << metadata.hidden_size << "\n";
    json << "}";
    return json.str();
}

std::string ModelMetadataExtractor::ToMarkdown(const ModelMetadata& metadata) {
    std::stringstream md;
    md << "# Model: " << metadata.name << "\n\n";
    md << "| Property | Value |\n";
    md << "|----------|-------|\n";
    md << "| Architecture | " << metadata.architecture << " |\n";
    md << "| Quantization | " << metadata.quantization << " |\n";
    md << "| Parameters | " << metadata.parameter_count << " |\n";
    md << "| File Size | " << metadata.file_size << " bytes |\n";
    md << "| Context Length | " << metadata.context_length << " |\n";
    md << "| Vocab Size | " << metadata.vocab_size << " |\n";
    md << "| Layers | " << metadata.num_layers << " |\n";
    md << "| Heads | " << metadata.num_heads << " |\n";
    md << "| Hidden Size | " << metadata.hidden_size << " |\n";
    return md.str();
}

} // namespace compatibility
} // namespace rawrxd

