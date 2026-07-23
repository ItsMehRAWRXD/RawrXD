// ============================================================================
// VAL-010 through VAL-023: Intermediate Validation Gates
// ============================================================================
// These gates cover intermediate validation milestones between core
// functionality (VAL-001 to VAL-009) and advanced features (VAL-024+)
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

// VAL-010: Model Format Support (GGML, GGUF versions)
class VAL010_ModelFormatGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-010"; }
    std::string GetName() const override { return "Model Format Support"; }
    std::string GetDescription() const override {
        return "Validates GGML/GGUF format versions and backward compatibility";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-002"}; }
};

// VAL-011: Attention Variants (MHA, MQA, GQA)
class VAL011_AttentionVariantsGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-011"; }
    std::string GetName() const override { return "Attention Variants"; }
    std::string GetDescription() const override {
        return "Validates Multi-Head, Multi-Query, and Grouped-Query Attention";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001", "VAL-004"}; }
};

// VAL-012: Positional Encodings (RoPE, ALiBi, Learned)
class VAL012_PositionalEncodingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-012"; }
    std::string GetName() const override { return "Positional Encodings"; }
    std::string GetDescription() const override {
        return "Validates RoPE, ALiBi, and learned positional embeddings";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
};

// VAL-013: Feed-Forward Variants (FFN, SwiGLU, GeGLU)
class VAL013_FFNVariantsGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-013"; }
    std::string GetName() const override { return "FFN Variants"; }
    std::string GetDescription() const override {
        return "Validates FFN, SwiGLU, and GeGLU feed-forward variants";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
};

// VAL-014: Model Architecture Support (LLaMA, GPT, Falcon, etc.)
class VAL014_ModelArchitecturesGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-014"; }
    std::string GetName() const override { return "Model Architectures"; }
    std::string GetDescription() const override {
        return "Validates support for LLaMA, GPT, Falcon, and other architectures";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-002", "VAL-011", "VAL-012", "VAL-013"}; }
};

// VAL-015: Context Length Handling
class VAL015_ContextLengthGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-015"; }
    std::string GetName() const override { return "Context Length Handling"; }
    std::string GetDescription() const override {
        return "Validates variable context lengths and long-context support";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-004", "VAL-012"}; }
};

// VAL-016: Batch Processing
class VAL016_BatchProcessingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-016"; }
    std::string GetName() const override { return "Batch Processing"; }
    std::string GetDescription() const override {
        return "Validates batch inference and dynamic batching";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001", "VAL-008"}; }
};

// VAL-017: Streaming Generation
class VAL017_StreamingGenerationGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-017"; }
    std::string GetName() const override { return "Streaming Generation"; }
    std::string GetDescription() const override {
        return "Validates token streaming and incremental output";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-005", "VAL-016"}; }
};

// VAL-018: Prompt Caching
class VAL018_PromptCachingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-018"; }
    std::string GetName() const override { return "Prompt Caching"; }
    std::string GetDescription() const override {
        return "Validates prompt KV cache reuse and prefix caching";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-004", "VAL-017"}; }
};

// VAL-019: Token Healing
class VAL019_TokenHealingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-019"; }
    std::string GetName() const override { return "Token Healing"; }
    std::string GetDescription() const override {
        return "Validates token boundary healing and partial token handling";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-003", "VAL-017"}; }
};

// VAL-020: Grammar-Constrained Decoding
class VAL020_GrammarConstrainedGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-020"; }
    std::string GetName() const override { return "Grammar-Constrained Decoding"; }
    std::string GetDescription() const override {
        return "Validates JSON, regex, and grammar-constrained generation";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-005", "VAL-017"}; }
};

// VAL-021: LoRA/Adapter Support
class VAL021_LoRAGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-021"; }
    std::string GetName() const override { return "LoRA/Adapter Support"; }
    std::string GetDescription() const override {
        return "Validates LoRA adapter loading and inference";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-002", "VAL-014"}; }
};

// VAL-022: Multi-Modal Input (Text + Image)
class VAL022_MultiModalGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-022"; }
    std::string GetName() const override { return "Multi-Modal Input"; }
    std::string GetDescription() const override {
        return "Validates text + image multi-modal processing";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-014"}; }
};

// VAL-023: Tool Use / Function Calling
class VAL023_ToolUseGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-023"; }
    std::string GetName() const override { return "Tool Use / Function Calling"; }
    std::string GetDescription() const override {
        return "Validates function calling and tool use patterns";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-020"}; }
};

} // namespace Validation
} // namespace RawrXD
