// ============================================================================
// MoEArchitectureParser.hpp - Architecture-agnostic MoE metadata parser
// Dispatches based on general.architecture key
// ============================================================================

#pragma once

#include "GGUFLoader.hpp"
#include <string>
#include <unordered_map>
#include <functional>
#include <memory>

namespace Deep2 {

// ============================================================================
// Forward declaration
// ============================================================================
struct MoEModelConfig;

// ============================================================================
// Architecture Parser Interface
// ============================================================================
class IArchitectureParser {
public:
    virtual ~IArchitectureParser() = default;
    
    // Parse metadata into config
    virtual bool Parse(const std::unordered_map<std::string, std::string>& metadata,
                       MoEModelConfig& config) = 0;
    
    // Get architecture name
    virtual const char* GetName() const = 0;
    
    // Validate config after parsing
    virtual bool Validate(const MoEModelConfig& config, std::string& error) const = 0;
    
    // Get expected tensor name patterns for this architecture
    struct TensorPatterns {
        std::string expertGate;    // e.g., "blk.{L}.ffn_gate_exps.weight"
        std::string expertUp;      // e.g., "blk.{L}.ffn_up_exps.weight"
        std::string expertDown;    // e.g., "blk.{L}.ffn_down_exps.weight"
        std::string router;        // e.g., "blk.{L}.ffn_gate_inp.weight"
        std::string sharedGate;    // empty if no shared expert
        std::string sharedUp;
        std::string sharedDown;
    };
    virtual TensorPatterns GetTensorPatterns() const = 0;
};

// ============================================================================
// Architecture Factory
// ============================================================================
class ArchitectureFactory {
public:
    // Register a parser for an architecture name
    static void Register(const std::string& archName, 
                         std::function<std::unique_ptr<IArchitectureParser>()> creator);
    
    // Create parser for architecture name
    static std::unique_ptr<IArchitectureParser> Create(const std::string& archName);
    
    // Get all registered architecture names
    static std::vector<std::string> GetRegisteredArchitectures();
    
    // Auto-register all built-in parsers
    static void RegisterBuiltins();
    
private:
    static std::unordered_map<std::string, 
                               std::function<std::unique_ptr<IArchitectureParser>()>>&
    GetRegistry();
};

// ============================================================================
// Built-in Parsers
// ============================================================================

// DeepSeek V2/V3 parser
class DeepSeekArchitectureParser : public IArchitectureParser {
public:
    bool Parse(const std::unordered_map<std::string, std::string>& metadata,
               MoEModelConfig& config) override;
    const char* GetName() const override { return "deepseek2"; }
    bool Validate(const MoEModelConfig& config, std::string& error) const override;
    TensorPatterns GetTensorPatterns() const override;
};

// Mixtral parser
class MixtralArchitectureParser : public IArchitectureParser {
public:
    bool Parse(const std::unordered_map<std::string, std::string>& metadata,
               MoEModelConfig& config) override;
    const char* GetName() const override { return "mixtral"; }
    bool Validate(const MoEModelConfig& config, std::string& error) const override;
    TensorPatterns GetTensorPatterns() const override;
};

// Qwen3 MoE parser
class Qwen3MoEArchitectureParser : public IArchitectureParser {
public:
    bool Parse(const std::unordered_map<std::string, std::string>& metadata,
               MoEModelConfig& config) override;
    const char* GetName() const override { return "qwen3"; }
    bool Validate(const MoEModelConfig& config, std::string& error) const override;
    TensorPatterns GetTensorPatterns() const override;
};

// Phi3 MoE parser
class Phi3MoEArchitectureParser : public IArchitectureParser {
public:
    bool Parse(const std::unordered_map<std::string, std::string>& metadata,
               MoEModelConfig& config) override;
    const char* GetName() const override { return "phi3"; }
    bool Validate(const MoEModelConfig& config, std::string& error) const override;
    TensorPatterns GetTensorPatterns() const override;
};

// Generic MoE fallback parser
class GenericMoEArchitectureParser : public IArchitectureParser {
public:
    bool Parse(const std::unordered_map<std::string, std::string>& metadata,
               MoEModelConfig& config) override;
    const char* GetName() const override { return "generic_moe"; }
    bool Validate(const MoEModelConfig& config, std::string& error) const override;
    TensorPatterns GetTensorPatterns() const override;
};

// ============================================================================
// Metadata Validator - Cross-checks metadata against tensor index
// ============================================================================
class MetadataValidator {
public:
    // Validate config invariants
    static bool ValidateConfig(const MoEModelConfig& config, std::string& error);
    
    // Cross-check: verify tensor count matches expected from config
    static bool ValidateTensorCount(const MoEModelConfig& config,
                                     size_t actualTensorCount,
                                     std::string& error);
    
    // Cross-check: verify expert tensor dimensions match config
    static bool ValidateExpertDimensions(const MoEModelConfig& config,
                                          const std::vector<TensorInfo>& tensors,
                                          const IArchitectureParser::TensorPatterns& patterns,
                                          std::string& error);
    
    // Cross-check: verify router tensor exists and has correct shape
    static bool ValidateRouterTensor(const MoEModelConfig& config,
                                       const std::vector<TensorInfo>& tensors,
                                       const IArchitectureParser::TensorPatterns& patterns,
                                       std::string& error);
    
    // Full validation pipeline
    static bool ValidateAll(const MoEModelConfig& config,
                            const std::vector<TensorInfo>& tensors,
                            const IArchitectureParser& parser,
                            std::string& error);
};

} // namespace Deep2