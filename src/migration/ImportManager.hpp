// RawrXD Import Manager
// Phase Y.1: Import from other inference engines
// Enables migration from llama.cpp, vLLM, TensorRT-LLM, etc.

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Migration {

// Source engine type
enum class SourceEngine {
    LLAMA_CPP,
    VLLM,
    TENSORRT_LLM,
    ONNX_RUNTIME,
    PYTORCH,
    HUGGINGFACE_TRANSFORMERS,
    DEEPSPEED,
    CUSTOM
};

// Import configuration
struct ImportConfig {
    SourceEngine sourceEngine;
    std::string sourcePath;
    std::string targetPath;
    bool convertFormat{true};
    bool quantize{false};
    std::string quantizationType{"Q4_K_M"};
    bool preserveWeights{true};
    bool importTokenizer{true};
    bool importConfig{true};
    std::map<std::string, std::string> customOptions;
};

// Import result
struct ImportResult {
    bool success;
    std::string modelId;
    std::string errorMessage;
    std::chrono::milliseconds duration;
    uint64_t bytesProcessed;
    std::vector<std::string> importedFiles;
    std::vector<std::string> warnings;
    std::map<std::string, std::string> metadata;
};

// Source engine info
struct SourceEngineInfo {
    SourceEngine engine;
    std::string name;
    std::string version;
    std::vector<std::string> supportedFormats;
    std::vector<std::string> supportedFeatures;
    bool isAvailable{false};
};

// Model compatibility
struct ModelCompatibility {
    bool isCompatible;
    std::vector<std::string> issues;
    std::vector<std::string> warnings;
    std::map<std::string, std::string> suggestedFixes;
};

// Import progress
struct ImportProgress {
    std::string stage;
    uint32_t currentStep;
    uint32_t totalSteps;
    double percentage;
    std::string currentFile;
    uint64_t bytesProcessed;
    uint64_t totalBytes;
};

// Import manager
class ImportManager {
public:
    ImportManager();
    ~ImportManager();
    
    // Initialization
    bool initialize();
    bool shutdown();
    
    // Source engine discovery
    std::vector<SourceEngineInfo> discoverSourceEngines() const;
    SourceEngineInfo getSourceEngineInfo(SourceEngine engine) const;
    bool isSourceEngineAvailable(SourceEngine engine) const;
    
    // Model detection
    bool canImport(const std::string& path) const;
    SourceEngine detectSourceEngine(const std::string& path) const;
    std::vector<SourceEngine> getCompatibleEngines(const std::string& path) const;
    
    // Compatibility checking
    ModelCompatibility checkCompatibility(const std::string& path, SourceEngine engine) const;
    std::vector<std::string> getRequiredConversions(const std::string& path, SourceEngine engine) const;
    
    // Import operations
    ImportResult importModel(const ImportConfig& config);
    ImportResult importModelAsync(const ImportConfig& config);
    bool cancelImport(const std::string& importId);
    
    // Batch import
    std::vector<ImportResult> importBatch(const std::vector<ImportConfig>& configs);
    
    // Import from specific engines
    ImportResult importFromLlamaCpp(const std::string& sourcePath, const std::string& targetPath);
    ImportResult importFromVLLM(const std::string& sourcePath, const std::string& targetPath);
    ImportResult importFromTensorRT(const std::string& sourcePath, const std::string& targetPath);
    ImportResult importFromONNX(const std::string& sourcePath, const std::string& targetPath);
    ImportResult importFromPyTorch(const std::string& sourcePath, const std::string& targetPath);
    ImportResult importFromHuggingFace(const std::string& sourcePath, const std::string& targetPath);
    
    // Configuration import
    bool importConfiguration(const std::string& sourcePath, SourceEngine engine);
    std::map<std::string, std::string> convertConfiguration(
        const std::map<std::string, std::string>& sourceConfig,
        SourceEngine engine);
    
    // Tokenizer import
    bool importTokenizer(const std::string& sourcePath, const std::string& targetPath);
    bool convertTokenizerFormat(const std::string& sourcePath, 
                                const std::string& targetPath,
                                SourceEngine engine);
    
    // Progress tracking
    ImportProgress getProgress(const std::string& importId) const;
    bool isImportComplete(const std::string& importId) const;
    ImportResult getImportResult(const std::string& importId) const;
    
    // Validation
    bool validateImportedModel(const std::string& modelPath);
    bool verifyImportIntegrity(const ImportResult& result);
    
    // Rollback
    bool rollbackImport(const std::string& importId);
    bool canRollback(const std::string& importId) const;
    
    // Statistics
    struct ImportStats {
        uint32_t totalImports;
        uint32_t successfulImports;
        uint32_t failedImports;
        uint32_t cancelledImports;
        uint64_t totalBytesProcessed;
        std::map<SourceEngine, uint32_t> importsByEngine;
    };
    ImportStats getStats() const;
    
    // Callbacks
    using ProgressCallback = std::function<void(const ImportProgress& progress)>;
    using CompletionCallback = std::function<void(const ImportResult& result)>;
    void onProgress(ProgressCallback callback);
    void onCompletion(CompletionCallback callback);

private:
    void notifyProgress(const ImportProgress& progress);
    void notifyCompletion(const ImportResult& result);
    std::string generateImportId() const;
    
    mutable std::mutex mutex_;
    std::map<std::string, ImportProgress> progress_;
    std::map<std::string, ImportResult> results_;
    std::map<std::string, ImportConfig> activeImports_;
    
    ProgressCallback progressCallback_;
    CompletionCallback completionCallback_;
    
    ImportStats stats_{};
};

// Format converter
class FormatConverter {
public:
    FormatConverter();
    
    // Conversion registration
    void registerConverter(const std::string& fromFormat,
                          const std::string& toFormat,
                          std::function<bool(const std::string&, const std::string&)> converter);
    
    // Conversion operations
    bool canConvert(const std::string& fromFormat, const std::string& toFormat) const;
    bool convert(const std::string& inputPath, const std::string& outputPath,
                const std::string& fromFormat, const std::string& toFormat);
    
    // Chain conversion
    std::vector<std::string> findConversionPath(const std::string& fromFormat,
                                               const std::string& toFormat) const;
    bool convertChain(const std::string& inputPath, const std::string& outputPath,
                     const std::vector<std::string>& formatChain);
    
    // Supported formats
    std::vector<std::string> getSupportedInputFormats() const;
    std::vector<std::string> getSupportedOutputFormats() const;
    std::vector<std::string> getSupportedConversions(const std::string& fromFormat) const;

private:
    std::map<std::pair<std::string, std::string>, 
             std::function<bool(const std::string&, const std::string&)>> converters_;
};

// Migration helper
class MigrationHelper {
public:
    MigrationHelper();
    
    // Pre-migration checks
    struct PreMigrationCheck {
        bool canMigrate;
        std::vector<std::string> issues;
        std::vector<std::string> warnings;
        uint64_t requiredSpace;
        uint64_t availableSpace;
        std::chrono::seconds estimatedTime;
    };
    PreMigrationCheck runPreMigrationChecks(const std::string& sourcePath,
                                           SourceEngine engine) const;
    
    // Migration planning
    struct MigrationPlan {
        std::vector<std::string> steps;
        std::vector<std::string> requiredFiles;
        std::vector<std::string> backupPaths;
        bool requiresDowntime;
        std::chrono::seconds estimatedDuration;
        std::map<std::string, std::string> rollbackPoints;
    };
    MigrationPlan createMigrationPlan(const std::string& sourcePath,
                                     const std::string& targetPath,
                                     SourceEngine engine) const;
    
    // Data migration
    bool migrateData(const std::string& sourcePath, const std::string& targetPath);
    bool migrateSettings(const std::string& sourcePath, const std::string& targetPath);
    bool migrateCache(const std::string& sourcePath, const std::string& targetPath);
    
    // Verification
    bool verifyMigration(const std::string& sourcePath, const std::string& targetPath);
    std::vector<std::string> getMigrationDifferences(const std::string& sourcePath,
                                                    const std::string& targetPath) const;
};

} // namespace Migration
} // namespace RawrXD
