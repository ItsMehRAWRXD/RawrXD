#pragma once

#include "fine_tuner.hpp"
#include <filesystem>
#include <vector>

namespace rawrxd::training {

// Checkpoint info
struct CheckpointInfo {
    std::string path;
    uint64_t step;
    uint64_t epoch;
    float loss;
    float metric;
    std::chrono::system_clock::time_point timestamp;
    size_t file_size;

    std::string toString() const {
        auto time = std::chrono::system_clock::to_time_t(timestamp);
        std::stringstream ss;
        ss << "Checkpoint[step=" << step
           << ", epoch=" << epoch
           << ", loss=" << loss
           << ", size=" << (file_size / 1024 / 1024) << "MB]";
        return ss.str();
    }
};

// Checkpoint manager
class CheckpointManager {
public:
    explicit CheckpointManager(const std::string& checkpoint_dir);

    // Save checkpoint
    bool saveCheckpoint(const FineTuner& trainer,
                        const std::string& tag = "");

    // Load checkpoint
    bool loadCheckpoint(FineTuner& trainer,
                        const std::string& tag);

    // Load latest checkpoint
    bool loadLatestCheckpoint(FineTuner& trainer);

    // List checkpoints
    std::vector<CheckpointInfo> listCheckpoints() const;

    // Delete checkpoint
    bool deleteCheckpoint(const std::string& tag);

    // Clean old checkpoints (keep only N most recent)
    void cleanupOldCheckpoints(size_t keep_count);

    // Export to different formats
    bool exportToGGUF(const std::string& checkpoint_tag,
                      const std::string& output_path);

    bool exportToSafetensors(const std::string& checkpoint_tag,
                            const std::string& output_path);

    bool exportToONNX(const std::string& checkpoint_tag,
                      const std::string& output_path);

    // Settings
    void setSaveOptimizer(bool save) { save_optimizer_ = save; }
    void setSaveScheduler(bool save) { save_scheduler_ = save; }
    void setSaveRNGState(bool save) { save_rng_state_ = save; }

private:
    std::filesystem::path checkpoint_dir_;
    bool save_optimizer_ = true;
    bool save_scheduler_ = true;
    bool save_rng_state_ = true;

    std::filesystem::path getCheckpointPath(const std::string& tag) const;
    std::string generateTag(uint64_t step) const;
    void saveMetadata(const CheckpointInfo& info);
    CheckpointInfo loadMetadata(const std::filesystem::path& path) const;
};

// Model exporter
class ModelExporter {
public:
    // Export formats
    struct ExportOptions {
        ModelFormat format = ModelFormat::GGUF;
        QuantizationType quantization = QuantizationType::Q4_0;
        bool merge_adapter = true;
        std::string metadata_author;
        std::string metadata_description;
        std::string metadata_license;
        std::string metadata_source;
        std::vector<std::string> include_patterns;
        std::vector<std::string> exclude_patterns;
    };

    // Export model
    static bool exportModel(const FineTuner& trainer,
                            const std::string& output_path,
                            const ExportOptions& options);

    // Format-specific exporters
    static bool exportToGGUF(const FineTuner& trainer,
                              const std::string& output_path,
                              const ExportOptions& options);

    static bool exportToSafetensors(const FineTuner& trainer,
                                     const std::string& output_path,
                                     const ExportOptions& options);

    static bool exportToONNX(const FineTuner& trainer,
                              const std::string& output_path,
                              const ExportOptions& options);

    static bool exportToPyTorch(const FineTuner& trainer,
                                 const std::string& output_path,
                                 const ExportOptions& options);

    // Quantization during export
    static bool quantizeAndExport(const FineTuner& trainer,
                                   const std::string& output_path,
                                   QuantizationType quant_type);

    // Validation
    static bool validateExport(const std::string& output_path,
                                ModelFormat format);

    // Get export size estimate
    static size_t estimateExportSize(const FineTuner& trainer,
                                      const ExportOptions& options);
};

// Checkpoint utilities
namespace checkpoint_utils {

// Resume from checkpoint with validation
bool resumeFromCheckpoint(CheckpointManager& manager,
                          FineTuner& trainer,
                          const std::string& checkpoint_path);

// Convert between checkpoint formats
bool convertCheckpoint(const std::string& input_path,
                        const std::string& output_path,
                        ModelFormat target_format);

// Merge multiple LoRA checkpoints
bool mergeLoRACheckpoints(const std::vector<std::string>& checkpoint_paths,
                          const std::vector<float>& weights,
                          const std::string& output_path);

} // namespace checkpoint_utils

} // namespace rawrxd::training
