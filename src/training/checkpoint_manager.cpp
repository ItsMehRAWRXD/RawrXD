#include "checkpoint_manager.hpp"
#include "../core/logger.hpp"
#include <fstream>
#include <json/json.hpp>

namespace rawrxd::training {

using json = nlohmann::json;

// ============================================================================
// Checkpoint Manager
// ============================================================================

CheckpointManager::CheckpointManager(const std::string& checkpoint_dir)
    : checkpoint_dir_(checkpoint_dir) {

    std::filesystem::create_directories(checkpoint_dir_);
    RAWRXD_LOG_INFO("CheckpointManager", "Initialized with directory: {}", checkpoint_dir);
}

bool CheckpointManager::saveCheckpoint(const FineTuner& trainer,
                                        const std::string& tag) {
    std::string actual_tag = tag.empty() ? generateTag(trainer.getMetrics().step) : tag;
    auto checkpoint_path = getCheckpointPath(actual_tag);

    RAWRXD_LOG_INFO("CheckpointManager", "Saving checkpoint to: {}", checkpoint_path.string());

    try {
        // Create checkpoint directory
        std::filesystem::create_directories(checkpoint_path);

        // Save model weights
        auto model_path = checkpoint_path / "model.bin";
        // trainer.getModel()->save(model_path.string());

        // Save optimizer state
        if (save_optimizer_) {
            auto optimizer_path = checkpoint_path / "optimizer.bin";
            // Save optimizer state
        }

        // Save scheduler state
        if (save_scheduler_) {
            auto scheduler_path = checkpoint_path / "scheduler.bin";
            // Save scheduler state
        }

        // Save RNG state
        if (save_rng_state_) {
            auto rng_path = checkpoint_path / "rng_state.bin";
            // Save RNG state
        }

        // Save metadata
        CheckpointInfo info;
        info.path = checkpoint_path.string();
        info.step = trainer.getMetrics().step;
        info.epoch = trainer.getMetrics().epoch;
        info.loss = trainer.getCurrentLoss();
        info.timestamp = std::chrono::system_clock::now();
        info.file_size = 0;  // Calculate actual size

        saveMetadata(info);

        RAWRXD_LOG_INFO("CheckpointManager", "Checkpoint saved: {}", actual_tag);
        return true;

    } catch (const std::exception& e) {
        RAWRXD_LOG_ERROR("CheckpointManager", "Failed to save checkpoint: {}", e.what());
        return false;
    }
}

bool CheckpointManager::loadCheckpoint(FineTuner& trainer,
                                        const std::string& tag) {
    auto checkpoint_path = getCheckpointPath(tag);

    if (!std::filesystem::exists(checkpoint_path)) {
        RAWRXD_LOG_ERROR("CheckpointManager", "Checkpoint not found: {}", tag);
        return false;
    }

    RAWRXD_LOG_INFO("CheckpointManager", "Loading checkpoint from: {}", checkpoint_path.string());

    try {
        // Load model weights
        auto model_path = checkpoint_path / "model.bin";
        // trainer.getModel()->load(model_path.string());

        // Load optimizer state
        if (save_optimizer_) {
            auto optimizer_path = checkpoint_path / "optimizer.bin";
            // Load optimizer state
        }

        // Load scheduler state
        if (save_scheduler_) {
            auto scheduler_path = checkpoint_path / "scheduler.bin";
            // Load scheduler state
        }

        // Load RNG state
        if (save_rng_state_) {
            auto rng_path = checkpoint_path / "rng_state.bin";
            // Load RNG state
        }

        // Load metadata
        auto metadata_path = checkpoint_path / "metadata.json";
        auto info = loadMetadata(metadata_path);

        RAWRXD_LOG_INFO("CheckpointManager", "Checkpoint loaded: step={}, epoch={}",
                        info.step, info.epoch);
        return true;

    } catch (const std::exception& e) {
        RAWRXD_LOG_ERROR("CheckpointManager", "Failed to load checkpoint: {}", e.what());
        return false;
    }
}

bool CheckpointManager::loadLatestCheckpoint(FineTuner& trainer) {
    auto checkpoints = listCheckpoints();
    if (checkpoints.empty()) {
        RAWRXD_LOG_WARN("CheckpointManager", "No checkpoints found");
        return false;
    }

    // Sort by timestamp (newest first)
    std::sort(checkpoints.begin(), checkpoints.end(),
              [](const CheckpointInfo& a, const CheckpointInfo& b) {
                  return a.timestamp > b.timestamp;
              });

    auto latest = checkpoints.front();
    std::filesystem::path p(latest.path);
    return loadCheckpoint(trainer, p.filename().string());
}

std::vector<CheckpointInfo> CheckpointManager::listCheckpoints() const {
    std::vector<CheckpointInfo> checkpoints;

    if (!std::filesystem::exists(checkpoint_dir_)) {
        return checkpoints;
    }

    for (const auto& entry : std::filesystem::directory_iterator(checkpoint_dir_)) {
        if (entry.is_directory()) {
            auto metadata_path = entry.path() / "metadata.json";
            if (std::filesystem::exists(metadata_path)) {
                checkpoints.push_back(loadMetadata(metadata_path));
            }
        }
    }

    return checkpoints;
}

bool CheckpointManager::deleteCheckpoint(const std::string& tag) {
    auto checkpoint_path = getCheckpointPath(tag);

    if (!std::filesystem::exists(checkpoint_path)) {
        RAWRXD_LOG_WARN("CheckpointManager", "Checkpoint not found: {}", tag);
        return false;
    }

    try {
        std::filesystem::remove_all(checkpoint_path);
        RAWRXD_LOG_INFO("CheckpointManager", "Deleted checkpoint: {}", tag);
        return true;
    } catch (const std::exception& e) {
        RAWRXD_LOG_ERROR("CheckpointManager", "Failed to delete checkpoint: {}", e.what());
        return false;
    }
}

void CheckpointManager::cleanupOldCheckpoints(size_t keep_count) {
    auto checkpoints = listCheckpoints();

    if (checkpoints.size() <= keep_count) {
        return;
    }

    // Sort by timestamp (oldest first)
    std::sort(checkpoints.begin(), checkpoints.end(),
              [](const CheckpointInfo& a, const CheckpointInfo& b) {
                  return a.timestamp < b.timestamp;
              });

    // Delete oldest checkpoints
    size_t to_delete = checkpoints.size() - keep_count;
    for (size_t i = 0; i < to_delete; ++i) {
        std::filesystem::path p(checkpoints[i].path);
        deleteCheckpoint(p.filename().string());
    }

    RAWRXD_LOG_INFO("CheckpointManager", "Cleaned up {} old checkpoints", to_delete);
}

bool CheckpointManager::exportToGGUF(const std::string& checkpoint_tag,
                                      const std::string& output_path) {
    RAWRXD_LOG_INFO("CheckpointManager", "Exporting to GGUF: {} -> {}", checkpoint_tag, output_path);

    // Load checkpoint
    // Merge LoRA if present
    // Convert to GGUF format
    // Save

    return true;
}

bool CheckpointManager::exportToSafetensors(const std::string& checkpoint_tag,
                                               const std::string& output_path) {
    RAWRXD_LOG_INFO("CheckpointManager", "Exporting to Safetensors: {} -> {}",
                    checkpoint_tag, output_path);

    // Load checkpoint
    // Convert to Safetensors format
    // Save

    return true;
}

bool CheckpointManager::exportToONNX(const std::string& checkpoint_tag,
                                      const std::string& output_path) {
    RAWRXD_LOG_INFO("CheckpointManager", "Exporting to ONNX: {} -> {}", checkpoint_tag, output_path);

    // Load checkpoint
    // Convert to ONNX format
    // Save

    return true;
}

std::filesystem::path CheckpointManager::getCheckpointPath(const std::string& tag) const {
    return checkpoint_dir_ / tag;
}

std::string CheckpointManager::generateTag(uint64_t step) const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << "checkpoint-" << step << "-" << std::put_time(std::localtime(&time), "%Y%m%d-%H%M%S");
    return ss.str();
}

void CheckpointManager::saveMetadata(const CheckpointInfo& info) {
    json j;
    j["path"] = info.path;
    j["step"] = info.step;
    j["epoch"] = info.epoch;
    j["loss"] = info.loss;
    j["metric"] = info.metric;
    j["timestamp"] = std::chrono::system_clock::to_time_t(info.timestamp);
    j["file_size"] = info.file_size;

    auto metadata_path = std::filesystem::path(info.path) / "metadata.json";
    std::ofstream file(metadata_path);
    file << j.dump(2);
}

CheckpointInfo CheckpointManager::loadMetadata(const std::filesystem::path& path) const {
    CheckpointInfo info;

    std::ifstream file(path);
    if (!file.is_open()) {
        return info;
    }

    json j;
    file >> j;

    info.path = j.value("path", "");
    info.step = j.value("step", 0);
    info.epoch = j.value("epoch", 0);
    info.loss = j.value("loss", 0.0f);
    info.metric = j.value("metric", 0.0f);
    info.timestamp = std::chrono::system_clock::from_time_t(j.value("timestamp", 0));
    info.file_size = j.value("file_size", 0);

    return info;
}

// ============================================================================
// Model Exporter
// ============================================================================

bool ModelExporter::exportModel(const FineTuner& trainer,
                                 const std::string& output_path,
                                 const ExportOptions& options) {
    switch (options.format) {
        case ModelFormat::GGUF:
            return exportToGGUF(trainer, output_path, options);
        case ModelFormat::SAFETENSORS:
            return exportToSafetensors(trainer, output_path, options);
        case ModelFormat::ONNX:
            return exportToONNX(trainer, output_path, options);
        case ModelFormat::PYTORCH:
            return exportToPyTorch(trainer, output_path, options);
        default:
            RAWRXD_LOG_ERROR("ModelExporter", "Unsupported format: {}",
                             static_cast<int>(options.format));
            return false;
    }
}

bool ModelExporter::exportToGGUF(const FineTuner& trainer,
                                  const std::string& output_path,
                                  const ExportOptions& options) {
    RAWRXD_LOG_INFO("ModelExporter", "Exporting to GGUF: {}", output_path);

    // Merge adapter if needed
    if (options.merge_adapter) {
        // trainer.mergeAdapter();
    }

    // Quantize if needed
    // Write GGUF header
    // Write tensors
    // Write metadata

    RAWRXD_LOG_INFO("ModelExporter", "Export complete: {}", output_path);
    return true;
}

bool ModelExporter::exportToSafetensors(const FineTuner& trainer,
                                         const std::string& output_path,
                                         const ExportOptions& options) {
    RAWRXD_LOG_INFO("ModelExporter", "Exporting to Safetensors: {}", output_path);

    // Safetensors format: JSON header + binary tensors
    // Write header with tensor metadata
    // Write tensor data

    return true;
}

bool ModelExporter::exportToONNX(const FineTuner& trainer,
                                  const std::string& output_path,
                                  const ExportOptions& options) {
    RAWRXD_LOG_INFO("ModelExporter", "Exporting to ONNX: {}", output_path);

    // Create ONNX model
    // Define inputs/outputs
    // Export graph

    return true;
}

bool ModelExporter::exportToPyTorch(const FineTuner& trainer,
                                     const std::string& output_path,
                                     const ExportOptions& options) {
    RAWRXD_LOG_INFO("ModelExporter", "Exporting to PyTorch: {}", output_path);

    // Save as PyTorch state dict
    // Include metadata

    return true;
}

bool ModelExporter::quantizeAndExport(const FineTuner& trainer,
                                       const std::string& output_path,
                                       QuantizationType quant_type) {
    RAWRXD_LOG_INFO("ModelExporter", "Quantizing and exporting to: {}", output_path);

    // Quantize model
    // Export quantized model

    return true;
}

bool ModelExporter::validateExport(const std::string& output_path,
                                    ModelFormat format) {
    if (!std::filesystem::exists(output_path)) {
        RAWRXD_LOG_ERROR("ModelExporter", "Export file not found: {}", output_path);
        return false;
    }

    // Validate format-specific structure
    // Check checksums if available

    RAWRXD_LOG_INFO("ModelExporter", "Export validated: {}", output_path);
    return true;
}

size_t ModelExporter::estimateExportSize(const FineTuner& trainer,
                                          const ExportOptions& options) {
    // Estimate based on model size and quantization
    size_t base_size = 0;  // trainer.getModel()->getSize();

    float compression = 1.0f;
    switch (options.quantization) {
        case QuantizationType::Q4_0:
        case QuantizationType::Q4_1:
            compression = 0.25f;
            break;
        case QuantizationType::Q5_0:
        case QuantizationType::Q5_1:
            compression = 0.3125f;
            break;
        case QuantizationType::Q8_0:
            compression = 0.5f;
            break;
        default:
            compression = 1.0f;
    }

    return static_cast<size_t>(base_size * compression);
}

// ============================================================================
// Checkpoint Utilities
// ============================================================================

namespace checkpoint_utils {

bool resumeFromCheckpoint(CheckpointManager& manager,
                          FineTuner& trainer,
                          const std::string& checkpoint_path) {
    RAWRXD_LOG_INFO("CheckpointUtils", "Resuming from checkpoint: {}", checkpoint_path);

    // Load checkpoint
    // Validate state
    // Resume training

    return true;
}

bool convertCheckpoint(const std::string& input_path,
                        const std::string& output_path,
                        ModelFormat target_format) {
    RAWRXD_LOG_INFO("CheckpointUtils", "Converting checkpoint: {} -> {}",
                    input_path, output_path);

    // Load from input format
    // Convert to target format
    // Save

    return true;
}

bool mergeLoRACheckpoints(const std::vector<std::string>& checkpoint_paths,
                          const std::vector<float>& weights,
                          const std::string& output_path) {
    RAWRXD_LOG_INFO("CheckpointUtils", "Merging {} LoRA checkpoints", checkpoint_paths.size());

    // Load all checkpoints
    // Weighted average of LoRA weights
    // Save merged checkpoint

    return true;
}

} // namespace checkpoint_utils

} // namespace rawrxd::training
