// RawrXD Fine-Tuner
// Phase AT: Fine-Tuning Infrastructure

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <chrono>

namespace rawrxd {
namespace training {

// Fine-tuning method
enum class FineTuneMethod {
    FULL,
    LORA,
    QLORA,
    ADAPTER
};

// Training state
enum class TrainingState {
    IDLE,
    INITIALIZING,
    TRAINING,
    VALIDATING,
    PAUSED,
    COMPLETED,
    ERROR
};

// Training metrics
struct TrainingMetrics {
    int epoch;
    int step;
    float loss;
    float learning_rate;
    float perplexity;
    float accuracy;
    std::chrono::seconds elapsed_time;
    float samples_per_second;
    float gpu_memory_gb;
    
    TrainingMetrics()
        : epoch(0)
        , step(0)
        , loss(0.0f)
        , learning_rate(0.0f)
        , perplexity(0.0f)
        , accuracy(0.0f)
        , samples_per_second(0.0f)
        , gpu_memory_gb(0.0f) {}
};

// LoRA configuration
struct LoRAConfig {
    int rank;
    float alpha;
    float dropout;
    std::vector<std::string> target_modules;
    bool bias;
    
    LoRAConfig()
        : rank(8)
        , alpha(16.0f)
        , dropout(0.0f)
        , bias(false) {}
};

// Training configuration
struct TrainingConfig {
    // Method
    FineTuneMethod method;
    LoRAConfig lora_config;
    
    // Training hyperparameters
    int num_epochs;
    int batch_size;
    int gradient_accumulation_steps;
    float learning_rate;
    float weight_decay;
    float warmup_ratio;
    float max_grad_norm;
    
    // Optimization
    std::string optimizer;
    std::string lr_scheduler;
    float lr_scheduler_kwargs;
    
    // Data
    std::string dataset_path;
    std::string output_dir;
    int max_seq_length;
    int num_workers;
    
    // Checkpointing
    int save_steps;
    int eval_steps;
    int logging_steps;
    int max_checkpoints;
    
    // System
    std::string device;
    bool fp16;
    bool bf16;
    int seed;
    
    TrainingConfig()
        : method(FineTuneMethod::LORA)
        , num_epochs(3)
        , batch_size(4)
        , gradient_accumulation_steps(1)
        , learning_rate(5e-5f)
        , weight_decay(0.01f)
        , warmup_ratio(0.1f)
        , max_grad_norm(1.0f)
        , optimizer("adamw")
        , lr_scheduler("linear")
        , max_seq_length(512)
        , num_workers(4)
        , save_steps(500)
        , eval_steps(500)
        , logging_steps(10)
        , max_checkpoints(3)
        , device("cuda")
        , fp16(false)
        , bf16(false)
        , seed(42) {}
};

// Checkpoint info
struct CheckpointInfo {
    std::string path;
    int epoch;
    int step;
    float loss;
    std::chrono::system_clock::time_point timestamp;
    
    CheckpointInfo()
        : epoch(0)
        , step(0)
        , loss(0.0f) {
        timestamp = std::chrono::system_clock::now();
    }
};

// Forward declarations
class FineTuner;
class LoRAAdapter;
class CheckpointManager;

// Callback types
using TrainingCallback = std::function<void(const TrainingMetrics&)>;
using CheckpointCallback = std::function<void(const CheckpointInfo&)>;

/**
 * FineTuner - Model fine-tuning controller
 */
class FineTuner {
public:
    FineTuner();
    ~FineTuner();
    
    // Initialize
    bool initialize(const TrainingConfig& config);
    void shutdown();
    
    // Training control
    bool train(const std::string& dataset_path);
    bool trainFromCheckpoint(const std::string& checkpoint_path);
    void pause();
    void resume();
    void stop();
    
    // Validation
    float validate(const std::string& validation_path);
    
    // State
    TrainingState getState() const;
    TrainingMetrics getCurrentMetrics() const;
    float getBestLoss() const;
    int getCurrentEpoch() const;
    int getCurrentStep() const;
    
    // Callbacks
    void setTrainingCallback(TrainingCallback callback);
    void setCheckpointCallback(CheckpointCallback callback);
    
    // Export
    bool exportModel(const std::string& output_path, const std::string& format);
    bool mergeLoRA(const std::string& output_path);
    
    // Configuration
    void updateConfig(const TrainingConfig& config);
    TrainingConfig getConfig() const;
    
    // History
    std::vector<TrainingMetrics> getTrainingHistory() const;
    std::vector<CheckpointInfo> getCheckpoints() const;
    
private:
    TrainingConfig config_;
    TrainingState state_;
    TrainingMetrics current_metrics_;
    float best_loss_;
    
    std::unique_ptr<LoRAAdapter> lora_adapter_;
    std::unique_ptr<CheckpointManager> checkpoint_manager_;
    
    TrainingCallback training_callback_;
    CheckpointCallback checkpoint_callback_;
    
    std::vector<TrainingMetrics> training_history_;
    std::vector<CheckpointInfo> checkpoints_;
    
    bool initialized_;
    bool should_stop_;
    bool paused_;
    
    // Internal methods
    bool setupModel();
    bool setupOptimizer();
    bool setupDataLoader(const std::string& dataset_path);
    void trainingLoop();
    void evaluateStep();
    void saveCheckpoint();
    void logMetrics(const TrainingMetrics& metrics);
};

/**
 * LoRAAdapter - Low-Rank Adaptation
 */
class LoRAAdapter {
public:
    LoRAAdapter();
    ~LoRAAdapter();
    
    bool initialize(const LoRAConfig& config);
    bool applyToModel(void* model);  // Model pointer would be typed in real implementation
    
    // Parameter management
    size_t getTrainableParameterCount() const;
    size_t getTotalParameterCount() const;
    float getTrainableParameterRatio() const;
    
    // Save/Load
    bool saveAdapter(const std::string& path);
    bool loadAdapter(const std::string& path);
    
    // Merge
    bool mergeIntoModel(void* model);
    
private:
    LoRAConfig config_;
    bool initialized_;
    
    struct LoRALayer {
        std::string name;
        int in_features;
        int out_features;
        std::vector<float> lora_a;
        std::vector<float> lora_b;
    };
    
    std::vector<LoRALayer> layers_;
};

/**
 * CheckpointManager - Training checkpoint management
 */
class CheckpointManager {
public:
    CheckpointManager();
    ~CheckpointManager();
    
    bool initialize(const std::string& checkpoint_dir, int max_checkpoints);
    
    // Save/Load
    bool saveCheckpoint(const CheckpointInfo& info, void* model_state, void* optimizer_state);
    bool loadCheckpoint(const std::string& path, void* model_state, void* optimizer_state);
    
    // Management
    std::vector<CheckpointInfo> listCheckpoints() const;
    bool deleteCheckpoint(const std::string& path);
    void cleanupOldCheckpoints();
    
    // Best checkpoint
    std::string getBestCheckpoint() const;
    void updateBestCheckpoint(const std::string& path, float loss);
    
private:
    std::string checkpoint_dir_;
    int max_checkpoints_;
    std::string best_checkpoint_path_;
    float best_loss_;
    
    std::vector<CheckpointInfo> checkpoints_;
};

// Global accessor
FineTuner* getFineTuner();
void setFineTuner(std::unique_ptr<FineTuner> tuner);

// Utility functions
std::string fineTuneMethodToString(FineTuneMethod method);
std::string trainingStateToString(TrainingState state);

} // namespace training
} // namespace rawrxd
