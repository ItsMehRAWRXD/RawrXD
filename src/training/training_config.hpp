#pragma once

#include "../core/common.hpp"
#include <string>

namespace rawrxd::training {

// Fine-tuning methods
enum class FineTuneMethod {
    LORA,       // Low-Rank Adaptation
    QLORA,      // Quantized LoRA
    FULL,       // Full fine-tuning
    PREFIX,     // Prefix tuning
    PROMPT,     // Prompt tuning
    ADAPTER,    // Adapter layers
    IA3,        // Infused Adapter by Inhibiting and Amplifying Inner Activations
    P_TUNING    // P-tuning v2
};

// Quantization types for QLoRA
enum class QuantizationType {
    Q4_0,       // 4-bit, block size 32
    Q4_1,       // 4-bit with min
    Q5_0,       // 5-bit
    Q5_1,       // 5-bit with min
    Q8_0,       // 8-bit, block size 32
    F16,        // FP16
    BF16,       // BF16
    NF4,        // Normal Float 4 (QLoRA)
    FP4         // FP4
};

// LoRA configuration
struct LoRAConfig {
    int rank = 8;                    // LoRA rank (r)
    float alpha = 16.0f;           // LoRA alpha (scaling)
    float dropout = 0.0f;          // Dropout probability
    std::string target_modules = "q_proj,k_proj,v_proj,o_proj"; // Modules to apply LoRA
    bool use_rslora = false;       // Use RS-LoRA (rank-stabilized)
    bool use_dora = false;         // Use DoRA (weight-decomposed)

    // Computed scaling factor
    float getScaling() const {
        return alpha / rank;
    }
};

// Optimizer types
enum class OptimizerType {
    ADAM,           // Adam
    ADAMW,          // AdamW
    SGD,            // SGD
    ADAGRAD,        // Adagrad
    ADADELTA,       // Adadelta
    RMSPROP,        // RMSprop
    LION,           // Lion
    ADAM_8BIT,      // 8-bit Adam
    ADAMW_8BIT,     // 8-bit AdamW
    PAGED_ADAMW_8BIT // Paged 8-bit AdamW (QLoRA)
};

// LR scheduler types
enum class LRSchedulerType {
    CONSTANT,           // Constant LR
    LINEAR,             // Linear decay
    COSINE,             // Cosine annealing
    COSINE_WITH_RESTARTS, // Cosine with restarts
    POLYNOMIAL,         // Polynomial decay
    INVERSE_SQRT,       // Inverse square root
    WARMUP_LINEAR,      // Warmup + linear decay
    WARMUP_COSINE       // Warmup + cosine
};

// Training configuration
struct TrainingConfig {
    // Method
    FineTuneMethod method = FineTuneMethod::LORA;

    // Training hyperparameters
    float learning_rate = 5e-5f;
    float min_learning_rate = 0.0f;
    float weight_decay = 0.01f;
    float beta1 = 0.9f;
    float beta2 = 0.999f;
    float epsilon = 1e-8f;
    float max_grad_norm = 1.0f;

    // Training settings
    uint64_t num_epochs = 3;
    uint64_t batch_size = 4;
    uint64_t gradient_accumulation_steps = 4;
    uint64_t warmup_steps = 100;
    uint64_t max_steps = 0;  // 0 = unlimited

    // Optimizer
    OptimizerType optimizer = OptimizerType::ADAMW;
    LRSchedulerType lr_scheduler = LRSchedulerType::WARMUP_LINEAR;

    // Data
    bool shuffle = true;
    uint64_t num_workers = 4;
    std::string train_data_path;
    std::string eval_data_path;
    std::string validation_split = "0.1";

    // Checkpointing
    std::string checkpoint_dir = "./checkpoints";
    uint64_t checkpoint_steps = 500;
    uint64_t save_total_limit = 3;  // Keep only N checkpoints
    bool save_optimizer = true;

    // Logging
    uint64_t log_interval = 10;
    uint64_t eval_interval = 100;
    std::string logging_dir = "./logs";
    std::string tensorboard_dir;
    std::string wandb_project;

    // Memory optimization
    bool fp16 = false;
    bool bf16 = false;
    bool gradient_checkpointing = false;
    uint64_t max_memory_per_gpu = 0;  // 0 = unlimited

    // Early stopping
    bool early_stopping = false;
    uint64_t early_stopping_patience = 3;
    float early_stopping_threshold = 0.0f;

    // Reproducibility
    uint64_t seed = 42;
    bool deterministic = false;

    // Validation
    void validate() const {
        if (batch_size == 0) {
            throw std::invalid_argument("batch_size must be > 0");
        }
        if (learning_rate <= 0.0f) {
            throw std::invalid_argument("learning_rate must be > 0");
        }
        if (num_epochs == 0 && max_steps == 0) {
            throw std::invalid_argument("Either num_epochs or max_steps must be > 0");
        }
        if (fp16 && bf16) {
            throw std::invalid_argument("Cannot use both fp16 and bf16");
        }
    }
};

// Dataset configuration
struct DatasetConfig {
    std::string path;
    std::string format = "json";  // json, jsonl, parquet, csv, txt
    std::string text_column = "text";
    std::string input_column = "input";
    std::string output_column = "output";
    std::string instruction_column = "instruction";
    uint64_t max_length = 2048;
    bool truncation = true;
    bool padding = true;
    std::string padding_side = "right";
};

// Model export configuration
struct ExportConfig {
    std::string output_path;
    ModelFormat format = ModelFormat::GGUF;
    QuantizationType quantization = QuantizationType::Q4_0;
    bool merge_adapter = true;  // Merge LoRA before export
    std::string metadata_author;
    std::string metadata_description;
    std::string metadata_license;
    std::string metadata_source;
};

// Model format
enum class ModelFormat {
    PYTORCH,    // .bin, .pt
    SAFETENSORS, // .safetensors
    GGUF,       // .gguf
    ONNX,       // .onnx
    TENSORRT,   // .trt
    COREML      // .mlmodel
};

// Training state for checkpointing
struct TrainingState {
    uint64_t global_step = 0;
    uint64_t epoch = 0;
    float best_metric = std::numeric_limits<float>::max();
    uint64_t num_epochs_no_improvement = 0;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::milliseconds total_training_time{0};

    void reset() {
        global_step = 0;
        epoch = 0;
        best_metric = std::numeric_limits<float>::max();
        num_epochs_no_improvement = 0;
        total_training_time = std::chrono::milliseconds{0};
    }
};

} // namespace rawrxd::training
