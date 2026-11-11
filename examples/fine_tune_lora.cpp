/**
 * @file fine_tune_lora.cpp
 * @brief Example: Fine-tune a model using LoRA
 *
 * This example demonstrates how to fine-tune a language model
 * using LoRA (Low-Rank Adaptation) for efficient parameter updates.
 */

#include "training/fine_tuner.hpp"
#include "training/training_config.hpp"
#include "training/data/dataset_loader.hpp"
#include "core/model_loader.hpp"
#include "core/logger.hpp"
#include <iostream>

using namespace rawrxd;
using namespace rawrxd::training;

int main(int argc, char* argv[]) {
    // ============================================================================
    // Parse command line arguments
    // ============================================================================

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <base_model> <dataset> [output_dir]\n";
        std::cerr << "\nExample:\n";
        std::cerr << "  " << argv[0] << " models/llama-7b.gguf data/alpaca.jsonl ./output\n";
        return 1;
    }

    std::string base_model_path = argv[1];
    std::string dataset_path = argv[2];
    std::string output_dir = (argc > 3) ? argv[3] : "./output";

    RAWRXD_LOG_INFO("FineTuneExample", "Starting LoRA fine-tuning");
    RAWRXD_LOG_INFO("FineTuneExample", "Base model: {}", base_model_path);
    RAWRXD_LOG_INFO("FineTuneExample", "Dataset: {}", dataset_path);
    RAWRXD_LOG_INFO("FineTuneExample", "Output: {}", output_dir);

    // ============================================================================
    // Load base model
    // ============================================================================

    RAWRXD_LOG_INFO("FineTuneExample", "Loading base model...");
    auto model = loadModel(base_model_path);
    if (!model) {
        RAWRXD_LOG_ERROR("FineTuneExample", "Failed to load base model");
        return 1;
    }
    RAWRXD_LOG_INFO("FineTuneExample", "Base model loaded successfully");

    // ============================================================================
    // Configure training
    // ============================================================================

    TrainingConfig config;
    config.method = FineTuneMethod::LORA;
    config.learning_rate = 5e-5f;
    config.min_learning_rate = 0.0f;
    config.weight_decay = 0.01f;
    config.beta1 = 0.9f;
    config.beta2 = 0.999f;
    config.epsilon = 1e-8f;
    config.max_grad_norm = 1.0f;

    config.num_epochs = 3;
    config.batch_size = 4;
    config.gradient_accumulation_steps = 4;  // Effective batch size = 16
    config.warmup_steps = 100;

    config.optimizer = OptimizerType::ADAMW;
    config.lr_scheduler = LRSchedulerType::WARMUP_COSINE;

    config.shuffle = true;
    config.num_workers = 4;

    config.checkpoint_dir = output_dir + "/checkpoints";
    config.checkpoint_steps = 500;
    config.save_total_limit = 3;

    config.log_interval = 10;
    config.eval_interval = 100;
    config.logging_dir = output_dir + "/logs";

    config.fp16 = true;  // Enable mixed precision
    config.gradient_checkpointing = true;

    config.seed = 42;

    // Validate configuration
    try {
        config.validate();
    } catch (const std::exception& e) {
        RAWRXD_LOG_ERROR("FineTuneExample", "Invalid configuration: {}", e.what());
        return 1;
    }

    // ============================================================================
    // Configure LoRA
    // ============================================================================

    LoRAConfig lora_config;
    lora_config.rank = 8;                    // LoRA rank
    lora_config.alpha = 16;                  // Scaling factor
    lora_config.dropout = 0.05f;            // Dropout for regularization
    lora_config.target_modules = "q_proj,k_proj,v_proj,o_proj";
    lora_config.use_rslora = false;         // Standard LoRA
    lora_config.use_dora = false;             // Standard LoRA

    RAWRXD_LOG_INFO("FineTuneExample", "LoRA config: rank={}, alpha={}",
                    lora_config.rank, lora_config.alpha);

    // ============================================================================
    // Load dataset
    // ============================================================================

    RAWRXD_LOG_INFO("FineTuneExample", "Loading dataset...");

    DatasetConfig dataset_config;
    dataset_config.path = dataset_path;
    dataset_config.format = "jsonl";
    dataset_config.text_column = "text";
    dataset_config.max_length = 2048;
    dataset_config.truncation = true;
    dataset_config.padding = true;

    auto dataset = createDataset(dataset_config);
    if (!dataset->load(dataset_path)) {
        RAWRXD_LOG_ERROR("FineTuneExample", "Failed to load dataset");
        return 1;
    }

    RAWRXD_LOG_INFO("FineTuneExample", "Dataset loaded: {} samples", dataset->size());

    // Split into train/validation
    auto [train_dataset, val_dataset] = dataset->split(0.9f);
    RAWRXD_LOG_INFO("FineTuneExample", "Train: {} samples, Val: {} samples",
                    train_dataset->size(), val_dataset->size());

    // ============================================================================
    // Create trainer
    // ============================================================================

    RAWRXD_LOG_INFO("FineTuneExample", "Creating LoRA trainer...");
    auto trainer = createFineTuner(FineTuneMethod::LORA, config, &lora_config);
    if (!trainer) {
        RAWRXD_LOG_ERROR("FineTuneExample", "Failed to create trainer");
        return 1;
    }

    // Initialize trainer
    if (!trainer->initialize(model)) {
        RAWRXD_LOG_ERROR("FineTuneExample", "Failed to initialize trainer");
        return 1;
    }

    // Get trainable parameter count
    auto* lora_trainer = dynamic_cast<LoRAFineTuner*>(trainer.get());
    if (lora_trainer) {
        size_t trainable = lora_trainer->getAdapter()->getTrainableParameterCount();
        size_t total = model->getParameterCount();
        float percent = 100.0f * trainable / total;
        RAWRXD_LOG_INFO("FineTuneExample",
                        "Trainable parameters: {} / {} ({:.2f}%)",
                        trainable, total, percent);
    }

    // ============================================================================
    // Set up callbacks
    // ============================================================================

    // Step callback - called after each training step
    trainer->setStepCallback([](const TrainingMetrics& metrics) {
        if (metrics.step % 10 == 0) {
            std::cout << "\rStep: " << metrics.step
                      << " | Loss: " << std::fixed << std::setprecision(4) << metrics.loss
                      << " | LR: " << std::scientific << metrics.learning_rate
                      << " | Tokens/s: " << std::fixed << metrics.tokens_per_second_avg
                      << std::flush;
        }
    });

    // Epoch callback - called after each epoch
    trainer->setEpochCallback([](const TrainingMetrics& metrics) {
        std::cout << "\nEpoch " << metrics.epoch << " completed"
                  << " | Loss: " << metrics.loss
                  << " | Time: " << metrics.total_time.count() / 1000.0 << "s\n";
    });

    // Checkpoint callback - called when checkpoint is saved
    CheckpointManager checkpoint_manager(config.checkpoint_dir);
    trainer->setCheckpointCallback([&checkpoint_manager](const std::string& path) {
        RAWRXD_LOG_INFO("FineTuneExample", "Checkpoint saved: {}", path);
    });

    // ============================================================================
    // Training loop
    // ============================================================================

    RAWRXD_LOG_INFO("FineTuneExample", "Starting training...");
    auto train_start = std::chrono::steady_clock::now();

    if (!trainer->train(*train_dataset)) {
        RAWRXD_LOG_ERROR("FineTuneExample", "Training failed");
        return 1;
    }

    auto train_duration = std::chrono::steady_clock::now() - train_start;
    auto train_seconds = std::chrono::duration_cast<std::chrono::seconds>(train_duration).count();

    RAWRXD_LOG_INFO("FineTuneExample", "Training completed in {} seconds", train_seconds);

    // ============================================================================
    // Validation
    // ============================================================================

    RAWRXD_LOG_INFO("FineTuneExample", "Running validation...");
    float val_loss = trainer->validate(*val_dataset);
    RAWRXD_LOG_INFO("FineTuneExample", "Validation loss: {:.4f}", val_loss);

    // ============================================================================
    // Export model
    // ============================================================================

    RAWRXD_LOG_INFO("FineTuneExample", "Exporting model...");

    // Merge LoRA weights into base model (optional)
    if (lora_trainer) {
        lora_trainer->mergeAdapter();
        RAWRXD_LOG_INFO("FineTuneExample", "LoRA weights merged into base model");
    }

    // Export to GGUF
    std::string output_path = output_dir + "/fine_tuned_model.gguf";
    if (ModelExporter::exportToGGUF(*trainer, output_path, QuantizationType::Q4_0)) {
        RAWRXD_LOG_INFO("FineTuneExample", "Model exported to: {}", output_path);
    } else {
        RAWRXD_LOG_ERROR("FineTuneExample", "Failed to export model");
    }

    // Also export adapter separately (for later use)
    if (lora_trainer) {
        std::string adapter_path = output_dir + "/adapter.bin";
        if (lora_trainer->getAdapter()->saveAdapter(adapter_path)) {
            RAWRXD_LOG_INFO("FineTuneExample", "Adapter saved to: {}", adapter_path);
        }
    }

    // ============================================================================
    // Summary
    // ============================================================================

    auto metrics = trainer->getMetrics();

    std::cout << "\n========================================\n";
    std::cout << "Training Summary\n";
    std::cout << "========================================\n";
    std::cout << "Total steps: " << metrics.step << "\n";
    std::cout << "Final loss: " << std::fixed << std::setprecision(4) << metrics.loss << "\n";
    std::cout << "Validation loss: " << val_loss << "\n";
    std::cout << "Total time: " << train_seconds << " seconds\n";
    std::cout << "Tokens processed: " << metrics.tokens_processed << "\n";
    std::cout << "Output: " << output_path << "\n";
    std::cout << "========================================\n";

    RAWRXD_LOG_INFO("FineTuneExample", "Fine-tuning complete!");
    return 0;
}
