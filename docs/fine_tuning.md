# RawrXD Fine-Tuning Guide

Comprehensive guide for fine-tuning LLMs using RawrXD's training infrastructure.

## Table of Contents

1. [Overview](#overview)
2. [Fine-Tuning Methods](#fine-tuning-methods)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Dataset Preparation](#dataset-preparation)
6. [Training](#training)
7. [Checkpointing](#checkpointing)
8. [Export](#export)
9. [Advanced Topics](#advanced-topics)

## Overview

RawrXD supports multiple fine-tuning approaches:

- **LoRA** (Low-Rank Adaptation): Efficient fine-tuning with minimal parameters
- **QLoRA**: Quantized LoRA for memory-constrained environments
- **Full Fine-Tuning**: Traditional full model fine-tuning
- **Prefix Tuning**: Learn continuous prompts
- **Prompt Tuning**: Soft prompt optimization

## Fine-Tuning Methods

### LoRA (Recommended)

LoRA adds trainable low-rank matrices to attention layers while freezing base weights.

**Advantages:**
- 10-100x fewer trainable parameters
- No inference latency (can merge weights)
- Easy to switch between tasks
- Reduced storage requirements

**Typical Configurations:**

| Model Size | Rank | Alpha | Target Modules | VRAM Required |
|------------|------|-------|----------------|---------------|
| 7B | 8 | 16 | q_proj,v_proj | ~8GB |
| 13B | 16 | 32 | q_proj,k_proj,v_proj,o_proj | ~16GB |
| 70B | 64 | 128 | all linear | ~48GB |

### QLoRA

QLoRA quantizes the base model to 4-bit while keeping LoRA weights in full precision.

**Advantages:**
- Train 70B models on single 48GB GPU
- Minimal accuracy loss with NF4 quantization
- Paged optimizers for memory efficiency

### Full Fine-Tuning

Traditional approach training all model parameters.

**Use when:**
- Maximum accuracy required
- Sufficient compute resources available
- Domain adaptation needs comprehensive changes

## Quick Start

### 1. Prepare Dataset

```json
// train.jsonl
{"instruction": "Explain quantum computing", "input": "", "output": "Quantum computing..."}
{"instruction": "Translate to French", "input": "Hello world", "output": "Bonjour le monde"}
```

### 2. Configure Training

```cpp
#include "training/training_config.hpp"

using namespace rawrxd::training;

TrainingConfig config;
config.method = FineTuneMethod::LORA;
config.learning_rate = 5e-5f;
config.batch_size = 4;
config.num_epochs = 3;
config.gradient_accumulation_steps = 4;

LoRAConfig lora;
lora.rank = 8;
lora.alpha = 16;
lora.target_modules = "q_proj,v_proj";
```

### 3. Run Training

```cpp
auto model = loadModel("base_model.gguf");
auto trainer = createFineTuner(FineTuneMethod::LORA, config, &lora);

trainer->initialize(model);
trainer->train(dataset);
```

## Configuration

### Training Hyperparameters

```cpp
TrainingConfig config;

// Learning rate
config.learning_rate = 5e-5f;        // Initial LR
config.min_learning_rate = 0.0f;     // Final LR
config.lr_scheduler = LRSchedulerType::WARMUP_COSINE;
config.warmup_steps = 100;

// Optimization
config.optimizer = OptimizerType::ADAMW;
config.weight_decay = 0.01f;
config.beta1 = 0.9f;
config.beta2 = 0.999f;
config.epsilon = 1e-8f;

// Training
config.batch_size = 4;
config.gradient_accumulation_steps = 4;  // Effective batch = 16
config.num_epochs = 3;
config.max_grad_norm = 1.0f;

// Memory
config.fp16 = true;                  // Mixed precision
config.gradient_checkpointing = true; // Trade compute for memory
```

### LoRA Configuration

```cpp
LoRAConfig lora;
lora.rank = 8;                       // LoRA rank (r)
lora.alpha = 16;                     // Scaling factor
lora.dropout = 0.05f;                // Regularization
lora.target_modules = "q_proj,k_proj,v_proj,o_proj";
lora.use_rslora = false;             // Rank-stabilized LoRA
lora.use_dora = false;               // Weight-decomposed LoRA
```

### QLoRA Configuration

```cpp
QLoRAConfig qlora;
qlora.quant_type = QuantizationType::NF4;
qlora.use_double_quant = true;       // Nested quantization
qlora.quant_storage_dtype = "uint8";
```

## Dataset Preparation

### Supported Formats

- **JSON/JSONL**: Standard instruction-following format
- **Text**: Raw text files (auto-chunked)
- **Parquet**: Columnar format for large datasets
- **CSV**: Simple tabular format

### Instruction Format

```json
{
  "instruction": "Task description",
  "input": "Optional context",
  "output": "Expected response"
}
```

### Chat Format

```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"},
    {"role": "assistant", "content": "Hi there!"}
  ]
}
```

### Dataset Configuration

```cpp
DatasetConfig dataset;
dataset.path = "data/train.jsonl";
dataset.format = "jsonl";
dataset.text_column = "text";
dataset.max_length = 2048;
dataset.truncation = true;
```

## Training

### Basic Training Loop

```cpp
// Create trainer
auto trainer = createFineTuner(FineTuneMethod::LORA, config, &lora);
trainer->initialize(model);

// Set callbacks
trainer->setStepCallback([](const TrainingMetrics& m) {
    std::cout << "Step " << m.step << ", Loss: " << m.loss << std::endl;
});

// Train
trainer->train(dataset);
```

### Resuming from Checkpoint

```cpp
CheckpointManager manager("./checkpoints");
manager.loadLatestCheckpoint(*trainer);
trainer->train(dataset);  // Continues from saved state
```

### Validation

```cpp
// Evaluate on validation set
float val_loss = trainer->validate(val_dataset);
std::cout << "Validation loss: " << val_loss << std::endl;
```

## Checkpointing

### Automatic Checkpointing

```cpp
config.checkpoint_steps = 500;       // Save every 500 steps
config.checkpoint_dir = "./checkpoints";
config.save_total_limit = 3;         // Keep only 3 checkpoints
```

### Manual Checkpointing

```cpp
CheckpointManager manager("./checkpoints");
manager.saveCheckpoint(*trainer, "best_model");
manager.loadCheckpoint(*trainer, "best_model");
```

### Checkpoint Cleanup

```cpp
// Keep only N most recent checkpoints
manager.cleanupOldCheckpoints(5);
```

## Export

### Export to GGUF

```cpp
ModelExporter::exportToGGUF(*trainer, "model.gguf", QuantizationType::Q4_0);
```

### Export to Safetensors

```cpp
ModelExporter::exportToSafetensors(*trainer, "model.safetensors");
```

### Export with Metadata

```cpp
ModelExporter::exportWithMetadata(
    *trainer,
    "model.gguf",
    ModelFormat::GGUF,
    "Your Name",
    "Fine-tuned model for task X",
    "MIT"
);
```

### Merge LoRA Before Export

```cpp
// Merge adapter into base model
auto lora_trainer = dynamic_cast<LoRAFineTuner*>(trainer.get());
lora_trainer->mergeAdapter();

// Export merged model
ModelExporter::exportModel(*trainer, "merged.gguf", ModelFormat::GGUF);
```

## Advanced Topics

### Multi-LoRA

```cpp
MultiLoRAManager multi_lora;

// Add multiple adapters
multi_lora.addAdapter("math", math_adapter);
multi_lora.addAdapter("coding", coding_adapter);

// Switch between tasks
multi_lora.setActiveAdapter("math");

// Combine adapters
multi_lora.combineAdapters(
    {"math", "coding"},
    {0.6f, 0.4f}  // Weights
);
```

### Gradient Accumulation

```cpp
// Simulate large batch size
config.batch_size = 2;
config.gradient_accumulation_steps = 8;
// Effective batch size = 16
```

### Mixed Precision Training

```cpp
config.fp16 = true;   // FP16 mixed precision
// or
config.bf16 = true;   // BF16 (better stability)
```

### Learning Rate Schedulers

```cpp
// Linear with warmup
config.lr_scheduler = LRSchedulerType::WARMUP_LINEAR;
config.warmup_steps = 100;

// Cosine annealing
config.lr_scheduler = LRSchedulerType::COSINE;

// Constant with warmup
config.lr_scheduler = LRSchedulerType::WARMUP_CONSTANT;
```

### Custom Loss Functions

```cpp
// Implement custom loss
class CustomFineTuner : public LoRAFineTuner {
protected:
    float computeLoss(const Batch& batch) override {
        // Custom loss computation
        return base_loss + regularization_term;
    }
};
```

## Troubleshooting

### Out of Memory

1. Reduce batch size
2. Enable gradient checkpointing
3. Use QLoRA instead of LoRA
4. Reduce sequence length
5. Enable gradient accumulation

### Training Instability

1. Reduce learning rate
2. Increase warmup steps
3. Use BF16 instead of FP16
4. Add gradient clipping
5. Check for data quality issues

### Slow Training

1. Increase batch size (if memory allows)
2. Reduce gradient accumulation steps
3. Use multiple GPUs
4. Optimize data loading (increase num_workers)
5. Profile to find bottlenecks

## Best Practices

1. **Start with LoRA**: Most efficient for most use cases
2. **Use validation set**: Monitor for overfitting
3. **Save checkpoints frequently**: Protect against interruptions
4. **Log metrics**: Track loss, learning rate, throughput
5. **Test before deploying**: Validate exported model
6. **Document hyperparameters**: Reproducibility is key

## Examples

See `examples/fine_tune_lora.cpp` for a complete working example.
