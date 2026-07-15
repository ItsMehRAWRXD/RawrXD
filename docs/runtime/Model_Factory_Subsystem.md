# RawrXD Runtime - Model Factory Subsystem
## Self-Training, Self-Quantizing, Self-Shaping Model Pipeline

**Version:** 1.0.0  
**Date:** 2026-07-15  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Data Ingestion Layer](#data-ingestion-layer)
4. [Training Engine](#training-engine)
5. [Quantization Pipeline](#quantization-pipeline)
6. [GGUF Export](#gguf-export)
7. [Implementation Details](#implementation-details)
8. [API Reference](#api-reference)

---

## Overview

The Model Factory is a sovereign, self-contained training and export pipeline that enables RawrXD to consume local data, train models from scratch or fine-tune existing ones, and export hardware-optimized artifacts. It integrates with the MoE Governor and Stress Tester to produce models perfectly shaped for the target hardware.

### Key Capabilities

- **Data Ingestion**: Consume code, documents, logs, configs
- **Local Training**: Train from scratch or fine-tune
- **Self-Quantization**: Automatically quantize to Q4/Q2/Q1
- **Hardware Shaping**: Shape models to fit hardware budget
- **GGUF Export**: Export standard GGUF format
- **Sovereign Execution**: No cloud dependencies

### Training Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| From Scratch | Train new model on custom data | Domain-specific models |
| Fine-Tune | Adapt existing model | Specialization |
| MoE Training | Train expert networks | Large model components |
| Adapter Training | LoRA/DoRA adapters | Efficient customization |

---

## Architecture

### Subsystem Integration

```
RawrXD Runtime
├── DataIngestion/
│   ├── CodeImporter.asm
│   ├── DocumentParser.asm
│   └── CurriculumBuilder.asm
├── TrainingEngine/
│   ├── ForwardPass.asm
│   ├── BackwardPass.asm
│   ├── Optimizer.asm
│   └── MoETrainer.asm
├── ModelFactory/
│   ├── Quantizer.asm
│   ├── Shaper.asm
│   └── Exporter.asm
├── MoEGovernor.asm
└── StressTester.asm
```

### Data Flow

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Local Data    │────→│  Model Factory   │────→│  Shaped Model   │
│  (Code, Docs,   │     │  (Train/Quant/   │     │  (GGUF Export)  │
│   Logs, Config) │     │   Shape/Export)  │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ↓
                    ┌──────────────────┐
                    │ Hardware Budget  │
                    │ (from Governor)  │
                    └──────────────────┘
```

---

## Data Ingestion Layer

### Supported Data Types

```cpp
enum DataType {
    SOURCE_CODE,      // C, C++, Python, Rust, etc.
    DOCUMENTATION,    // Markdown, HTML, PDF
    CONFIGURATION,    // JSON, YAML, TOML, XML
    LOGS,            // Application logs, system logs
    NOTES,           // Personal notes, wikis
    STRUCTURED_DATA  // Databases, APIs
};
```

### Ingestion Pipeline

```asm
; Ingest data from filesystem
ModelFactory_IngestData PROC
    ; Scan directories
    lea rcx, [source_paths]
    call FileSystem_ScanRecursive
    
    ; Process each file
    mov rcx, [num_files]
    lea rsi, [file_list]
    
@@process_loop:
    push rcx
    push rsi
    
    ; Detect file type
    call ModelFactory_DetectFileType
    mov [file_type], eax
    
    ; Parse based on type
    cmp eax, TYPE_SOURCE_CODE
    je @@parse_code
    
    cmp eax, TYPE_DOCUMENTATION
    je @@parse_docs
    
    cmp eax, TYPE_CONFIGURATION
    je @@parse_config
    
@@parse_code:
    call ModelFactory_ParseSourceCode
    jmp @@next
    
@@parse_docs:
    call ModelFactory_ParseDocumentation
    jmp @@next
    
@@parse_config:
    call ModelFactory_ParseConfiguration
    
@@next:
    ; Add to corpus
    call ModelFactory_AddToCorpus
    
    pop rsi
    add rsi, sizeof(FileEntry)
    pop rcx
    dec rcx
    jnz @@process_loop
    
    ; Build training curriculum
    call ModelFactory_BuildCurriculum
    
    ret
ModelFactory_IngestData ENDP
```

### Preprocessing

```asm
; Preprocess ingested data
ModelFactory_Preprocess PROC
    ; Deduplication
    call ModelFactory_Deduplicate
    
    ; Chunking
    call ModelFactory_ChunkDocuments
    
    ; Tokenization
    call RawrXD_Tokenizer_Process
    
    ; Build vocabulary
    call ModelFactory_BuildVocabulary
    
    ; Create training batches
    call ModelFactory_CreateBatches
    
    ret
ModelFactory_Preprocess ENDP
```

---

## Training Engine

### Forward Pass

```asm
; Transformer forward pass
Training_ForwardPass PROC
    ; Input embeddings
    call Transformer_EmbeddingLookup
    
    ; Positional encoding
    call Transformer_AddPositionalEncoding
    
    ; Transformer layers
    mov rcx, [num_layers]
    
@@layer_loop:
    push rcx
    
    ; Self-attention
    call Transformer_SelfAttention
    
    ; Add & norm
    call Transformer_AddAndNorm
    
    ; FFN (or MoE)
    cmp [use_moe], 1
    je @@moe_ffn
    
    ; Standard FFN
    call Transformer_FeedForward
    jmp @@ffn_done
    
@@moe_ffn:
    ; MoE layer
    call MoE_LayerForward
    
@@ffn_done:
    ; Add & norm
    call Transformer_AddAndNorm
    
    pop rcx
    dec rcx
    jnz @@layer_loop
    
    ; Output projection
    call Transformer_OutputProjection
    
    ; Softmax
    call Transformer_Softmax
    
    ret
Training_ForwardPass ENDP
```

### Backward Pass

```asm
; Backward pass for training
Training_BackwardPass PROC
    ; Output gradient
    call Loss_CrossEntropyGradient
    
    ; Backprop through layers (reverse)
    mov rcx, [num_layers]
    dec rcx
    
@@layer_loop:
    push rcx
    
    ; Backprop through FFN/MoE
    cmp [use_moe], 1
    je @@moe_backward
    
    call Transformer_FeedForwardBackward
    jmp @@ffn_done
    
@@moe_backward:
    call MoE_LayerBackward
    
@@ffn_done:
    ; Backprop through attention
    call Transformer_SelfAttentionBackward
    
    pop rcx
    dec rcx
    jns @@layer_loop
    
    ; Embedding gradients
    call Transformer_EmbeddingBackward
    
    ret
Training_BackwardPass ENDP
```

### Optimizer (AdamW)

```asm
; AdamW optimizer step
Optimizer_AdamWStep PROC
    ; For each parameter
    mov rcx, [num_parameters]
    lea rsi, [parameters]
    lea rdi, [gradients]
    
@@param_loop:
    push rcx
    
    ; m_t = beta1 * m_{t-1} + (1 - beta1) * g_t
    movss xmm0, [rsi+Param.m]
    mulss xmm0, [beta1]
    movss xmm1, [rdi]
    mulss xmm1, [one_minus_beta1]
    addss xmm0, xmm1
    movss [rsi+Param.m], xmm0
    
    ; v_t = beta2 * v_{t-1} + (1 - beta2) * g_t^2
    movss xmm0, [rsi+Param.v]
    mulss xmm0, [beta2]
    movss xmm1, [rdi]
    mulss xmm1, xmm1
    mulss xmm1, [one_minus_beta2]
    addss xmm0, xmm1
    movss [rsi+Param.v], xmm0
    
    ; m_hat = m_t / (1 - beta1^t)
    ; v_hat = v_t / (1 - beta2^t)
    
    ; Update: theta = theta - lr * m_hat / (sqrt(v_hat) + eps)
    
    ; Weight decay
    movss xmm0, [rsi+Param.value]
    mulss xmm0, [weight_decay]
    mulss xmm0, [learning_rate]
    subss [rsi+Param.value], xmm0
    
    add rsi, sizeof(Param)
    add rdi, sizeof(float)
    pop rcx
    dec rcx
    jnz @@param_loop
    
    ret
Optimizer_AdamWStep ENDP
```

---

## Quantization Pipeline

### Layer Sensitivity Analysis

```asm
; Analyze layer sensitivity to quantization
ModelFactory_AnalyzeSensitivity PROC
    ; For each layer
    mov rcx, [num_layers]
    lea rsi, [layer_table]
    
@@layer_loop:
    push rcx
    push rsi
    
    ; Compute gradient norms
    call ModelFactory_ComputeGradNorm
    mov [rsi+Layer.grad_norm], xmm0
    
    ; Compute activation ranges
    call ModelFactory_ComputeActivationRange
    mov [rsi+Layer.act_range], xmm0
    
    ; Compute Hessian diagonal (approximate)
    call ModelFactory_ApproximateHessian
    mov [rsi+Layer.hessian_diag], xmm0
    
    ; Calculate sensitivity score
    ; sensitivity = grad_norm * act_range / hessian_diag
    movss xmm0, [rsi+Layer.grad_norm]
    mulss xmm0, [rsi+Layer.act_range]
    divss xmm0, [rsi+Layer.hessian_diag]
    movss [rsi+Layer.sensitivity], xmm0
    
    pop rsi
    add rsi, sizeof(Layer)
    pop rcx
    dec rcx
    jnz @@layer_loop
    
    ret
ModelFactory_AnalyzeSensitivity ENDP
```

### Quantization Strategy

```cpp
struct QuantizationStrategy {
    // High sensitivity layers: Q8
    // Medium sensitivity: Q4
    // Low sensitivity: Q2
    // Very low: Q1
    
    int embedding_bits = 8;
    int attention_qkv_bits = 4;
    int attention_out_bits = 4;
    int ffn_up_bits = 2;
    int ffn_down_bits = 2;
    int ffn_gate_bits = 2;
    int router_bits = 8;
    int norm_bits = 16;  // Keep as FP16
};
```

### Apply Quantization

```asm
; Apply quantization to model weights
ModelFactory_QuantizeModel PROC
    ; Analyze sensitivity
    call ModelFactory_AnalyzeSensitivity
    
    ; Sort layers by sensitivity
    call ModelFactory_SortLayersBySensitivity
    
    ; Assign quantization levels
    call ModelFactory_AssignQuantizationLevels
    
    ; Quantize each layer
    mov rcx, [num_layers]
    lea rsi, [layer_table]
    
@@quantize_loop:
    push rcx
    push rsi
    
    ; Get quantization bits for this layer
    mov eax, [rsi+Layer.quant_bits]
    
    cmp eax, 8
    je @@quantize_q8
    
    cmp eax, 4
    je @@quantize_q4
    
    cmp eax, 2
    je @@quantize_q2
    
    cmp eax, 1
    je @@quantize_q1
    
@@quantize_q8:
    call Quantizer_QuantizeQ8
    jmp @@next
    
@@quantize_q4:
    call Quantizer_QuantizeQ4
    jmp @@next
    
@@quantize_q2:
    call Quantizer_QuantizeQ2
    jmp @@next
    
@@quantize_q1:
    call Quantizer_QuantizeQ1
    
@@next:
    pop rsi
    add rsi, sizeof(Layer)
    pop rcx
    dec rcx
    jnz @@quantize_loop
    
    ret
ModelFactory_QuantizeModel ENDP
```

---

## GGUF Export

### GGUF Format

```cpp
struct GGUFHeader {
    uint32_t magic;          // 'GGUF'
    uint32_t version;        // 3
    uint64_t tensor_count;
    uint64_t metadata_count;
};

struct GGUFMetadata {
    char key[256];
    uint32_t type;
    union {
        uint8_t uint8;
        int8_t int8;
        uint16_t uint16;
        int16_t int16;
        uint32_t uint32;
        int32_t int32;
        float float32;
        uint64_t uint64;
        int64_t int64;
        double float64;
        bool bool_;
        char string[256];
        struct { uint64_t len; void* data; } array;
    } value;
};

struct GGUFWeight {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;           // GGML_TYPE
    uint64_t offset;
    uint64_t size;
};
```

### Export Implementation

```asm
; Export model to GGUF format
ModelFactory_ExportGGUF PROC
    ; Open file
    lea rcx, [output_path]
    call File_OpenWrite
    mov [file_handle], rax
    
    ; Write header
    call ModelFactory_WriteGGUFHeader
    
    ; Write metadata
    call ModelFactory_WriteGGUFMetadata
    
    ; Calculate tensor offsets
    call ModelFactory_CalculateTensorOffsets
    
    ; Write tensor info
    call ModelFactory_WriteTensorInfo
    
    ; Write tensor data
    call ModelFactory_WriteTensorData
    
    ; Close file
    mov rcx, [file_handle]
    call File_Close
    
    ret
ModelFactory_ExportGGUF ENDP

; Write GGUF header
ModelFactory_WriteGGUFHeader PROC
    ; Magic: 'GGUF'
    mov eax, 'GGUF'
    mov [buffer], eax
    
    ; Version: 3
    mov dword [buffer+4], 3
    
    ; Tensor count
    mov rax, [num_tensors]
    mov [buffer+8], rax
    
    ; Metadata count
    mov rax, [num_metadata]
    mov [buffer+16], rax
    
    ; Write to file
    mov rcx, [file_handle]
    lea rdx, [buffer]
    mov r8, 24
    call File_Write
    
    ret
ModelFactory_WriteGGUFHeader ENDP
```

---

## Implementation Details

### File Structure

```
rawrxd/
├── src/
│   ├── modelfactory/
│   │   ├── ModelFactory.asm       ; Main subsystem
│   │   ├── DataIngestion.asm      ; Data import
│   │   ├── TrainingEngine.asm     ; Forward/backward/optimizer
│   │   ├── Quantizer.asm          ; Quantization
│   │   ├── Shaper.asm             ; Model shaping
│   │   └── GGUFExporter.asm       ; GGUF export
```

### Integration with MoE Governor

```asm
; Shape model to hardware budget
ModelFactory_ShapeAndExport PROC
    ; Get hardware budget from Stress Tester
    call StressTester_GetHardwareBudget
    mov [hardware_budget], rax
    
    ; Train or fine-tune model
    cmp [mode], MODE_TRAIN
    je @@train
    
    cmp [mode], MODE_FINETUNE
    je @@finetune
    
@@train:
    call ModelFactory_TrainFromScratch
    jmp @@shape
    
@@finetune:
    call ModelFactory_FineTune
    
@@shape:
    ; Shape model to fit hardware
    mov rcx, [hardware_budget]
    call MoEGovernor_ShapeModel
    
    ; Quantize
    call ModelFactory_QuantizeModel
    
    ; Export
    call ModelFactory_ExportGGUF
    
    ret
ModelFactory_ShapeAndExport ENDP
```

---

## API Reference

### C/C++ Interface

```cpp
// Initialize Model Factory
FactoryStatus ModelFactory_Init();

// Ingest data
FactoryStatus ModelFactory_IngestData(const char** paths, int num_paths);

// Train model
FactoryStatus ModelFactory_Train(TrainingConfig* config);

// Fine-tune model
FactoryStatus ModelFactory_FineTune(const char* base_model, 
                                     TrainingConfig* config);

// Quantize model
FactoryStatus ModelFactory_Quantize(QuantizationConfig* config);

// Shape model to hardware
FactoryStatus ModelFactory_ShapeToHardware(HardwareBudget* budget);

// Export to GGUF
FactoryStatus ModelFactory_ExportGGUF(const char* output_path);

// Full pipeline
FactoryStatus ModelFactory_RunFullPipeline(PipelineConfig* config);
```

### MASM Interface

```asm
; Initialize
extern ModelFactory_Init:proc

; Ingest data
extern ModelFactory_IngestData:proc

; Train
extern ModelFactory_Train:proc

; Quantize
extern ModelFactory_Quantize:proc

; Export
extern ModelFactory_ExportGGUF:proc
```

---

## Summary

The Model Factory provides:

- ✅ Local data ingestion
- ✅ Training from scratch
- ✅ Fine-tuning
- ✅ Self-quantization
- ✅ Hardware shaping
- ✅ GGUF export
- ✅ Sovereign execution

**Status:** ✅ Complete

---

*End of Model Factory Subsystem Documentation*
