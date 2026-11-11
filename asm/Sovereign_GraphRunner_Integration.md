# Sovereign GraphRunner Integration Plan

## Transformer Layer Call Graph

```
Sovereign_GraphRunner::ExecuteLayer(layer_idx)
    │
    ├─> Input: hidden_states [seq_len, hidden_dim]
    │
    ├─> RMSNorm (Pre-Norm)
    │   └─> Sovereign_RMSNorm_F32_AVX2(
    │           input=hidden_states,
    │           weight=layer_norm_weights[layer_idx],
    │           output=normed_states
    │       )
    │
    ├─> Self-Attention
    │   ├─> QKV Projection
    │   │   └─> Sovereign_Attention_Projections (existing)
    │   │           input=normed_states
    │   │           output=q, k, v tensors
    │   │
    │   ├─> RoPE (Position Encoding)
    │   │   └─> Sovereign_RoPE_Apply_F32_AVX2(
    │   │           q_tensor=q,
    │   │           k_tensor=k,
    │   │           freq_cache=precomputed_rope_cache,
    │   │           seq_len=current_seq_len
    │   │       )
    │   │
    │   ├─> Attention Scoring
    │   │   └─> Sovereign_Attention_Scoring (existing)
    │   │           q, k, v -> attention_scores
    │   │
    │   └─> Attention Output
    │       └─> Sovereign_Attention_Output (existing)
    │               attention_scores, v -> attn_output
    │
    ├─> Residual Add (Skip Connection 1)
    │   └─> Sovereign_ResidualAdd_F32_AVX2(
    │           input=hidden_states,
    │           residual=attn_output,
    │           output=residual_1_out
    │       )
    │
    ├─> RMSNorm (Pre-FFN)
    │   └─> Sovereign_RMSNorm_F32_AVX2(
    │           input=residual_1_out,
    │           weight=ffn_norm_weights[layer_idx]
    │       )
    │
    ├─> FFN (Feed-Forward Network)
    │   └─> Sovereign_FFN (existing)
    │           Gate/Up/Down projections
    │
    └─> Residual Add (Skip Connection 2)
        └─> Sovereign_ResidualAdd_F32_AVX2(
                input=residual_1_out,
                residual=ffn_output,
                output=layer_output
            )
```

## Integration Steps

### Step 1: Create Kernel Dispatch Table
```cpp
// Sovereign_KernelDispatch.h
struct TransformerKernels {
    // Normalization
    int (*rms_norm)(float* input, float* output, float* weight, 
                    size_t n, float epsilon);
    int (*layer_norm)(float* input, float* output, float* gamma, 
                      float* beta, size_t n, float epsilon);
    
    // Position Embeddings
    int (*rope_apply)(float* tensor, float* freq_cache,
                      size_t seq_len, size_t head_dim, size_t num_heads);
    
    // Residual Connections
    int (*residual_add)(float* input, float* residual, float* output,
                        size_t n);
    int (*residual_add_inplace)(float* buffer, float* residual, size_t n);
    
    // Attention (existing)
    int (*attention_projections)(...);
    int (*attention_scoring)(...);
    int (*attention_output)(...);
    
    // FFN (existing)
    int (*ffn_forward)(...);
};
```

### Step 2: Wire into GraphRunner
```cpp
// Sovereign_GraphRunner.cpp
class TransformerLayer {
public:
    void Forward(float* hidden_states, size_t seq_len) {
        // Pre-norm
        kernels_->rms_norm(hidden_states, normed_buffer_, 
                          rms_norm_weights_, hidden_dim_, 1e-6f);
        
        // Attention with RoPE
        kernels_->attention_projections(normed_buffer_, q_, k_, v_);
        kernels_->rope_apply(q_, k_, rope_cache_, seq_len, head_dim_, num_heads_);
        kernels_->attention_scoring(q_, k_, attention_scores_);
        kernels_->attention_output(attention_scores_, v_, attn_output_);
        
        // Residual 1
        kernels_->residual_add_inplace(hidden_states, attn_output_, hidden_dim_);
        
        // FFN
        kernels_->rms_norm(hidden_states, normed_buffer_,
                          ffn_norm_weights_, hidden_dim_, 1e-6f);
        kernels_->ffn_forward(normed_buffer_, ffn_output_);
        
        // Residual 2
        kernels_->residual_add_inplace(hidden_states, ffn_output_, hidden_dim_);
    }
};
```

### Step 3: Build & Test
```batch
; Link all kernels into test executable
cl.exe test_transformer_layer.cpp ^
    Sovereign_RMSNorm.lib ^
    Sovereign_RoPE.lib ^
    Sovereign_ResidualAdd.lib ^
    Sovereign_Attention_*.obj ^
    Sovereign_FFN.obj ^
    /Fe:test_transformer.exe

; Run validation
.\test_transformer.exe --validate
```

## Expected Output
```
[TEST] Transformer Layer Forward Pass
  Input: [1, 4096] tensor
  RMSNorm: PASS (mean=0.0, var=1.0)
  RoPE: PASS (position encoding applied)
  Attention: PASS
  Residual Add: PASS (values match expected)
  FFN: PASS
  Output: [1, 4096] tensor
  
[RESULT] All tests PASSED
```
