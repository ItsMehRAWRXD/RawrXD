// tokenizer_bridge.cpp - Tokenizer Bridge Implementation
// Phase 8.1 - Gate G2: Tokenizer encode/decode round trip
// NO DEPENDENCIES - Pure Win32 API

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include "sovereign_runtime.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// TOKENIZER TYPES
// ============================================================================

#define MAX_TOKEN_LEN 256
#define MAX_VOCAB_SIZE 32000

// ============================================================================
// BYTE PAIR ENCODING (BPE) TOKENIZER
// ============================================================================

typedef struct {
    char* token;
    float score;
    int id;
} BPEToken;

typedef struct {
    BPEToken* tokens;
    int vocab_size;
    int max_token_len;
    
    // Special tokens
    int bos_id;
    int eos_id;
    int pad_id;
    int unk_id;
    
    // Byte fallback
    int byte_fallback;
} BPETokenizer;

// ============================================================================
// SENTENCEPIECE TOKENIZER (Simplified)
// ============================================================================

typedef struct {
    char** pieces;
    int* piece_ids;
    float* scores;
    int vocab_size;
    
    // Special tokens
    int bos_id;
    int eos_id;
    int pad_id;
    int unk_id;
} SPMTokenizer;

// ============================================================================
// TOKENIZER LOADING FROM GGUF
// ============================================================================

static int load_spm_tokenizer(ModelContext* ctx, const uint8_t* data, size_t size) {
    // Parse tokenizer.model data (protobuf format - simplified)
    // In production, this would use proper protobuf parsing
    
    TokenizerBridge* tok = &ctx->tokenizer;
    
    // Allocate vocabulary
    tok->vocab = (char**)malloc(MAX_VOCAB_SIZE * sizeof(char*));
    tok->vocab_scores = (float*)malloc(MAX_VOCAB_SIZE * sizeof(float));
    
    if (!tok->vocab || !tok->vocab_scores) {
        return -1;
    }
    
    // Parse pieces from data
    // This is a simplified parser - real implementation would parse protobuf
    const uint8_t* p = data;
    const uint8_t* end = data + size;
    
    int vocab_idx = 0;
    while (p < end && vocab_idx < MAX_VOCAB_SIZE) {
        // Look for piece entry
        // Format: piece: "token" score: float
        
        // Skip whitespace
        while (p < end && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) p++;
        if (p >= end) break;
        
        // Read token (simplified - assumes space-delimited)
        char token[MAX_TOKEN_LEN];
        int token_len = 0;
        while (p < end && *p != ' ' && *p != '\n' && token_len < MAX_TOKEN_LEN - 1) {
            token[token_len++] = *p++;
        }
        token[token_len] = '\0';
        
        // Store token
        tok->vocab[vocab_idx] = (char*)malloc(token_len + 1);
        if (tok->vocab[vocab_idx]) {
            strcpy(tok->vocab[vocab_idx], token);
            tok->vocab_scores[vocab_idx] = 0.0f; // Would parse actual score
            vocab_idx++;
        }
        
        // Skip to next line
        while (p < end && *p != '\n') p++;
        if (p < end) p++;
    }
    
    tok->vocab_size = vocab_idx;
    tok->tokenizer_type = 0; // SPM
    
    // Set special tokens (defaults)
    tok->bos_token = 1;
    tok->eos_token = 2;
    tok->pad_token = 0;
    tok->unk_token = 0;
    
    return 0;
}

static int load_bpe_tokenizer(ModelContext* ctx, const uint8_t* data, size_t size) {
    // BPE tokenizer loading (vocab.json format)
    TokenizerBridge* tok = &ctx->tokenizer;
    
    tok->vocab = (char**)malloc(MAX_VOCAB_SIZE * sizeof(char*));
    tok->vocab_scores = (float*)malloc(MAX_VOCAB_SIZE * sizeof(float));
    
    if (!tok->vocab || !tok->vocab_scores) {
        return -1;
    }
    
    // Parse JSON (simplified)
    // Real implementation would use proper JSON parser
    
    int vocab_idx = 0;
    tok->vocab_size = vocab_idx;
    tok->tokenizer_type = 1; // BPE
    
    return 0;
}

// ============================================================================
// G2: TOKENIZER INITIALIZATION
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_InitTokenizer(
    ModelContext* ctx,
    const char* vocab_data,
    size_t vocab_size
) {
    if (!ctx || !vocab_data) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    TokenizerBridge* tok = &ctx->tokenizer;
    memset(tok, 0, sizeof(TokenizerBridge));
    
    // Detect tokenizer type from data
    // Check for SPM format (contains "<s>", "</s>", "<unk>")
    if (strstr(vocab_data, "<s>") != NULL) {
        if (load_spm_tokenizer(ctx, (const uint8_t*)vocab_data, vocab_size) != 0) {
            return SOVEREIGN_RUNTIME_ERROR_TOKENIZER;
        }
    } else {
        // Assume BPE
        if (load_bpe_tokenizer(ctx, (const uint8_t*)vocab_data, vocab_size) != 0) {
            return SOVEREIGN_RUNTIME_ERROR_TOKENIZER;
        }
    }
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// G2: ENCODE (Text → Tokens)
// ============================================================================

SOVEREIGN_RUNTIME_API int Sovereign_Runtime_Encode(
    ModelContext* ctx,
    const char* text,
    int* tokens,
    int max_tokens
) {
    if (!ctx || !text || !tokens || max_tokens <= 0) {
        return -1;
    }
    
    TokenizerBridge* tok = &ctx->tokenizer;
    if (!tok->vocab || tok->vocab_size <= 0) {
        return -1;
    }
    
    int n_tokens = 0;
    
    // Add BOS token
    tokens[n_tokens++] = tok->bos_token;
    if (n_tokens >= max_tokens) return n_tokens;
    
    // Simple word-based tokenization (simplified)
    // Real implementation would use proper BPE/SPM algorithm
    
    const char* p = text;
    while (*p && n_tokens < max_tokens) {
        // Skip whitespace
        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
        if (!*p) break;
        
        // Find longest matching token
        int best_len = 0;
        int best_id = tok->unk_token;
        
        for (int i = 0; i < tok->vocab_size; i++) {
            const char* vocab_token = tok->vocab[i];
            int vocab_len = strlen(vocab_token);
            
            if (vocab_len > best_len && strncmp(p, vocab_token, vocab_len) == 0) {
                best_len = vocab_len;
                best_id = i;
            }
        }
        
        tokens[n_tokens++] = best_id;
        p += best_len > 0 ? best_len : 1;
    }
    
    return n_tokens;
}

// ============================================================================
// G2: DECODE (Tokens → Text)
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_Decode(
    ModelContext* ctx,
    const int* tokens,
    int n_tokens,
    char* text,
    int max_text_len
) {
    if (!ctx || !tokens || !text || max_text_len <= 0) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    TokenizerBridge* tok = &ctx->tokenizer;
    if (!tok->vocab || tok->vocab_size <= 0) {
        return SOVEREIGN_RUNTIME_ERROR_TOKENIZER;
    }
    
    int pos = 0;
    text[0] = '\0';
    
    for (int i = 0; i < n_tokens && pos < max_text_len - 1; i++) {
        int token_id = tokens[i];
        
        // Skip special tokens
        if (token_id == tok->bos_token || token_id == tok->eos_token ||
            token_id == tok->pad_token) {
            continue;
        }
        
        if (token_id >= 0 && token_id < tok->vocab_size) {
            const char* token_text = tok->vocab[token_id];
            int token_len = strlen(token_text);
            
            // Check space
            if (pos + token_len >= max_text_len - 1) break;
            
            // Append token
            strcpy(text + pos, token_text);
            pos += token_len;
        }
    }
    
    text[pos] = '\0';
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// G3: EMBEDDING LOOKUP
// ============================================================================

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_GetEmbedding(
    ModelContext* ctx,
    int token_id,
    float* embedding,
    int embedding_dim
) {
    if (!ctx || !embedding) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    if (!ctx->token_embd || !ctx->token_embd->data) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    if (token_id < 0 || token_id >= ctx->vocab_size) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    // Get embedding from token_embd.weight
    const float* emb_data = (const float*)ctx->token_embd->data;
    
    // Copy embedding
    for (int i = 0; i < embedding_dim; i++) {
        embedding[i] = emb_data[token_id * embedding_dim + i];
    }
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

SOVEREIGN_RUNTIME_API SovereignRuntimeStatus Sovereign_Runtime_GetTokenEmbeddings(
    ModelContext* ctx,
    const int* tokens,
    int n_tokens,
    float* embeddings
) {
    if (!ctx || !tokens || !embeddings) {
        return SOVEREIGN_RUNTIME_ERROR_NULL_POINTER;
    }
    
    if (!ctx->token_embd || !ctx->token_embd->data) {
        return SOVEREIGN_RUNTIME_ERROR_INVALID_TENSOR;
    }
    
    int embedding_dim = ctx->hidden_dim;
    const float* emb_data = (const float*)ctx->token_embd->data;
    
    // Get embeddings for all tokens
    for (int t = 0; t < n_tokens; t++) {
        int token_id = tokens[t];
        if (token_id >= 0 && token_id < ctx->vocab_size) {
            for (int i = 0; i < embedding_dim; i++) {
                embeddings[t * embedding_dim + i] = emb_data[token_id * embedding_dim + i];
            }
        }
    }
    
    return SOVEREIGN_RUNTIME_SUCCESS;
}

// ============================================================================
// TOKENIZER CLEANUP
// ============================================================================

SOVEREIGN_RUNTIME_API void Sovereign_Runtime_FreeTokenizer(ModelContext* ctx) {
    if (!ctx) return;
    
    TokenizerBridge* tok = &ctx->tokenizer;
    
    if (tok->vocab) {
        for (int i = 0; i < tok->vocab_size; i++) {
            free(tok->vocab[i]);
        }
        free(tok->vocab);
        tok->vocab = NULL;
    }
    
    if (tok->vocab_scores) {
        free(tok->vocab_scores);
        tok->vocab_scores = NULL;
    }
    
    tok->vocab_size = 0;
}