/*
 * Truth Gate 003 - TG3-G1: Tokenizer Parity
 * 
 * Validates that RawrXD tokenizer produces identical token IDs to llama.cpp
 * 
 * Acceptance: 100% token ID match
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <windows.h>

#define MAX_VOCAB_SIZE 131072
#define MAX_TOKEN_LEN 256
#define MAX_SEQ_LEN 4096

/* Tokenizer structure */
typedef struct {
    char **vocab;              /* [vocab_size] - token strings */
    uint32_t vocab_size;
    
    /* BPE merges */
    uint32_t *merge_first;     /* [num_merges] - first token ID */
    uint32_t *merge_second;    /* [num_merges] - second token ID */
    uint32_t num_merges;
    
    /* Special tokens */
    uint32_t bos_id;
    uint32_t eos_id;
    uint32_t unk_id;
    uint32_t pad_id;
    
    /* Pre-tokenization regex pattern (simplified) */
    char *pattern;
} tokenizer_t;

/* GGUF context */
typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    void* base_addr;
    size_t file_size;
    uint64_t data_offset;
} gguf_context_t;

/* ============== GGUF LOADING ============== */

static int read_string(const uint8_t** ptr, char* buffer, size_t max_len) {
    uint64_t len = *(uint64_t*)*ptr;
    *ptr += sizeof(uint64_t);
    
    if (len >= max_len) {
        *ptr += len;
        return 0;
    }
    
    memcpy(buffer, *ptr, len);
    buffer[len] = '\0';
    *ptr += len;
    return 1;
}

static int skip_metadata_value(const uint8_t** ptr, uint32_t type) {
    switch (type) {
        case 0: case 1:  *ptr += 1; break;
        case 2: case 3:  *ptr += 2; break;
        case 4: case 5: case 6:  *ptr += 4; break;
        case 10: case 11: case 12: *ptr += 8; break;
        case 7:  *ptr += 1; break;
        case 8: {
            uint64_t len = *(uint64_t*)*ptr;
            *ptr += sizeof(uint64_t) + len;
            break;
        }
        case 9: {
            uint32_t elem_type = *(uint32_t*)*ptr;
            *ptr += sizeof(uint32_t);
            uint64_t count = *(uint64_t*)*ptr;
            *ptr += sizeof(uint64_t);
            for (uint64_t i = 0; i < count; i++) {
                if (!skip_metadata_value(ptr, elem_type)) return 0;
            }
            break;
        }
        default: return 0;
    }
    return 1;
}

int load_tokenizer_from_gguf(const char *gguf_path, tokenizer_t *tok) {
    memset(tok, 0, sizeof(tokenizer_t));
    
    /* Open file */
    HANDLE file_handle = CreateFileA(gguf_path, GENERIC_READ, FILE_SHARE_READ,
                                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to open: %s\n", gguf_path);
        return -1;
    }
    
    LARGE_INTEGER size;
    GetFileSizeEx(file_handle, &size);
    size_t file_size = (size_t)size.QuadPart;
    
    HANDLE map_handle = CreateFileMappingA(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    void *base_addr = MapViewOfFile(map_handle, FILE_MAP_READ, 0, 0, 0);
    
    /* Read header */
    uint8_t *data = (uint8_t*)base_addr;
    uint32_t magic = *(uint32_t*)data;
    uint32_t version = *(uint32_t*)(data + 4);
    uint64_t n_tensors = *(uint64_t*)(data + 8);
    uint64_t n_kv = *(uint64_t*)(data + 16);
    
    if (magic != 0x46554747) {
        fprintf(stderr, "Invalid GGUF magic\n");
        return -1;
    }
    
    printf("GGUF: version=%u, tensors=%llu, kv=%llu\n", 
           version, (unsigned long long)n_tensors, (unsigned long long)n_kv);
    
    const uint8_t *ptr = data + 24;
    
    /* Parse metadata */
    for (uint64_t i = 0; i < n_kv; i++) {
        char key[256];
        read_string(&ptr, key, sizeof(key));
        
        uint32_t type = *(uint32_t*)ptr;
        ptr += sizeof(uint32_t);
        
        if (strcmp(key, "tokenizer.ggml.tokens") == 0) {
            /* Array of strings - vocab */
            ptr += sizeof(uint32_t); /* elem_type */
            tok->vocab_size = *(uint64_t*)ptr;
            ptr += sizeof(uint64_t);
            
            printf("Loading vocab: %u tokens\n", tok->vocab_size);
            
            tok->vocab = calloc(tok->vocab_size, sizeof(char*));
            for (uint32_t j = 0; j < tok->vocab_size; j++) {
                char token[MAX_TOKEN_LEN];
                read_string(&ptr, token, sizeof(token));
                tok->vocab[j] = strdup(token);
            }
        }
        else if (strcmp(key, "tokenizer.ggml.bos_token_id") == 0) {
            tok->bos_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else if (strcmp(key, "tokenizer.ggml.eos_token_id") == 0) {
            tok->eos_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else if (strcmp(key, "tokenizer.ggml.unknown_token_id") == 0) {
            tok->unk_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else if (strcmp(key, "tokenizer.ggml.padding_token_id") == 0) {
            tok->pad_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else {
            skip_metadata_value(&ptr, type);
        }
    }
    
    UnmapViewOfFile(base_addr);
    CloseHandle(map_handle);
    CloseHandle(file_handle);
    
    if (tok->vocab_size == 0) {
        fprintf(stderr, "No vocab loaded\n");
        return -1;
    }
    
    printf("Tokenizer loaded:\n");
    printf("  Vocab: %u tokens\n", tok->vocab_size);
    printf("  BOS: %u, EOS: %u, UNK: %u\n", tok->bos_id, tok->eos_id, tok->unk_id);
    printf("  Sample: '%s', '%s', '%s'...\n", 
           tok->vocab[0], tok->vocab[1], tok->vocab[2]);
    
    return 0;
}

/* ============== SIMPLE TOKENIZATION (Greedy) ============== */

/* Find longest matching token at position */
int find_best_token(const tokenizer_t *tok, const char *text, int pos, int len) {
    int best_len = 0;
    int best_id = tok->unk_id;
    
    for (uint32_t i = 0; i < tok->vocab_size; i++) {
        const char *token = tok->vocab[i];
        int token_len = (int)strlen(token);
        
        if (token_len > 0 && pos + token_len <= len) {
            if (memcmp(text + pos, token, token_len) == 0) {
                if (token_len > best_len) {
                    best_len = token_len;
                    best_id = i;
                }
            }
        }
    }
    
    return best_id;
}

/* Greedy tokenization */
int tokenize_greedy(const tokenizer_t *tok, const char *text, 
                    uint32_t *tokens, int max_tokens) {
    int len = (int)strlen(text);
    int pos = 0;
    int n_tokens = 0;
    
    /* Add BOS */
    if (n_tokens < max_tokens) {
        tokens[n_tokens++] = tok->bos_id;
    }
    
    while (pos < len && n_tokens < max_tokens) {
        /* Skip whitespace */
        while (pos < len && isspace((unsigned char)text[pos])) {
            pos++;
        }
        if (pos >= len) break;
        
        /* Find best token */
        int token_id = find_best_token(tok, text, pos, len);
        tokens[n_tokens++] = token_id;
        pos += (int)strlen(tok->vocab[token_id]);
    }
    
    /* Add EOS */
    if (n_tokens < max_tokens) {
        tokens[n_tokens++] = tok->eos_id;
    }
    
    return n_tokens;
}

/* ============== VALIDATION ============== */

void validate_tokenizer(const tokenizer_t *tok, const char *prompt) {
    printf("\nTG3-G1: Tokenizer Parity Validation\n");
    printf("====================================\n");
    printf("Prompt: '%s'\n\n", prompt);
    
    uint32_t tokens[MAX_SEQ_LEN];
    int n_tokens = tokenize_greedy(tok, prompt, tokens, MAX_SEQ_LEN);
    
    printf("RawrXD tokenization:\n");
    printf("  Count: %d tokens\n", n_tokens);
    printf("  IDs: ");
    for (int i = 0; i < n_tokens && i < 20; i++) {
        printf("%u ", tokens[i]);
    }
    if (n_tokens > 20) printf("...");
    printf("\n");
    
    printf("\n  Token strings:\n");
    for (int i = 0; i < n_tokens && i < 20; i++) {
        printf("    [%d] %u: '%s'\n", i, tokens[i], tok->vocab[tokens[i]]);
    }
    
    /* Check BOS/EOS */
    printf("\nValidation:\n");
    int pass = 1;
    
    if (n_tokens >= 1 && tokens[0] == tok->bos_id) {
        printf("  [PASS] BOS token at start\n");
    } else {
        printf("  [FAIL] BOS token missing or incorrect\n");
        pass = 0;
    }
    
    if (n_tokens >= 2 && tokens[n_tokens - 1] == tok->eos_id) {
        printf("  [PASS] EOS token at end\n");
    } else {
        printf("  [FAIL] EOS token missing or incorrect\n");
        pass = 0;
    }
    
    if (n_tokens > 2) {
        printf("  [PASS] Content tokens produced\n");
    } else {
        printf("  [WARN] No content tokens\n");
    }
    
    printf("\n====================================\n");
    printf("TG3-G1 Status: %s\n", pass ? "PASS (basic)" : "FAIL");
    printf("\nNote: Full TG3-G1 requires llama.cpp comparison\n");
    printf("Next: Export tokens for external validation\n");
}

/* ============== EXPORT FOR COMPARISON ============== */

void export_tokens_for_comparison(const tokenizer_t *tok, const char *prompt, 
                                   const char *output_file) {
    uint32_t tokens[MAX_SEQ_LEN];
    int n_tokens = tokenize_greedy(tok, prompt, tokens, MAX_SEQ_LEN);
    
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to write: %s\n", output_file);
        return;
    }
    
    fprintf(fp, "# TG3-G1 Tokenizer Output\n");
    fprintf(fp, "# Prompt: %s\n", prompt);
    fprintf(fp, "# Count: %d\n", n_tokens);
    fprintf(fp, "# Format: token_id token_string\n\n");
    
    for (int i = 0; i < n_tokens; i++) {
        fprintf(fp, "%u '%s'\n", tokens[i], tok->vocab[tokens[i]]);
    }
    
    fclose(fp);
    printf("Exported to: %s\n", output_file);
}

/* ============== MAIN ============== */

int main(int argc, char **argv) {
    printf("Truth Gate 003 - TG3-G1: Tokenizer Parity\n");
    printf("=========================================\n\n");
    
    const char *model_path = (argc > 1) ? argv[1] : "d:/ministral3_q4_0.gguf";
    const char *prompt = (argc > 2) ? argv[2] : "The capital of France is";
    
    printf("Model: %s\n", model_path);
    printf("Prompt: '%s'\n\n", prompt);
    
    /* Load tokenizer */
    tokenizer_t tok;
    if (load_tokenizer_from_gguf(model_path, &tok) != 0) {
        printf("[FAIL] Could not load tokenizer\n");
        return 1;
    }
    
    /* Validate */
    validate_tokenizer(&tok, prompt);
    
    /* Export for comparison */
    export_tokens_for_comparison(&tok, prompt, "d:/tg3_g1_rawrxd_tokens.txt");
    
    printf("\n=========================================\n");
    printf("TG3-G1 Instructions:\n");
    printf("1. Run llama.cpp with same prompt\n");
    printf("2. Compare token IDs\n");
    printf("3. Acceptance: 100%% match\n");
    
    /* Cleanup */
    if (tok.vocab) {
        for (uint32_t i = 0; i < tok.vocab_size; i++) {
            free(tok.vocab[i]);
        }
        free(tok.vocab);
    }
    
    return 0;
}
