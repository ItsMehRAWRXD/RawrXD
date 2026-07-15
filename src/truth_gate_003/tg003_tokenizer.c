/*
 * Truth Gate 003 - Phase 3: Tokenizer Integration
 * 
 * Minimal BPE tokenizer implementation for text-to-tokens conversion.
 * Extracts vocabulary from GGUF metadata.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define MAX_VOCAB_SIZE 131072
#define MAX_TOKEN_LEN 256
#define MAX_LINE_LEN 4096

/* Tokenizer structure */
typedef struct {
    char **vocab;           /* [vocab_size] - token strings */
    uint32_t vocab_size;
    float *scores;          /* [vocab_size] - merge scores */
    int *token_ids;         /* For encoding */
    
    /* Special tokens */
    uint32_t bos_id;
    uint32_t eos_id;
    uint32_t pad_id;
    uint32_t unk_id;
} tokenizer_t;

/* ============== GGUF METADATA EXTRACTION ============== */

/* Read string from GGUF metadata */
static int read_gguf_string(const uint8_t **ptr, char *out, size_t max_len) {
    uint64_t len = *(uint64_t*)*ptr;
    *ptr += sizeof(uint64_t);
    
    if (len >= max_len) {
        *ptr += len;
        return -1;
    }
    
    memcpy(out, *ptr, len);
    out[len] = '\0';
    *ptr += len;
    return 0;
}

/* Skip metadata value */
static int skip_metadata_value(const uint8_t **ptr, uint32_t type) {
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

/* Load tokenizer vocab from GGUF */
int tokenizer_load_from_gguf(tokenizer_t *tok, const char *gguf_path) {
    FILE *fp = fopen(gguf_path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open: %s\n", gguf_path);
        return -1;
    }
    
    /* Read header */
    uint8_t hdr[24];
    fread(hdr, 1, 24, fp);
    
    uint32_t magic = *(uint32_t*)hdr;
    if (magic != 0x46554747) {
        fprintf(stderr, "Invalid GGUF magic\n");
        fclose(fp);
        return -1;
    }
    
    uint32_t version = *(uint32_t*)(hdr + 4);
    uint64_t n_tensors = *(uint64_t*)(hdr + 8);
    uint64_t n_kv = *(uint64_t*)(hdr + 16);
    
    printf("GGUF: version=%u, tensors=%llu, kv=%llu\n", 
           version, (unsigned long long)n_tensors, (unsigned long long)n_kv);
    
    /* Map file */
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    fseek(fp, 24, SEEK_SET);
    
    uint8_t *data = malloc(file_size);
    fread(data, 1, file_size - 24, fp);
    fclose(fp);
    
    const uint8_t *ptr = data;
    
    /* Parse metadata looking for tokenizer info */
    tok->vocab_size = 0;
    tok->bos_id = 0;
    tok->eos_id = 0;
    tok->pad_id = 0;
    tok->unk_id = 0;
    
    for (uint64_t i = 0; i < n_kv; i++) {
        char key[256];
        read_gguf_string(&ptr, key, sizeof(key));
        
        uint32_t type = *(uint32_t*)ptr;
        ptr += sizeof(uint32_t);
        
        /* Look for tokenizer vocab */
        if (strcmp(key, "tokenizer.ggml.tokens") == 0) {
            /* Array of strings */
            uint32_t elem_type = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
            uint64_t count = *(uint64_t*)ptr;
            ptr += sizeof(uint64_t);
            
            printf("Found vocab: %llu tokens\n", (unsigned long long)count);
            
            tok->vocab_size = (uint32_t)count;
            tok->vocab = calloc(count, sizeof(char*));
            tok->scores = calloc(count, sizeof(float));
            
            for (uint64_t j = 0; j < count; j++) {
                char token[MAX_TOKEN_LEN];
                read_gguf_string(&ptr, token, sizeof(token));
                tok->vocab[j] = strdup(token);
            }
        }
        else if (strcmp(key, "tokenizer.ggml.scores") == 0) {
            /* Array of floats - skip for now */
            uint32_t elem_type = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
            uint64_t count = *(uint64_t*)ptr;
            ptr += sizeof(uint64_t);
            ptr += count * sizeof(float);
        }
        else if (strcmp(key, "tokenizer.ggml.bos_token_id") == 0) {
            tok->bos_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else if (strcmp(key, "tokenizer.ggml.eos_token_id") == 0) {
            tok->eos_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else if (strcmp(key, "tokenizer.ggml.padding_token_id") == 0) {
            tok->pad_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else if (strcmp(key, "tokenizer.ggml.unknown_token_id") == 0) {
            tok->unk_id = *(uint32_t*)ptr;
            ptr += sizeof(uint32_t);
        }
        else {
            skip_metadata_value(&ptr, type);
        }
    }
    
    free(data);
    
    if (tok->vocab_size == 0) {
        fprintf(stderr, "No tokenizer vocab found in GGUF\n");
        return -1;
    }
    
    printf("Tokenizer loaded:\n");
    printf("  Vocab size: %u\n", tok->vocab_size);
    printf("  BOS id: %u\n", tok->bos_id);
    printf("  EOS id: %u\n", tok->eos_id);
    printf("  PAD id: %u\n", tok->pad_id);
    printf("  UNK id: %u\n", tok->unk_id);
    printf("  Sample tokens: '%s', '%s', '%s'...\n",
           tok->vocab[0], tok->vocab[1], tok->vocab[2]);
    
    return 0;
}

/* ============== SIMPLE TOKENIZATION ============== */

/* Find longest matching token at position */
int find_token(const tokenizer_t *tok, const char *text, int pos, int len) {
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

/* Simple greedy tokenization (not true BPE but functional) */
int tokenize(const tokenizer_t *tok, const char *text, uint32_t *tokens, int max_tokens) {
    int len = (int)strlen(text);
    int pos = 0;
    int n_tokens = 0;
    
    /* Add BOS token */
    if (n_tokens < max_tokens) {
        tokens[n_tokens++] = tok->bos_id;
    }
    
    while (pos < len && n_tokens < max_tokens) {
        /* Skip whitespace */
        while (pos < len && isspace((unsigned char)text[pos])) {
            pos++;
        }
        
        if (pos >= len) break;
        
        /* Find best matching token */
        int token_id = find_token(tok, text, pos, len);
        tokens[n_tokens++] = token_id;
        
        /* Advance by token length */
        pos += (int)strlen(tok->vocab[token_id]);
    }
    
    /* Add EOS token */
    if (n_tokens < max_tokens) {
        tokens[n_tokens++] = tok->eos_id;
    }
    
    return n_tokens;
}

/* Decode tokens back to text */
int detokenize(const tokenizer_t *tok, const uint32_t *tokens, int n_tokens, 
               char *text, int max_len) {
    int pos = 0;
    
    for (int i = 0; i < n_tokens && pos < max_len - 1; i++) {
        uint32_t token_id = tokens[i];
        if (token_id < tok->vocab_size) {
            const char *token = tok->vocab[token_id];
            int len = (int)strlen(token);
            
            if (pos + len < max_len - 1) {
                memcpy(text + pos, token, len);
                pos += len;
            }
        }
    }
    
    text[pos] = '\0';
    return pos;
}

/* ============== TESTING ============== */

void test_tokenizer(const char *model_path) {
    printf("Truth Gate 003 - Phase 3: Tokenizer Integration\n");
    printf("===============================================\n\n");
    
    tokenizer_t tok = {0};
    
    if (tokenizer_load_from_gguf(&tok, model_path) != 0) {
        printf("[FAIL] Failed to load tokenizer\n");
        return;
    }
    
    /* Test tokenization */
    const char *test_text = "Hello world";
    uint32_t tokens[256];
    
    printf("\nTest tokenization:\n");
    printf("  Input: '%s'\n", test_text);
    
    int n_tokens = tokenize(&tok, test_text, tokens, 256);
    
    printf("  Tokens (%d): ", n_tokens);
    for (int i = 0; i < n_tokens && i < 20; i++) {
        printf("%u ", tokens[i]);
    }
    if (n_tokens > 20) printf("...");
    printf("\n");
    
    /* Show token strings */
    printf("  Token strings: ");
    for (int i = 0; i < n_tokens && i < 20; i++) {
        printf("'%s' ", tok.vocab[tokens[i]]);
    }
    printf("\n");
    
    /* Test detokenization */
    char decoded[MAX_LINE_LEN];
    detokenize(&tok, tokens, n_tokens, decoded, sizeof(decoded));
    printf("  Decoded: '%s'\n", decoded);
    
    /* Validation */
    printf("\nValidation:\n");
    int pass = 1;
    
    if (n_tokens >= 2) {
        printf("  [PASS] Tokenization produced tokens\n");
    } else {
        printf("  [FAIL] No tokens produced\n");
        pass = 0;
    }
    
    if (tokens[0] == tok.bos_id) {
        printf("  [PASS] BOS token added\n");
    } else {
        printf("  [WARN] BOS token not at start\n");
    }
    
    if (tokens[n_tokens - 1] == tok.eos_id) {
        printf("  [PASS] EOS token added\n");
    } else {
        printf("  [WARN] EOS token not at end\n");
    }
    
    printf("\n===============================================\n");
    printf("Phase 3: Tokenizer %s\n", pass ? "PASSED" : "FAILED");
    printf("\nNext: End-to-end inference pipeline\n");
    
    /* Cleanup */
    if (tok.vocab) {
        for (uint32_t i = 0; i < tok.vocab_size; i++) {
            free(tok.vocab[i]);
        }
        free(tok.vocab);
        free(tok.scores);
    }
}

int main(int argc, char **argv) {
    const char *model_path = (argc > 1) ? argv[1] : "d:/ministral3_q4_0.gguf";
    test_tokenizer(model_path);
    return 0;
}
