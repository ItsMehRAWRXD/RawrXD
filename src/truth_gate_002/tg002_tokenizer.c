/* tg002_tokenizer.c - Phase 4: Token Generation
 * BPE Tokenizer and sampling strategies
 * Compile: gcc -O2 -Wall tg002_tokenizer.c -o tg002_tokenizer.exe -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_TOKEN_LEN 256
#define VOCAB_SIZE 51200  /* Phi-2 vocab size */

/* ============================================================================
 * Simple BPE Tokenizer
 * This is a simplified implementation for demonstration
 * Full BPE requires loading merge rules from the model
 * ============================================================================ */

typedef struct {
    char* vocab[VOCAB_SIZE];
    int vocab_len;
    /* For full BPE, we'd need merge rules here */
} tokenizer_t;

/* Initialize tokenizer with basic vocabulary */
void tokenizer_init(tokenizer_t* tok) {
    tok->vocab_len = 0;
    
    /* Add basic characters */
    for (int i = 0; i < 256; i++) {
        if (isprint(i) || isspace(i)) {
            char str[2] = {(char)i, '\0'};
            tok->vocab[tok->vocab_len] = strdup(str);
            tok->vocab_len++;
        }
    }
    
    /* Add common tokens */
    const char* common[] = {
        "<|endoftext|>", "<s>", "</s>", "<unk>",
        " the", " The", " a", " A", " is", " are",
        " and", " or", " of", " to", " in", " for",
        "ing", "ed", "er", "ly", "tion", "ment",
        NULL
    };
    
    for (int i = 0; common[i]; i++) {
        if (tok->vocab_len < VOCAB_SIZE) {
            tok->vocab[tok->vocab_len] = strdup(common[i]);
            tok->vocab_len++;
        }
    }
    
    printf("Tokenizer initialized with %d tokens\n", tok->vocab_len);
}

void tokenizer_free(tokenizer_t* tok) {
    for (int i = 0; i < tok->vocab_len; i++) {
        free(tok->vocab[i]);
    }
}

/* Simple greedy tokenization (not true BPE) */
int tokenize(tokenizer_t* tok, const char* text, int* tokens, int max_tokens) {
    int token_count = 0;
    const char* ptr = text;
    
    while (*ptr && token_count < max_tokens) {
        /* Try to find longest matching token */
        int best_len = 0;
        int best_id = 0;  /* <unk> */
        
        for (int i = 0; i < tok->vocab_len; i++) {
            int len = strlen(tok->vocab[i]);
            if (len > best_len && strncmp(ptr, tok->vocab[i], len) == 0) {
                best_len = len;
                best_id = i;
            }
        }
        
        tokens[token_count++] = best_id;
        ptr += best_len > 0 ? best_len : 1;
    }
    
    return token_count;
}

/* Decode tokens back to string */
void decode(tokenizer_t* tok, const int* tokens, int n_tokens, char* output, int max_len) {
    output[0] = '\0';
    int pos = 0;
    
    for (int i = 0; i < n_tokens && pos < max_len - 1; i++) {
        if (tokens[i] >= 0 && tokens[i] < tok->vocab_len) {
            const char* token = tok->vocab[tokens[i]];
            int len = strlen(token);
            if (pos + len < max_len - 1) {
                strcpy(output + pos, token);
                pos += len;
            }
        }
    }
    output[pos] = '\0';
}

/* ============================================================================
 * Sampling Strategies
 * ============================================================================ */

/* Greedy sampling - select highest probability token */
int sample_greedy(const float* logits, int n_vocab) {
    int best_idx = 0;
    float best_val = logits[0];
    
    for (int i = 1; i < n_vocab; i++) {
        if (logits[i] > best_val) {
            best_val = logits[i];
            best_idx = i;
        }
    }
    
    return best_idx;
}

/* Temperature sampling */
int sample_temperature(const float* logits, int n_vocab, float temperature) {
    float probs[VOCAB_SIZE];
    float sum = 0.0f;
    
    /* Apply temperature and compute softmax */
    for (int i = 0; i < n_vocab; i++) {
        probs[i] = expf(logits[i] / temperature);
        sum += probs[i];
    }
    
    /* Normalize */
    for (int i = 0; i < n_vocab; i++) {
        probs[i] /= sum;
    }
    
    /* Sample from distribution */
    float r = (float)rand() / RAND_MAX;
    float cumsum = 0.0f;
    
    for (int i = 0; i < n_vocab; i++) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return i;
        }
    }
    
    return n_vocab - 1;
}

/* Top-k sampling */
int sample_top_k(const float* logits, int n_vocab, int k, float temperature) {
    /* Find top k indices */
    typedef struct { int idx; float val; } pair_t;
    pair_t top_k[100];  /* Assume k <= 100 */
    
    /* Initialize with first k */
    for (int i = 0; i < k; i++) {
        top_k[i].idx = i;
        top_k[i].val = logits[i];
    }
    
    /* Find actual top k */
    for (int i = k; i < n_vocab; i++) {
        /* Find minimum in top_k */
        int min_idx = 0;
        for (int j = 1; j < k; j++) {
            if (top_k[j].val < top_k[min_idx].val) {
                min_idx = j;
            }
        }
        /* Replace if current is larger */
        if (logits[i] > top_k[min_idx].val) {
            top_k[min_idx].idx = i;
            top_k[min_idx].val = logits[i];
        }
    }
    
    /* Apply temperature to top k */
    float probs[100];
    float sum = 0.0f;
    for (int i = 0; i < k; i++) {
        probs[i] = expf(top_k[i].val / temperature);
        sum += probs[i];
    }
    
    /* Normalize */
    for (int i = 0; i < k; i++) {
        probs[i] /= sum;
    }
    
    /* Sample */
    float r = (float)rand() / RAND_MAX;
    float cumsum = 0.0f;
    
    for (int i = 0; i < k; i++) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return top_k[i].idx;
        }
    }
    
    return top_k[k-1].idx;
}

/* Top-p (nucleus) sampling */
int sample_top_p(const float* logits, int n_vocab, float p, float temperature) {
    /* Sort logits by value (descending) - simple bubble sort for small n_vocab */
    typedef struct { int idx; float val; } pair_t;
    pair_t sorted[VOCAB_SIZE];
    
    for (int i = 0; i < n_vocab; i++) {
        sorted[i].idx = i;
        sorted[i].val = logits[i];
    }
    
    /* Bubble sort */
    for (int i = 0; i < n_vocab - 1; i++) {
        for (int j = 0; j < n_vocab - i - 1; j++) {
            if (sorted[j].val < sorted[j+1].val) {
                pair_t tmp = sorted[j];
                sorted[j] = sorted[j+1];
                sorted[j+1] = tmp;
            }
        }
    }
    
    /* Compute softmax probabilities */
    float probs[VOCAB_SIZE];
    float sum = 0.0f;
    for (int i = 0; i < n_vocab; i++) {
        probs[i] = expf(sorted[i].val / temperature);
        sum += probs[i];
    }
    for (int i = 0; i < n_vocab; i++) {
        probs[i] /= sum;
    }
    
    /* Find nucleus */
    float cumsum = 0.0f;
    int nucleus_size = 0;
    for (int i = 0; i < n_vocab; i++) {
        cumsum += probs[i];
        nucleus_size++;
        if (cumsum >= p) break;
    }
    
    /* Renormalize nucleus */
    float nucleus_sum = 0.0f;
    for (int i = 0; i < nucleus_size; i++) {
        nucleus_sum += probs[i];
    }
    for (int i = 0; i < nucleus_size; i++) {
        probs[i] /= nucleus_sum;
    }
    
    /* Sample from nucleus */
    float r = (float)rand() / RAND_MAX;
    cumsum = 0.0f;
    
    for (int i = 0; i < nucleus_size; i++) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return sorted[i].idx;
        }
    }
    
    return sorted[nucleus_size - 1].idx;
}

/* ============================================================================
 * KV Cache
 * ============================================================================ */

typedef struct {
    float* k_cache;  /* [max_seq_len x head_dim] */
    float* v_cache;  /* [max_seq_len x head_dim] */
    int seq_len;
    int head_dim;
    int max_seq_len;
} kv_cache_t;

void kv_cache_init(kv_cache_t* cache, int max_seq_len, int head_dim) {
    cache->k_cache = (float*)calloc(max_seq_len * head_dim, sizeof(float));
    cache->v_cache = (float*)calloc(max_seq_len * head_dim, sizeof(float));
    cache->seq_len = 0;
    cache->head_dim = head_dim;
    cache->max_seq_len = max_seq_len;
}

void kv_cache_free(kv_cache_t* cache) {
    free(cache->k_cache);
    free(cache->v_cache);
}

void kv_cache_append(kv_cache_t* cache, const float* k, const float* v) {
    if (cache->seq_len < cache->max_seq_len) {
        memcpy(cache->k_cache + cache->seq_len * cache->head_dim, 
               k, cache->head_dim * sizeof(float));
        memcpy(cache->v_cache + cache->seq_len * cache->head_dim,
               v, cache->head_dim * sizeof(float));
        cache->seq_len++;
    }
}

/* ============================================================================
 * Tests
 * ============================================================================ */

void test_tokenizer() {
    printf("Testing Tokenizer...\n");
    
    tokenizer_t tok;
    tokenizer_init(&tok);
    
    const char* text = "Hello world";
    int tokens[100];
    int n_tokens = tokenize(&tok, text, tokens, 100);
    
    printf("  Input: \"%s\"\n", text);
    printf("  Tokens: ");
    for (int i = 0; i < n_tokens; i++) {
        printf("%d ", tokens[i]);
    }
    printf("\n");
    
    char decoded[256];
    decode(&tok, tokens, n_tokens, decoded, sizeof(decoded));
    printf("  Decoded: \"%s\"\n\n", decoded);
    
    tokenizer_free(&tok);
}

void test_sampling() {
    printf("Testing Sampling Strategies...\n");
    
    /* Create dummy logits */
    float logits[VOCAB_SIZE];
    for (int i = 0; i < VOCAB_SIZE; i++) {
        logits[i] = (float)(rand() % 100) / 10.0f;
    }
    /* Make token 42 the highest */
    logits[42] = 100.0f;
    
    int greedy = sample_greedy(logits, VOCAB_SIZE);
    printf("  Greedy: %d (expected 42)\n", greedy);
    
    int temp = sample_temperature(logits, VOCAB_SIZE, 0.8f);
    printf("  Temperature (T=0.8): %d\n", temp);
    
    int top_k = sample_top_k(logits, VOCAB_SIZE, 10, 1.0f);
    printf("  Top-k (k=10): %d\n", top_k);
    
    int top_p = sample_top_p(logits, VOCAB_SIZE, 0.9f, 1.0f);
    printf("  Top-p (p=0.9): %d\n\n", top_p);
}

void test_kv_cache() {
    printf("Testing KV Cache...\n");
    
    kv_cache_t cache;
    kv_cache_init(&cache, 512, 64);  /* max_seq_len=512, head_dim=64 */
    
    float k[64], v[64];
    for (int i = 0; i < 64; i++) {
        k[i] = (float)i;
        v[i] = (float)(i + 100);
    }
    
    kv_cache_append(&cache, k, v);
    kv_cache_append(&cache, k, v);
    kv_cache_append(&cache, k, v);
    
    printf("  Sequence length: %d (expected 3)\n", cache.seq_len);
    printf("  K[0][0]: %.0f (expected 0)\n", cache.k_cache[0]);
    printf("  V[2][10]: %.0f (expected 110)\n\n", cache.v_cache[2 * 64 + 10]);
    
    kv_cache_free(&cache);
}

/* ============================================================================
 * Main
 * ============================================================================ */
int main() {
    printf("========================================\n");
    printf("Truth Gate 002 - Phase 4: Token Generation\n");
    printf("========================================\n\n");
    
    srand(42);  /* For reproducible tests */
    
    test_tokenizer();
    test_sampling();
    test_kv_cache();
    
    printf("========================================\n");
    printf("All tests completed!\n");
    printf("========================================\n");
    
    return 0;
}
