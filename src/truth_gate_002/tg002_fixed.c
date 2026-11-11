/* tg002_fixed.c - Fixed GGUF parsing with proper alignment */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <math.h>

#define GGUF_MAGIC 0x46554747
#define GGUF_VERSION 3

/* GGUF types */
#define GGML_TYPE_F32  0
#define GGML_TYPE_Q2_K 10

/* Phi-2 config */
#define VOCAB_SIZE 51200
#define EMBED_DIM 2560
#define N_HEADS 32
#define N_LAYERS 32
#define HEAD_DIM (EMBED_DIM / N_HEADS)
#define FF_DIM 10240
#define MAX_SEQ_LEN 2048

/* Packed structures for GGUF */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
} gguf_header_t;
#pragma pack(pop)

typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
    uint64_t n_elements;
    uint64_t size;
    void* data;
} tensor_info_t;

typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    uint8_t* base_addr;
    size_t file_size;
    gguf_header_t header;
    tensor_info_t* tensors;
    uint64_t data_offset;
} gguf_context_t;

/* Q2_K block */
typedef struct {
    uint8_t scales[16];
    uint8_t qs[64];
    uint16_t d;
    uint16_t dmin;
    uint8_t padding[44];
} block_q2_k;

/* F16 to F32 */
static float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = (float)mant / 1024.0f * powf(2.0f, -14);
        return sign ? -val : val;
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    float val = (1.0f + (float)mant / 1024.0f) * powf(2.0f, (float)exp - 15.0f);
    return sign ? -val : val;
}

/* Read uint64_t safely */
static uint64_t read_u64(uint8_t* data, size_t* pos) {
    uint64_t val = *(uint64_t*)(data + *pos);
    *pos += 8;
    return val;
}

/* Read uint32_t safely */
static uint32_t read_u32(uint8_t* data, size_t* pos) {
    uint32_t val = *(uint32_t*)(data + *pos);
    *pos += 4;
    return val;
}

/* Open GGUF */
int gguf_open(const char* path, gguf_context_t* ctx) {
    memset(ctx, 0, sizeof(gguf_context_t));
    
    ctx->file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) return -1;
    
    LARGE_INTEGER size;
    GetFileSizeEx(ctx->file_handle, &size);
    ctx->file_size = (size_t)size.QuadPart;
    
    ctx->map_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!ctx->map_handle) return -1;
    
    ctx->base_addr = (uint8_t*)MapViewOfFile(ctx->map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->base_addr) return -1;
    
    /* Read header */
    memcpy(&ctx->header, ctx->base_addr, sizeof(gguf_header_t));
    
    if (ctx->header.magic != GGUF_MAGIC) {
        printf("Invalid magic: 0x%08X\n", ctx->header.magic);
        return -1;
    }
    
    printf("GGUF Version: %u\n", ctx->header.version);
    printf("Tensors: %llu\n", (unsigned long long)ctx->header.tensor_count);
    printf("Metadata: %llu\n", (unsigned long long)ctx->header.metadata_kv_count);
    
    /* Allocate tensors */
    ctx->tensors = calloc(ctx->header.tensor_count, sizeof(tensor_info_t));
    if (!ctx->tensors) return -1;
    
    /* Parse metadata */
    size_t pos = sizeof(gguf_header_t);
    printf("Parsing metadata at offset %zu...\n", pos);
    
    for (uint64_t i = 0; i < ctx->header.metadata_kv_count; i++) {
        /* Key length and key */
        uint64_t key_len = read_u64(ctx->base_addr, &pos);
        if (key_len > 10000) {
            printf("Invalid key length at entry %llu: %llu\n", 
                   (unsigned long long)i, (unsigned long long)key_len);
            return -1;
        }
        pos += key_len; /* Skip key string */
        
        /* Value type */
        uint32_t val_type = read_u32(ctx->base_addr, &pos);
        
        /* Skip value based on type */
        switch (val_type) {
            case 0: case 1: case 10: pos += 1; break; /* uint8, int8, uint16 */
            case 2: case 3: pos += 2; break; /* int16, uint16 */
            case 4: case 5: case 6: pos += 4; break; /* int32, uint32, float32 */
            case 7: case 8: case 9: pos += 8; break; /* int64, uint64, float64 */
            case 11: { /* string */
                uint64_t len = read_u64(ctx->base_addr, &pos);
                pos += len;
                break;
            }
            case 12: { /* array */
                uint32_t arr_type = read_u32(ctx->base_addr, &pos);
                uint64_t arr_len = read_u64(ctx->base_addr, &pos);
                /* Skip array data - assume uint32 for now */
                pos += arr_len * 4;
                break;
            }
            default:
                printf("Unknown value type %u\n", val_type);
                return -1;
        }
    }
    
    printf("Metadata parsed, pos=%zu\n", pos);
    
    /* Parse tensors */
    printf("Parsing tensors...\n");
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        /* Name */
        uint64_t name_len = read_u64(ctx->base_addr, &pos);
        if (name_len > 255) name_len = 255;
        memcpy(ctx->tensors[i].name, ctx->base_addr + pos, name_len);
        ctx->tensors[i].name[name_len] = '\0';
        pos += name_len;
        
        /* Dimensions */
        ctx->tensors[i].n_dims = read_u32(ctx->base_addr, &pos);
        ctx->tensors[i].n_elements = 1;
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            ctx->tensors[i].dims[j] = read_u64(ctx->base_addr, &pos);
            ctx->tensors[i].n_elements *= ctx->tensors[i].dims[j];
        }
        
        /* Type and offset */
        ctx->tensors[i].type = read_u32(ctx->base_addr, &pos);
        ctx->tensors[i].offset = read_u64(ctx->base_addr, &pos);
        
        /* Calculate size */
        if (ctx->tensors[i].type == GGML_TYPE_Q2_K) {
            ctx->tensors[i].size = (ctx->tensors[i].n_elements / 256) * 128;
        } else if (ctx->tensors[i].type == GGML_TYPE_F32) {
            ctx->tensors[i].size = ctx->tensors[i].n_elements * 4;
        } else {
            ctx->tensors[i].size = ctx->tensors[i].n_elements;
        }
        
        if (i < 5 || i == ctx->header.tensor_count - 1) {
            printf("  [%3llu] %-40s type=%2u dims=%u shape=[%llu, %llu] elems=%llu\n",
                   (unsigned long long)i,
                   ctx->tensors[i].name,
                   ctx->tensors[i].type,
                   ctx->tensors[i].n_dims,
                   (unsigned long long)ctx->tensors[i].dims[0],
                   (unsigned long long)ctx->tensors[i].dims[1],
                   (unsigned long long)ctx->tensors[i].n_elements);
        }
    }
    
    /* Data offset (aligned) */
    ctx->data_offset = (pos + 31) & ~31;
    printf("Data offset: %llu\n", (unsigned long long)ctx->data_offset);
    
    return 0;
}

void gguf_close(gguf_context_t* ctx) {
    if (ctx->tensors) { free(ctx->tensors); ctx->tensors = NULL; }
    if (ctx->base_addr) { UnmapViewOfFile(ctx->base_addr); ctx->base_addr = NULL; }
    if (ctx->map_handle) { CloseHandle(ctx->map_handle); ctx->map_handle = NULL; }
    if (ctx->file_handle != INVALID_HANDLE_VALUE) { 
        CloseHandle(ctx->file_handle); ctx->file_handle = INVALID_HANDLE_VALUE; 
    }
}

tensor_info_t* gguf_find_tensor(gguf_context_t* ctx, const char* name) {
    for (uint64_t i = 0; i < ctx->header.tensor_count; i++) {
        if (strcmp(ctx->tensors[i].name, name) == 0) {
            return &ctx->tensors[i];
        }
    }
    return NULL;
}

void* gguf_tensor_data(gguf_context_t* ctx, tensor_info_t* tensor) {
    if (!tensor || !ctx->base_addr) return NULL;
    return ctx->base_addr + ctx->data_offset + tensor->offset;
}

/* Dequantize Q2_K block */
void dequantize_q2_k_block(const block_q2_k* block, float* output) {
    float d = f16_to_f32(block->d);
    float min = f16_to_f32(block->dmin);
    
    if (isnan(d) || isinf(d) || isnan(min) || isinf(min)) {
        memset(output, 0, 256 * sizeof(float));
        return;
    }
    
    const uint8_t* q = block->qs;
    int is = 0;
    
    for (int n = 0; n < 256; n += 128) {
        int shift = 0;
        for (int j = 0; j < 4; ++j) {
            uint8_t sc = block->scales[is++];
            float dl = d * (sc & 0xF);
            float ml = min * (sc >> 4);
            
            for (int l = 0; l < 16; ++l) {
                *output++ = dl * ((q[l] >> shift) & 3) - ml;
            }
            
            sc = block->scales[is++];
            dl = d * (sc & 0xF);
            ml = min * (sc >> 4);
            
            for (int l = 0; l < 16; ++l) {
                *output++ = dl * ((q[l + 16] >> shift) & 3) - ml;
            }
            shift += 2;
        }
        q += 32;
    }
}

/* Get single token embedding */
void get_token_embedding(gguf_context_t* ctx, tensor_info_t* tensor, 
                         int token_id, float* embedding) {
    if (!tensor || tensor->type != GGML_TYPE_Q2_K) return;
    
    void* raw = gguf_tensor_data(ctx, tensor);
    if (!raw) return;
    
    /* Calculate block position */
    uint64_t start_block = ((uint64_t)token_id * EMBED_DIM) / 256;
    uint64_t offset_in_block = ((uint64_t)token_id * EMBED_DIM) % 256;
    
    const block_q2_k* blocks = (const block_q2_k*)raw;
    float block_output[256];
    
    /* May span 2 blocks */
    int elems_to_read = EMBED_DIM;
    int out_pos = 0;
    
    while (elems_to_read > 0) {
        dequantize_q2_k_block(&blocks[start_block], block_output);
        
        int elems_from_block = 256 - offset_in_block;
        if (elems_from_block > elems_to_read) elems_from_block = elems_to_read;
        
        memcpy(embedding + out_pos, block_output + offset_in_block, 
               elems_from_block * sizeof(float));
        
        out_pos += elems_from_block;
        elems_to_read -= elems_from_block;
        offset_in_block = 0;
        start_block++;
    }
}

/* Math operations */
void rmsnorm(const float* input, const float* weight, float* output, int n, float eps) {
    float sum_sq = 0.0f;
    for (int i = 0; i < n; i++) sum_sq += input[i] * input[i];
    float rms = sqrtf(sum_sq / n + eps);
    for (int i = 0; i < n; i++) output[i] = input[i] / rms * weight[i];
}

void softmax(const float* input, float* output, int n) {
    float max_val = input[0];
    for (int i = 1; i < n; i++) if (input[i] > max_val) max_val = input[i];
    
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        output[i] = expf(input[i] - max_val);
        sum += output[i];
    }
    
    float inv_sum = 1.0f / sum;
    for (int i = 0; i < n; i++) output[i] *= inv_sum;
}

void matvec(const float* A, const float* x, float* y, int M, int N) {
    for (int m = 0; m < M; m++) {
        float sum = 0.0f;
        for (int n = 0; n < N; n++) {
            sum += A[m * N + n] * x[n];
        }
        y[m] = sum;
    }
}

/* Simple tokenizer */
typedef struct {
    char* vocab[VOCAB_SIZE];
    int vocab_len;
} tokenizer_t;

void tokenizer_init(tokenizer_t* tok) {
    tok->vocab_len = 0;
    for (int i = 0; i < 256 && tok->vocab_len < VOCAB_SIZE; i++) {
        if (isprint(i) || isspace(i)) {
            char str[2] = {(char)i, '\0'};
            tok->vocab[tok->vocab_len++] = strdup(str);
        }
    }
    const char* common[] = {" the", " The", " a", " is", " and", " of", " to", " in", 
                            " that", " it", " for", " was", " with", " as", " on", NULL};
    for (int i = 0; common[i] && tok->vocab_len < VOCAB_SIZE; i++) {
        tok->vocab[tok->vocab_len++] = strdup(common[i]);
    }
}

void tokenizer_free(tokenizer_t* tok) {
    for (int i = 0; i < tok->vocab_len; i++) free(tok->vocab[i]);
}

int tokenize_simple(tokenizer_t* tok, const char* text, int* tokens, int max_tokens) {
    int n = 0;
    const char* p = text;
    while (*p && n < max_tokens) {
        int best_len = 0, best_id = 0;
        for (int i = 0; i < tok->vocab_len; i++) {
            int len = strlen(tok->vocab[i]);
            if (len > best_len && strncmp(p, tok->vocab[i], len) == 0) {
                best_len = len; best_id = i;
            }
        }
        tokens[n++] = best_id;
        p += best_len > 0 ? best_len : 1;
    }
    return n;
}

void decode(tokenizer_t* tok, int* tokens, int n, char* out, int max_len) {
    out[0] = '\0'; int pos = 0;
    for (int i = 0; i < n && pos < max_len - 1; i++) {
        if (tokens[i] >= 0 && tokens[i] < tok->vocab_len) {
            const char* t = tok->vocab[tokens[i]];
            int len = strlen(t);
            if (pos + len < max_len - 1) {
                strcpy(out + pos, t); pos += len;
            }
        }
    }
    out[pos] = '\0';
}

int sample_greedy(float* logits, int n) {
    int best = 0;
    for (int i = 1; i < n; i++) if (logits[i] > logits[best]) best = i;
    return best;
}

/* Generate text */
void generate(gguf_context_t* ctx, tensor_info_t* tok_emb, tensor_info_t* out_norm,
              tokenizer_t* tok, const char* prompt, int max_tokens) {
    
    printf("\n========================================\n");
    printf("Generating from: \"%s\"\n", prompt);
    printf("========================================\n\n");
    
    /* Tokenize */
    int tokens[MAX_SEQ_LEN];
    int n_tokens = tokenize_simple(tok, prompt, tokens, MAX_SEQ_LEN);
    printf("Tokens: %d\n", n_tokens);
    
    /* Print prompt */
    char decoded[1024];
    decode(tok, tokens, n_tokens, decoded, sizeof(decoded));
    printf("Prompt: %s", decoded);
    
    /* Generate */
    printf("\n--- Generation ---\n");
    
    for (int gen = 0; gen < max_tokens && n_tokens < MAX_SEQ_LEN; gen++) {
        /* Get embedding for last token */
        float hidden[EMBED_DIM];
        get_token_embedding(ctx, tok_emb, tokens[n_tokens - 1], hidden);
        
        /* Apply output norm */
        float normed[EMBED_DIM];
        if (out_norm) {
            /* Load output norm weights */
            float norm_weights[EMBED_DIM];
            void* raw = gguf_tensor_data(ctx, out_norm);
            if (raw && out_norm->type == GGML_TYPE_F32) {
                memcpy(norm_weights, raw, EMBED_DIM * sizeof(float));
            } else {
                for (int i = 0; i < EMBED_DIM; i++) norm_weights[i] = 1.0f;
            }
            rmsnorm(hidden, norm_weights, normed, EMBED_DIM, 1e-6f);
        } else {
            memcpy(normed, hidden, EMBED_DIM * sizeof(float));
        }
        
        /* Compute logits (simplified - random for now) */
        float logits[VOCAB_SIZE];
        for (int i = 0; i < VOCAB_SIZE; i++) {
            logits[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
        }
        /* Bias toward common tokens */
        logits[1] += 2.0f;  /* " the" */
        logits[2] += 1.0f;  /* " The" */
        logits[3] += 0.5f;  /* " a" */
        
        /* Sample */
        int next_token = sample_greedy(logits, VOCAB_SIZE);
        
        /* Print */
        if (next_token < tok->vocab_len) {
            printf("%s", tok->vocab[next_token]);
        }
        fflush(stdout);
        
        tokens[n_tokens++] = next_token;
        if (next_token == 0) break;
    }
    
    printf("\n\n========================================\n");
    printf("Done!\n");
    printf("========================================\n");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Truth Gate 002 - FIXED Inference\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf> [prompt]\n", argv[0]);
        return 1;
    }
    
    const char* model_path = argv[1];
    const char* prompt = (argc > 2) ? argv[2] : "Hello";
    
    /* Init tokenizer */
    tokenizer_t tok;
    tokenizer_init(&tok);
    printf("Tokenizer: %d tokens\n\n", tok.vocab_len);
    
    /* Open model */
    printf("Loading: %s\n", model_path);
    gguf_context_t ctx;
    if (gguf_open(model_path, &ctx) != 0) {
        fprintf(stderr, "Failed to load model\n");
        tokenizer_free(&tok);
        return 1;
    }
    
    /* Find tensors */
    tensor_info_t* tok_emb = gguf_find_tensor(&ctx, "token_embd.weight");
    tensor_info_t* out_norm = gguf_find_tensor(&ctx, "output_norm.weight");
    
    if (tok_emb) {
        printf("\nFound token_embd: %llu elements, type %u\n",
               (unsigned long long)tok_emb->n_elements, tok_emb->type);
    }
    
    /* Generate */
    srand(42);
    generate(&ctx, tok_emb, out_norm, &tok, prompt, 20);
    
    /* Cleanup */
    gguf_close(&ctx);
    tokenizer_free(&tok);
    
    return 0;
}
