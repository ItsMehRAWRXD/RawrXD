/* tg002_v3.c - GGUF v3 parser with correct value type handling */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <math.h>

#define GGUF_MAGIC 0x46554747
#define VOCAB_SIZE 51200
#define EMBED_DIM 2560
#define MAX_SEQ_LEN 2048

/* GGML types */
#define GGML_TYPE_F32  0
#define GGML_TYPE_Q2_K 10

/* GGUF value types */
#define GGUF_TYPE_UINT8   0
#define GGUF_TYPE_INT8    1
#define GGUF_TYPE_UINT16  2
#define GGUF_TYPE_INT16   3
#define GGUF_TYPE_UINT32  4
#define GGUF_TYPE_INT32   5
#define GGUF_TYPE_FLOAT32 6
#define GGUF_TYPE_UINT64  7
#define GGUF_TYPE_INT64   8
#define GGUF_TYPE_FLOAT64 9
#define GGUF_TYPE_BOOL    10
#define GGUF_TYPE_STRING  11
#define GGUF_TYPE_ARRAY   12

typedef struct {
    char name[256];
    uint32_t n_dims;
    uint64_t dims[4];
    uint32_t type;
    uint64_t offset;
    uint64_t n_elements;
    uint64_t size;
} tensor_info_t;

typedef struct {
    HANDLE file_handle;
    HANDLE map_handle;
    uint8_t* data;
    size_t file_size;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
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

/* Get uint64 from little-endian bytes */
static uint64_t get_u64(uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | 
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Get uint32 from little-endian bytes */
static uint32_t get_u32(uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | 
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Get value size based on type */
static size_t get_value_size(uint32_t type) {
    switch (type) {
        case GGUF_TYPE_UINT8:
        case GGUF_TYPE_INT8:
        case GGUF_TYPE_BOOL:
            return 1;
        case GGUF_TYPE_UINT16:
        case GGUF_TYPE_INT16:
            return 2;
        case GGUF_TYPE_UINT32:
        case GGUF_TYPE_INT32:
        case GGUF_TYPE_FLOAT32:
            return 4;
        case GGUF_TYPE_UINT64:
        case GGUF_TYPE_INT64:
        case GGUF_TYPE_FLOAT64:
            return 8;
        default:
            return 0; /* Variable size types */
    }
}

/* Open GGUF */
int gguf_open(const char* path, gguf_context_t* ctx) {
    memset(ctx, 0, sizeof(gguf_context_t));
    
    ctx->file_handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ctx->file_handle == INVALID_HANDLE_VALUE) {
        printf("Failed to open file\n");
        return -1;
    }
    
    LARGE_INTEGER size;
    GetFileSizeEx(ctx->file_handle, &size);
    ctx->file_size = (size_t)size.QuadPart;
    
    ctx->map_handle = CreateFileMappingA(ctx->file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!ctx->map_handle) {
        printf("Failed to create mapping\n");
        return -1;
    }
    
    ctx->data = (uint8_t*)MapViewOfFile(ctx->map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!ctx->data) {
        printf("Failed to map view\n");
        return -1;
    }
    
    /* Parse header */
    uint32_t magic = get_u32(ctx->data);
    if (magic != GGUF_MAGIC) {
        printf("Invalid magic: 0x%08X\n", magic);
        return -1;
    }
    
    ctx->version = get_u32(ctx->data + 4);
    ctx->tensor_count = get_u64(ctx->data + 8);
    ctx->metadata_kv_count = get_u64(ctx->data + 16);
    
    printf("GGUF Version: %u\n", ctx->version);
    printf("Tensors: %llu\n", (unsigned long long)ctx->tensor_count);
    printf("Metadata: %llu\n", (unsigned long long)ctx->metadata_kv_count);
    
    /* Allocate tensors */
    ctx->tensors = calloc(ctx->tensor_count, sizeof(tensor_info_t));
    if (!ctx->tensors) return -1;
    
    /* Parse metadata */
    size_t pos = 24;
    printf("Parsing metadata...\n");
    
    for (uint64_t i = 0; i < ctx->metadata_kv_count && pos < ctx->file_size; i++) {
        /* Key length */
        uint64_t key_len = get_u64(ctx->data + pos);
        pos += 8;
        
        if (key_len > 10000 || pos + key_len > ctx->file_size) {
            printf("Invalid key length %llu at pos %zu\n", (unsigned long long)key_len, pos);
            return -1;
        }
        
        /* Skip key */
        pos += key_len;
        
        /* Value type */
        uint32_t val_type = get_u32(ctx->data + pos);
        pos += 4;
        
        /* Handle value based on type */
        if (val_type == GGUF_TYPE_STRING) {
            /* String: length + data */
            uint64_t str_len = get_u64(ctx->data + pos);
            pos += 8 + str_len;
        } else if (val_type == GGUF_TYPE_ARRAY) {
            /* Array: type + length + data */
            uint32_t arr_type = get_u32(ctx->data + pos);
            pos += 4;
            uint64_t arr_len = get_u64(ctx->data + pos);
            pos += 8;
            
            /* Calculate element size */
            size_t elem_size = get_value_size(arr_type);
            if (elem_size == 0 && arr_type == GGUF_TYPE_STRING) {
                /* Array of strings - need to parse each */
                for (uint64_t j = 0; j < arr_len; j++) {
                    uint64_t str_len = get_u64(ctx->data + pos);
                    pos += 8 + str_len;
                }
            } else {
                pos += arr_len * elem_size;
            }
        } else {
            /* Simple type - fixed size */
            size_t val_size = get_value_size(val_type);
            if (val_size == 0) {
                printf("Unknown value type %u at pos %zu\n", val_type, pos);
                return -1;
            }
            pos += val_size;
        }
    }
    
    printf("Metadata parsed, pos=%zu\n", pos);
    
    /* Parse tensors */
    printf("Parsing tensors...\n");
    for (uint64_t i = 0; i < ctx->tensor_count && pos < ctx->file_size; i++) {
        /* Name */
        uint64_t name_len = get_u64(ctx->data + pos);
        pos += 8;
        
        if (name_len > 255) name_len = 255;
        memcpy(ctx->tensors[i].name, ctx->data + pos, name_len);
        ctx->tensors[i].name[name_len] = '\0';
        pos += name_len;
        
        /* Dimensions */
        ctx->tensors[i].n_dims = get_u32(ctx->data + pos);
        pos += 4;
        
        ctx->tensors[i].n_elements = 1;
        for (uint32_t j = 0; j < ctx->tensors[i].n_dims; j++) {
            ctx->tensors[i].dims[j] = get_u64(ctx->data + pos);
            pos += 8;
            ctx->tensors[i].n_elements *= ctx->tensors[i].dims[j];
        }
        
        /* Type and offset */
        ctx->tensors[i].type = get_u32(ctx->data + pos);
        pos += 4;
        ctx->tensors[i].offset = get_u64(ctx->data + pos);
        pos += 8;
        
        /* Calculate size */
        if (ctx->tensors[i].type == GGML_TYPE_Q2_K) {
            ctx->tensors[i].size = (ctx->tensors[i].n_elements / 256) * 128;
        } else if (ctx->tensors[i].type == GGML_TYPE_F32) {
            ctx->tensors[i].size = ctx->tensors[i].n_elements * 4;
        } else {
            ctx->tensors[i].size = ctx->tensors[i].n_elements;
        }
        
        if (i < 3 || i >= ctx->tensor_count - 2) {
            printf("  [%3llu] %-45s type=%2u dims=%u [%llu, %llu]\n",
                   (unsigned long long)i,
                   ctx->tensors[i].name,
                   ctx->tensors[i].type,
                   ctx->tensors[i].n_dims,
                   (unsigned long long)ctx->tensors[i].dims[0],
                   ctx->tensors[i].n_dims > 1 ? (unsigned long long)ctx->tensors[i].dims[1] : 0);
        } else if (i == 3) {
            printf("  ...\n");
        }
    }
    
    /* Data offset (aligned to 32 bytes) */
    ctx->data_offset = (pos + 31) & ~31;
    printf("Data offset: %llu\n", (unsigned long long)ctx->data_offset);
    
    return 0;
}

void gguf_close(gguf_context_t* ctx) {
    if (ctx->tensors) { free(ctx->tensors); ctx->tensors = NULL; }
    if (ctx->data) { UnmapViewOfFile(ctx->data); ctx->data = NULL; }
    if (ctx->map_handle) { CloseHandle(ctx->map_handle); ctx->map_handle = NULL; }
    if (ctx->file_handle != INVALID_HANDLE_VALUE) { 
        CloseHandle(ctx->file_handle); ctx->file_handle = INVALID_HANDLE_VALUE; 
    }
}

tensor_info_t* gguf_find_tensor(gguf_context_t* ctx, const char* name) {
    for (uint64_t i = 0; i < ctx->tensor_count; i++) {
        if (strcmp(ctx->tensors[i].name, name) == 0) {
            return &ctx->tensors[i];
        }
    }
    return NULL;
}

void* gguf_tensor_data(gguf_context_t* ctx, tensor_info_t* tensor) {
    if (!tensor || !ctx->data) return NULL;
    return ctx->data + ctx->data_offset + tensor->offset;
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

/* Get token embedding */
void get_token_embedding(gguf_context_t* ctx, tensor_info_t* tensor, 
                         int token_id, float* embedding) {
    if (!tensor || tensor->type != GGML_TYPE_Q2_K) return;
    
    void* raw = gguf_tensor_data(ctx, tensor);
    if (!raw) return;
    
    uint64_t start_block = ((uint64_t)token_id * EMBED_DIM) / 256;
    uint64_t offset_in_block = ((uint64_t)token_id * EMBED_DIM) % 256;
    
    const block_q2_k* blocks = (const block_q2_k*)raw;
    float block_output[256];
    
    int elems_to_read = EMBED_DIM;
    int out_pos = 0;
    
    while (elems_to_read > 0) {
        dequantize_q2_k_block(&blocks[start_block], block_output);
        
        int elems_from_block = 256 - (int)offset_in_block;
        if (elems_from_block > elems_to_read) elems_from_block = elems_to_read;
        
        memcpy(embedding + out_pos, block_output + offset_in_block, 
               elems_from_block * sizeof(float));
        
        out_pos += elems_from_block;
        elems_to_read -= elems_from_block;
        offset_in_block = 0;
        start_block++;
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

/* Generate */
void generate(gguf_context_t* ctx, tensor_info_t* tok_emb, tokenizer_t* tok, 
              const char* prompt, int max_tokens) {
    
    printf("\n========================================\n");
    printf("Generating from: \"%s\"\n", prompt);
    printf("========================================\n\n");
    
    int tokens[MAX_SEQ_LEN];
    int n_tokens = tokenize_simple(tok, prompt, tokens, MAX_SEQ_LEN);
    printf("Tokens: %d\n\n", n_tokens);
    
    char decoded[1024];
    decode(tok, tokens, n_tokens, decoded, sizeof(decoded));
    printf("Prompt: %s", decoded);
    printf("\n--- Generation ---\n");
    
    for (int gen = 0; gen < max_tokens && n_tokens < MAX_SEQ_LEN; gen++) {
        /* Get embedding */
        float hidden[EMBED_DIM];
        get_token_embedding(ctx, tok_emb, tokens[n_tokens - 1], hidden);
        
        /* Compute logits (random for now) */
        float logits[VOCAB_SIZE];
        for (int i = 0; i < VOCAB_SIZE; i++) {
            logits[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
        }
        logits[1] += 2.0f;
        logits[2] += 1.0f;
        
        int next_token = sample_greedy(logits, VOCAB_SIZE);
        
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
    printf("Truth Gate 002 - V3\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <model.gguf> [prompt]\n", argv[0]);
        return 1;
    }
    
    const char* model_path = argv[1];
    const char* prompt = (argc > 2) ? argv[2] : "Hello";
    
    tokenizer_t tok;
    tokenizer_init(&tok);
    printf("Tokenizer: %d tokens\n\n", tok.vocab_len);
    
    printf("Loading: %s\n", model_path);
    gguf_context_t ctx;
    if (gguf_open(model_path, &ctx) != 0) {
        fprintf(stderr, "Failed to load model\n");
        tokenizer_free(&tok);
        return 1;
    }
    
    tensor_info_t* tok_emb = gguf_find_tensor(&ctx, "token_embd.weight");
    if (tok_emb) {
        printf("\nFound token_embd: %llu elements, type %u\n",
               (unsigned long long)tok_emb->n_elements, tok_emb->type);
    } else {
        printf("Warning: token_embd.weight not found\n");
    }
    
    srand(42);
    generate(&ctx, tok_emb, &tok, prompt, 20);
    
    gguf_close(&ctx);
    tokenizer_free(&tok);
    
    return 0;
}
