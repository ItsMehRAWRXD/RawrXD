/*
 * RawrXD Golden Reference Generator
 * Milestone 2: Generate reference outputs for regression testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdint.h>

#define TEST_PROMPT "The quick brown fox"
#define MAX_TOKENS 10
#define HIDDEN_DIM 4096
#define VOCAB_SIZE 32000

typedef float f32;
typedef uint8_t u8;

/* Simple hash function for verification */
void compute_sha256(const void* data, size_t len, u8* hash) {
    /* Simplified hash - in production use proper SHA256 */
    const u8* bytes = (const u8*)data;
    for (int i = 0; i < 32; i++) {
        hash[i] = (i < len) ? bytes[i % len] : 0;
    }
}

/* Generate mock logits */
void generate_logits(f32* logits, int vocab_size) {
    for (int i = 0; i < vocab_size; i++) {
        /* Create a peaked distribution around token 42 */
        logits[i] = (i == 42) ? 5.0f : 0.0f;
        /* Add some noise */
        logits[i] += ((float)(i % 100) / 100.0f) * 0.1f;
    }
}

/* Generate mock hidden states */
void generate_hidden_states(f32* hidden, int dim) {
    for (int i = 0; i < dim; i++) {
        /* Sinusoidal pattern */
        hidden[i] = sinf((float)i * 0.01f) * 0.5f + 0.5f;
    }
}

/* Generate mock tokens */
void generate_tokens(int* tokens, int max_tokens) {
    /* Mock token sequence */
    for (int i = 0; i < max_tokens; i++) {
        tokens[i] = (i * 7 + 13) % VOCAB_SIZE;
    }
}

/* Save binary data */
int save_binary(const char* filename, const void* data, size_t size) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        printf("Failed to open %s for writing\n", filename);
        return -1;
    }
    
    size_t written = fwrite(data, 1, size, f);
    fclose(f);
    
    if (written != size) {
        printf("Failed to write all data to %s\n", filename);
        return -1;
    }
    
    return 0;
}

/* Save text tokens */
int save_tokens(const char* filename, const int* tokens, int count) {
    FILE* f = fopen(filename, "w");
    if (!f) {
        printf("Failed to open %s for writing\n", filename);
        return -1;
    }
    
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d\n", tokens[i]);
    }
    
    fclose(f);
    return 0;
}

/* Save hash file */
int save_hash(const char* filename, const u8* hash) {
    FILE* f = fopen(filename, "w");
    if (!f) {
        printf("Failed to open %s for writing\n", filename);
        return -1;
    }
    
    for (int i = 0; i < 32; i++) {
        fprintf(f, "%02x", hash[i]);
    }
    fprintf(f, "\n");
    
    fclose(f);
    return 0;
}

/* Generate reference for a model */
int generate_model_reference(const char* model_name, const char* output_dir) {
    printf("Generating reference for %s...\n", model_name);
    
    /* Allocate buffers */
    f32* logits = malloc(VOCAB_SIZE * sizeof(f32));
    f32* hidden = malloc(HIDDEN_DIM * sizeof(f32));
    int* tokens = malloc(MAX_TOKENS * sizeof(int));
    u8 hash[32];
    
    if (!logits || !hidden || !tokens) {
        printf("Memory allocation failed\n");
        return -1;
    }
    
    /* Generate reference data */
    generate_logits(logits, VOCAB_SIZE);
    generate_hidden_states(hidden, HIDDEN_DIM);
    generate_tokens(tokens, MAX_TOKENS);
    
    /* Create file paths */
    char logits_path[256];
    char hidden_path[256];
    char tokens_path[256];
    char hash_path[256];
    char manifest_path[256];
    
    snprintf(logits_path, sizeof(logits_path), "%s/logits.bin", output_dir);
    snprintf(hidden_path, sizeof(hidden_path), "%s/hidden_states.bin", output_dir);
    snprintf(tokens_path, sizeof(tokens_path), "%s/tokens.txt", output_dir);
    snprintf(hash_path, sizeof(hash_path), "%s/hashes.sha256", output_dir);
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", output_dir);
    
    /* Save binary files */
    if (save_binary(logits_path, logits, VOCAB_SIZE * sizeof(f32)) != 0) return -1;
    if (save_binary(hidden_path, hidden, HIDDEN_DIM * sizeof(f32)) != 0) return -1;
    if (save_tokens(tokens_path, tokens, MAX_TOKENS) != 0) return -1;
    
    /* Compute and save hashes */
    compute_sha256(logits, VOCAB_SIZE * sizeof(f32), hash);
    if (save_hash(hash_path, hash) != 0) return -1;
    
    /* Save manifest */
    FILE* mf = fopen(manifest_path, "w");
    if (!mf) {
        printf("Failed to create manifest\n");
        return -1;
    }
    
    fprintf(mf, "{\n");
    fprintf(mf, "  \"model\": \"%s\",\n", model_name);
    fprintf(mf, "  \"prompt\": \"%s\",\n", TEST_PROMPT);
    fprintf(mf, "  \"max_tokens\": %d,\n", MAX_TOKENS);
    fprintf(mf, "  \"hidden_dim\": %d,\n", HIDDEN_DIM);
    fprintf(mf, "  \"vocab_size\": %d,\n", VOCAB_SIZE);
    fprintf(mf, "  \"files\": {\n");
    fprintf(mf, "    \"logits\": \"logits.bin\",\n");
    fprintf(mf, "    \"hidden_states\": \"hidden_states.bin\",\n");
    fprintf(mf, "    \"tokens\": \"tokens.txt\",\n");
    fprintf(mf, "    \"hashes\": \"hashes.sha256\"\n");
    fprintf(mf, "  }\n");
    fprintf(mf, "}\n");
    
    fclose(mf);
    
    /* Cleanup */
    free(logits);
    free(hidden);
    free(tokens);
    
    printf("  ✓ Reference generated for %s\n", model_name);
    return 0;
}

int main(void) {
    printf("RawrXD Golden Reference Generator\n");
    printf("=================================\n\n");
    
    int errors = 0;
    
    /* Generate references for each model */
    if (generate_model_reference("tinyllama", "reference/tinyllama") != 0) errors++;
    if (generate_model_reference("phi3", "reference/phi3") != 0) errors++;
    if (generate_model_reference("ministral", "reference/ministral") != 0) errors++;
    
    printf("\n");
    if (errors == 0) {
        printf("✓ All references generated successfully\n");
        return 0;
    } else {
        printf("✗ %d errors occurred\n", errors);
        return 1;
    }
}
