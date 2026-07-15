/*
 * RawrXD Inference End-to-End Test
 * Validates complete inference pipeline with mock model
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define TEST_NAME "Inference E2E"
#define MAX_TOKENS 50
#define VOCAB_SIZE 32000
#define HIDDEN_DIM 4096
#define NUM_LAYERS 4  /* Reduced for testing */
#define NUM_HEADS 8
#define HEAD_DIM 64

typedef struct {
    float* weights;
    int rows;
    int cols;
} matrix_t;

typedef struct {
    matrix_t* layers;
    int num_layers;
    float* embedding;
    int vocab_size;
    int hidden_dim;
} mock_model_t;

typedef struct {
    float* key_cache;
    float* value_cache;
    int seq_len;
    int max_len;
} kv_cache_t;

int tests_passed = 0;
int tests_failed = 0;

/* Initialize mock model with random weights */
int model_init(mock_model_t* model) {
    model->num_layers = NUM_LAYERS;
    model->vocab_size = VOCAB_SIZE;
    model->hidden_dim = HIDDEN_DIM;
    
    /* Embedding table */
    model->embedding = (float*)calloc(VOCAB_SIZE * HIDDEN_DIM, sizeof(float));
    if (!model->embedding) return -1;
    
    for (int i = 0; i < VOCAB_SIZE * HIDDEN_DIM; i++) {
        model->embedding[i] = ((float)rand() / RAND_MAX - 0.5f) * 0.1f;
    }
    
    /* Layer weights */
    model->layers = (matrix_t*)calloc(NUM_LAYERS, sizeof(matrix_t));
    if (!model->layers) {
        free(model->embedding);
        return -1;
    }
    
    for (int l = 0; l < NUM_LAYERS; l++) {
        model->layers[l].rows = HIDDEN_DIM;
        model->layers[l].cols = HIDDEN_DIM;
        model->layers[l].weights = (float*)calloc(HIDDEN_DIM * HIDDEN_DIM, sizeof(float));
        if (!model->layers[l].weights) return -1;
        
        /* Xavier initialization */
        float scale = sqrtf(2.0f / HIDDEN_DIM);
        for (int i = 0; i < HIDDEN_DIM * HIDDEN_DIM; i++) {
            model->layers[l].weights[i] = ((float)rand() / RAND_MAX - 0.5f) * scale;
        }
    }
    
    return 0;
}

void model_free(mock_model_t* model) {
    if (model->embedding) {
        free(model->embedding);
        model->embedding = NULL;
    }
    if (model->layers) {
        for (int l = 0; l < model->num_layers; l++) {
            if (model->layers[l].weights) {
                free(model->layers[l].weights);
            }
        }
        free(model->layers);
        model->layers = NULL;
    }
}

/* Simple matrix multiplication */
void matmul(const float* A, const float* B, float* C, int M, int N, int K) {
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

/* RMS Norm */
void rms_norm(float* out, const float* in, int n, float eps) {
    float sum_sq = 0.0f;
    for (int i = 0; i < n; i++) {
        sum_sq += in[i] * in[i];
    }
    float rms = sqrtf(sum_sq / n + eps);
    for (int i = 0; i < n; i++) {
        out[i] = in[i] / rms;
    }
}

/* SiLU activation */
float silu(float x) {
    return x / (1.0f + expf(-x));
}

/* Forward pass through one layer */
void layer_forward(const mock_model_t* model, int layer_idx, 
                   float* hidden, int seq_len) {
    matrix_t* layer = &model->layers[layer_idx];
    float* temp = (float*)calloc(seq_len * HIDDEN_DIM, sizeof(float));
    
    /* Linear transformation */
    matmul(hidden, layer->weights, temp, seq_len, HIDDEN_DIM, HIDDEN_DIM);
    
    /* Activation */
    for (int i = 0; i < seq_len * HIDDEN_DIM; i++) {
        temp[i] = silu(temp[i]);
    }
    
    /* Copy back */
    memcpy(hidden, temp, seq_len * HIDDEN_DIM * sizeof(float));
    
    free(temp);
}

/* Mock tokenization */
int tokenize(const char* text, int* tokens, int max_tokens) {
    int count = 0;
    const char* ptr = text;
    
    while (*ptr && count < max_tokens) {
        /* Skip whitespace */
        while (*ptr && (*ptr == ' ' || *ptr == '\t' || *ptr == '\n')) ptr++;
        if (!*ptr) break;
        
        /* Simple hash-based tokenization */
        unsigned int hash = 0;
        while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '\n') {
            hash = hash * 31 + *ptr++;
        }
        
        tokens[count++] = (hash % (VOCAB_SIZE - 100)) + 10;
    }
    
    return count;
}

/* Mock detokenization */
void detokenize(const int* tokens, int num_tokens, char* output, int max_len) {
    int pos = 0;
    
    for (int i = 0; i < num_tokens && pos < max_len - 10; i++) {
        int token = tokens[i];
        
        /* Map tokens to words */
        if (token >= 1000 && token < 1100) {
            const char* words[] = {"the", "a", "is", "are", "was", "were", 
                                   "be", "been", "have", "has", "had"};
            int idx = (token - 1000) % 11;
            pos += snprintf(output + pos, max_len - pos, "%s ", words[idx]);
        } else if (token >= 2000 && token < 2100) {
            const char* nouns[] = {"cat", "dog", "house", "car", "tree",
                                   "book", "computer", "phone"};
            int idx = (token - 2000) % 8;
            pos += snprintf(output + pos, max_len - pos, "%s ", nouns[idx]);
        } else {
            pos += snprintf(output + pos, max_len - pos, "tok%d ", token);
        }
    }
    
    if (pos > 0 && output[pos - 1] == ' ') {
        output[pos - 1] = '\0';
    }
}

/* Sample next token */
int sample_token(const float* logits, int vocab_size, float temperature) {
    /* Apply temperature */
    float scaled[VOCAB_SIZE];
    for (int i = 0; i < vocab_size; i++) {
        scaled[i] = logits[i] / temperature;
    }
    
    /* Softmax */
    float max_logit = scaled[0];
    for (int i = 1; i < vocab_size; i++) {
        if (scaled[i] > max_logit) max_logit = scaled[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < vocab_size; i++) {
        scaled[i] = expf(scaled[i] - max_logit);
        sum += scaled[i];
    }
    
    for (int i = 0; i < vocab_size; i++) {
        scaled[i] /= sum;
    }
    
    /* Greedy sampling */
    int best_token = 0;
    float best_prob = scaled[0];
    for (int i = 1; i < vocab_size; i++) {
        if (scaled[i] > best_prob) {
            best_prob = scaled[i];
            best_token = i;
        }
    }
    
    return best_token;
}

/* Test 1: Model initialization */
int test_model_init() {
    printf("\n  [TEST] Model Initialization\n");
    
    mock_model_t model = {0};
    
    if (model_init(&model) != 0) {
        printf("    ✗ Model initialization failed\n");
        return -1;
    }
    
    printf("    ✓ Model initialized (%d layers, %d hidden)\n", 
           model.num_layers, model.hidden_dim);
    
    model_free(&model);
    return 0;
}

/* Test 2: Tokenization roundtrip */
int test_tokenization() {
    printf("\n  [TEST] Tokenization\n");
    
    const char* input = "the cat sat on the mat";
    int tokens[50];
    char output[256];
    
    int num_tokens = tokenize(input, tokens, 50);
    if (num_tokens <= 0) {
        printf("    ✗ Tokenization failed\n");
        return -1;
    }
    
    printf("    Tokenized to %d tokens\n", num_tokens);
    
    detokenize(tokens, num_tokens, output, sizeof(output));
    printf("    Roundtrip: '%s'\n", output);
    
    printf("    ✓ Tokenization successful\n");
    return 0;
}

/* Test 3: Forward pass */
int test_forward_pass() {
    printf("\n  [TEST] Forward Pass\n");
    
    mock_model_t model = {0};
    if (model_init(&model) != 0) {
        return -1;
    }
    
    /* Create input */
    int tokens[] = {1000, 2000, 1001};
    int seq_len = 3;
    
    /* Embed tokens */
    float* hidden = (float*)calloc(seq_len * HIDDEN_DIM, sizeof(float));
    for (int t = 0; t < seq_len; t++) {
        int token = tokens[t] % VOCAB_SIZE;
        for (int d = 0; d < HIDDEN_DIM; d++) {
            hidden[t * HIDDEN_DIM + d] = model.embedding[token * HIDDEN_DIM + d];
        }
    }
    
    /* Forward through layers */
    for (int l = 0; l < model.num_layers; l++) {
        layer_forward(&model, l, hidden, seq_len);
    }
    
    /* Check output is reasonable */
    float sum = 0.0f;
    for (int i = 0; i < seq_len * HIDDEN_DIM; i++) {
        sum += hidden[i];
    }
    
    printf("    Hidden state sum: %.4f\n", sum);
    
    if (isnan(sum) || isinf(sum)) {
        printf("    ✗ Invalid hidden state\n");
        free(hidden);
        model_free(&model);
        return -1;
    }
    
    printf("    ✓ Forward pass successful\n");
    
    free(hidden);
    model_free(&model);
    return 0;
}

/* Test 4: Complete generation */
int test_generation() {
    printf("\n  [TEST] Token Generation\n");
    
    mock_model_t model = {0};
    if (model_init(&model) != 0) {
        return -1;
    }
    
    const char* prompt = "the cat";
    int prompt_tokens[50];
    int generated[MAX_TOKENS];
    float hidden[HIDDEN_DIM];
    float logits[VOCAB_SIZE];
    char output[512];
    
    /* Tokenize */
    int num_prompt = tokenize(prompt, prompt_tokens, 50);
    printf("    Prompt: '%s' (%d tokens)\n", prompt, num_prompt);
    
    /* Copy prompt */
    int total = num_prompt;
    for (int i = 0; i < num_prompt; i++) {
        generated[i] = prompt_tokens[i];
    }
    
    /* Generate */
    clock_t start = clock();
    
    for (int step = 0; step < 5 && total < MAX_TOKENS; step++) {
        /* Embed last token */
        int last_token = generated[total - 1] % VOCAB_SIZE;
        for (int d = 0; d < HIDDEN_DIM; d++) {
            hidden[d] = model.embedding[last_token * HIDDEN_DIM + d];
        }
        
        /* Forward through layers */
        for (int l = 0; l < model.num_layers; l++) {
            float temp[HIDDEN_DIM];
            layer_forward(&model, l, hidden, 1);
        }
        
        /* Project to vocab (simplified) */
        for (int v = 0; v < VOCAB_SIZE; v++) {
            logits[v] = 0.0f;
            for (int d = 0; d < HIDDEN_DIM; d++) {
                logits[v] += hidden[d] * model.embedding[v * HIDDEN_DIM + d];
            }
        }
        
        /* Sample */
        int next = sample_token(logits, VOCAB_SIZE, 0.8f);
        generated[total++] = next;
    }
    
    clock_t end = clock();
    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    /* Detokenize */
    detokenize(generated, total, output, sizeof(output));
    
    printf("    Generated: '%s'\n", output);
    printf("    Tokens: %d, Time: %.2f ms\n", total, elapsed);
    
    if (total <= num_prompt) {
        printf("    ✗ No tokens generated\n");
        model_free(&model);
        return -1;
    }
    
    printf("    ✓ Generation successful\n");
    
    model_free(&model);
    return 0;
}

/* Run test */
void run_test(const char* name, int (*func)(void)) {
    int result = func();
    if (result == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
}

int main() {
    printf("RawrXD Inference E2E Test\n");
    printf("=========================\n");
    
    srand((unsigned int)time(NULL));
    
    run_test("Model Init", test_model_init);
    run_test("Tokenization", test_tokenization);
    run_test("Forward Pass", test_forward_pass);
    run_test("Generation", test_generation);
    
    printf("\n");
    printf("=========================\n");
    printf("E2E Test Summary\n");
    printf("=========================\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("Total:  %d\n", tests_passed + tests_failed);
    
    if (tests_failed == 0) {
        printf("\n✓ ALL E2E TESTS PASSED\n");
        return 0;
    } else {
        printf("\n✗ SOME E2E TESTS FAILED\n");
        return 1;
    }
}
