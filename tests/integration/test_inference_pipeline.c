/*
 * RawrXD Validation Framework
 * Integration Test: Inference Pipeline
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NAME "Inference Pipeline"
#define MAX_INPUT_LEN 1024
#define MAX_OUTPUT_LEN 1024

/* Mock inference pipeline */
typedef struct {
    char input[MAX_INPUT_LEN];
    char output[MAX_OUTPUT_LEN];
    int tokens_generated;
    float latency_ms;
} InferenceResult;

int mock_tokenize(const char* text, int* tokens, int max_tokens) {
    /* Simple word tokenization */
    int count = 0;
    const char* p = text;
    
    while (*p && count < max_tokens) {
        while (*p && *p == ' ') p++;
        if (!*p) break;
        
        tokens[count++] = 1; /* Mock token ID */
        while (*p && *p != ' ') p++;
    }
    
    return count;
}

int mock_generate(int* input_tokens, int input_len, int* output_tokens, int max_output) {
    /* Mock generation: echo input */
    int gen_len = input_len < max_output ? input_len : max_output;
    for (int i = 0; i < gen_len; i++) {
        output_tokens[i] = input_tokens[i];
    }
    return gen_len;
}

int mock_detokenize(const int* tokens, int num_tokens, char* text, int max_len) {
    /* Mock detokenization */
    strncpy(text, "Hello world", max_len);
    return strlen(text);
}

int run_inference(const char* prompt, InferenceResult* result) {
    /* Step 1: Tokenize */
    int input_tokens[256];
    int input_len = mock_tokenize(prompt, input_tokens, 256);
    if (input_len == 0) return -1;
    
    /* Step 2: Generate */
    int output_tokens[256];
    int output_len = mock_generate(input_tokens, input_len, output_tokens, 256);
    if (output_len == 0) return -1;
    
    /* Step 3: Detokenize */
    mock_detokenize(output_tokens, output_len, result->output, MAX_OUTPUT_LEN);
    
    result->tokens_generated = output_len;
    result->latency_ms = 100.0f; /* Mock latency */
    
    return 0;
}

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    
    /* Test 1: Simple inference */
    InferenceResult result1;
    memset(&result1, 0, sizeof(result1));
    
    int rc1 = run_inference("hello world", &result1);
    if (rc1 != 0) {
        printf("[%s] FAIL: Inference failed\n", TEST_NAME);
        return 1;
    }
    
    printf("[%s] Input: 'hello world'\n", TEST_NAME);
    printf("[%s] Output: '%s'\n", TEST_NAME, result1.output);
    printf("[%s] Tokens: %d, Latency: %.2f ms\n", TEST_NAME, result1.tokens_generated, result1.latency_ms);
    
    if (result1.tokens_generated == 0) {
        printf("[%s] FAIL: No tokens generated\n", TEST_NAME);
        return 1;
    }
    
    /* Test 2: Empty input */
    InferenceResult result2;
    int rc2 = run_inference("", &result2);
    if (rc2 == 0) {
        printf("[%s] FAIL: Empty input should fail\n", TEST_NAME);
        return 1;
    }
    
    printf("[%s] Empty input correctly rejected\n", TEST_NAME);
    
    printf("[%s] PASS\n", TEST_NAME);
    return 0;
}
