/*
 * RawrXD Validation Framework
 * Sampler Test: Temperature Scaling
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#define TEST_NAME "Temperature Scaling"
#define VOCAB_SIZE 1000

typedef float f32;

void apply_temperature(f32* logits, int n, f32 temp) {
    if (temp == 0.0f) return;
    for (int i = 0; i < n; i++) {
        logits[i] /= temp;
    }
}

f32 compute_entropy(const f32* probs, int n) {
    f32 entropy = 0.0f;
    for (int i = 0; i < n; i++) {
        if (probs[i] > 0.0f) {
            entropy -= probs[i] * logf(probs[i]);
        }
    }
    return entropy;
}

void softmax(f32* x, int n) {
    f32 max_val = x[0];
    for (int i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    f32 sum = 0.0f;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    for (int i = 0; i < n; i++) {
        x[i] /= sum;
    }
}

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    
    /* Create non-uniform logits for meaningful temperature test */
    f32* logits = malloc(VOCAB_SIZE * sizeof(f32));
    if (!logits) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    /* Create peaked distribution: first token has highest logit */
    for (int i = 0; i < VOCAB_SIZE; i++) {
        logits[i] = (VOCAB_SIZE - i) / 100.0f; /* Decreasing values */
    }
    
    /* Test 1: Temperature = 1.0 (no change) */
    f32* probs1 = malloc(VOCAB_SIZE * sizeof(f32));
    memcpy(probs1, logits, VOCAB_SIZE * sizeof(f32));
    apply_temperature(probs1, VOCAB_SIZE, 1.0f);
    softmax(probs1, VOCAB_SIZE);
    
    f32 entropy1 = compute_entropy(probs1, VOCAB_SIZE);
    printf("[%s] T=1.0 entropy: %f\n", TEST_NAME, entropy1);
    
    /* Test 2: Temperature = 0.5 (more peaked) */
    f32* probs2 = malloc(VOCAB_SIZE * sizeof(f32));
    memcpy(probs2, logits, VOCAB_SIZE * sizeof(f32));
    apply_temperature(probs2, VOCAB_SIZE, 0.5f);
    softmax(probs2, VOCAB_SIZE);
    
    f32 entropy2 = compute_entropy(probs2, VOCAB_SIZE);
    printf("[%s] T=0.5 entropy: %f\n", TEST_NAME, entropy2);
    
    /* Test 3: Temperature = 2.0 (more flat) */
    f32* probs3 = malloc(VOCAB_SIZE * sizeof(f32));
    memcpy(probs3, logits, VOCAB_SIZE * sizeof(f32));
    apply_temperature(probs3, VOCAB_SIZE, 2.0f);
    softmax(probs3, VOCAB_SIZE);
    
    f32 entropy3 = compute_entropy(probs3, VOCAB_SIZE);
    printf("[%s] T=2.0 entropy: %f\n", TEST_NAME, entropy3);
    
    /* Verify: T=0.5 should have lower entropy than T=1.0 */
    /* Verify: T=2.0 should have higher entropy than T=1.0 */
    int pass = 1;
    if (entropy2 >= entropy1) {
        printf("[%s] FAIL: T=0.5 should have lower entropy than T=1.0\n", TEST_NAME);
        pass = 0;
    }
    if (entropy3 <= entropy1) {
        printf("[%s] FAIL: T=2.0 should have higher entropy than T=1.0\n", TEST_NAME);
        pass = 0;
    }
    
    free(logits);
    free(probs1);
    free(probs2);
    free(probs3);
    
    if (pass) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        return 1;
    }
}
