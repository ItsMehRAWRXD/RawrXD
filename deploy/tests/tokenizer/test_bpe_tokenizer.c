/*
 * RawrXD Validation Framework
 * Tokenizer Test: BPE Tokenization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NAME "BPE Tokenizer"
#define MAX_TOKENS 256

typedef struct {
    char* text;
    int* tokens;
    int num_tokens;
} TokenizerResult;

/* Simple BPE-like tokenization for testing */
int bpe_tokenize(const char* text, int* tokens, int max_tokens) {
    int count = 0;
    const char* p = text;
    
    while (*p && count < max_tokens) {
        /* Skip whitespace */
        while (*p && (*p == ' ' || *p == '\t' || *p == '\n')) p++;
        if (!*p) break;
        
        /* Simple word tokenization */
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')) {
            /* Word */
            tokens[count++] = 1; /* Token ID for word */
            while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) p++;
        } else if (*p >= '0' && *p <= '9') {
            /* Number */
            tokens[count++] = 2; /* Token ID for number */
            while (*p && *p >= '0' && *p <= '9') p++;
        } else {
            /* Punctuation */
            tokens[count++] = 3 + (unsigned char)*p;
            p++;
        }
    }
    
    return count;
}

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    
    /* Test 1: Simple sentence */
    const char* text1 = "hello world";
    int tokens1[MAX_TOKENS];
    int count1 = bpe_tokenize(text1, tokens1, MAX_TOKENS);
    
    printf("[%s] Test 1: '%s' -> %d tokens\n", TEST_NAME, text1, count1);
    if (count1 != 2) {
        printf("[%s] FAIL: Expected 2 tokens, got %d\n", TEST_NAME, count1);
        return 1;
    }
    
    /* Test 2: Numbers */
    const char* text2 = "123 456";
    int tokens2[MAX_TOKENS];
    int count2 = bpe_tokenize(text2, tokens2, MAX_TOKENS);
    
    printf("[%s] Test 2: '%s' -> %d tokens\n", TEST_NAME, text2, count2);
    if (count2 != 2) {
        printf("[%s] FAIL: Expected 2 tokens, got %d\n", TEST_NAME, count2);
        return 1;
    }
    
    /* Test 3: Empty string */
    const char* text3 = "";
    int tokens3[MAX_TOKENS];
    int count3 = bpe_tokenize(text3, tokens3, MAX_TOKENS);
    
    printf("[%s] Test 3: Empty string -> %d tokens\n", TEST_NAME, count3);
    if (count3 != 0) {
        printf("[%s] FAIL: Expected 0 tokens, got %d\n", TEST_NAME, count3);
        return 1;
    }
    
    printf("[%s] PASS\n", TEST_NAME);
    return 0;
}
