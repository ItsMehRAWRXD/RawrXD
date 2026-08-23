// test_gguf_tokenizer_bounds.cpp - Fuzz-style bounds validation for ParseGGUF
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include "gguf_embedded_tokenizer.hpp"

using namespace RawrXD;

static int g_passed = 0;
static int g_failed = 0;

void check(bool condition, const char* name) {
    if (condition) {
        printf("[PASS] %s\n", name);
        ++g_passed;
    } else {
        printf("[FAIL] %s\n", name);
        ++g_failed;
    }
}

// Build a minimal valid GGUF v3 with tokenizer.ggml.tokens metadata
std::vector<uint8_t> buildValidGGUF() {
    std::vector<uint8_t> data;
    auto appendU32 = [&](uint32_t v) {
        data.push_back(v & 0xFF);
        data.push_back((v >> 8) & 0xFF);
        data.push_back((v >> 16) & 0xFF);
        data.push_back((v >> 24) & 0xFF);
    };
    auto appendU64 = [&](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            data.push_back((v >> (i * 8)) & 0xFF);
        }
    };
    auto appendString = [&](const char* s) {
        size_t len = strlen(s);
        appendU64(len);
        for (size_t i = 0; i < len; ++i) data.push_back(s[i]);
    };

    // Magic + Version
    appendU32(0x46554747); // "GGUF"
    appendU32(3);          // version 3

    // tensorCount = 0, metadataCount = 2
    appendU64(0);
    appendU64(2);

    // Metadata 1: tokenizer.ggml.tokens (ARRAY of STRING)
    appendString("tokenizer.ggml.tokens");
    appendU32(9); // ARRAY
    appendU32(8); // STRING element type
    appendU64(3); // 3 tokens
    appendString("hello");
    appendString("world");
    appendString("test");

    // Metadata 2: tokenizer.ggml.bos_token_id (UINT32)
    appendString("tokenizer.ggml.bos_token_id");
    appendU32(4); // UINT32
    appendU32(1);

    return data;
}

// Helper lambdas for test cases
static void appendU32(std::vector<uint8_t>& data, uint32_t v) {
    data.push_back(v & 0xFF);
    data.push_back((v >> 8) & 0xFF);
    data.push_back((v >> 16) & 0xFF);
    data.push_back((v >> 24) & 0xFF);
}

static void appendU64(std::vector<uint8_t>& data, uint64_t v) {
    for (int i = 0; i < 8; ++i) data.push_back((v >> (i * 8)) & 0xFF);
}

static void appendString(std::vector<uint8_t>& data, const char* s) {
    size_t len = strlen(s);
    appendU64(data, len);
    for (size_t i = 0; i < len; ++i) data.push_back(s[i]);
}

int main() {
    printf("=== GGUF Tokenizer Bounds Validation ===\n\n");

    // Test 1: Valid GGUF parses successfully
    {
        GGUFEmbeddedTokenizer tok;
        check(tok.LoadFromGGUF("D:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"),
              "Valid real GGUF loads");
    }

    // Test 2: Truncated header (too small)
    {
        std::vector<uint8_t> data = {0x47, 0x47, 0x55, 0x46}; // "GGUF" only
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(data.data(), data.size()),
              "Truncated header rejected");
    }

    // Test 3: Wrong magic
    {
        std::vector<uint8_t> data = {0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(data.data(), data.size()),
              "Wrong magic rejected");
    }

    // Test 4: Valid magic+version but truncated metadata count
    {
        std::vector<uint8_t> data;
        appendU32(data, 0x46554747);
        appendU32(data, 3);
        // Missing tensorCount + metadataCount
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(data.data(), data.size()),
              "Truncated after magic/version rejected");
    }

    // Test 5: Metadata count too large (1M+1)
    {
        std::vector<uint8_t> data;
        appendU32(data, 0x46554747);
        appendU32(data, 3);
        appendU64(data, 0); // tensorCount
        appendU64(data, 1000001); // metadataCount > limit
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(data.data(), data.size()),
              "Excessive metadata count rejected");
    }

    // Test 6: String length overflow (claiming huge string)
    {
        std::vector<uint8_t> data;
        appendU32(data, 0x46554747);
        appendU32(data, 3);
        appendU64(data, 0); // tensorCount
        appendU64(data, 1); // metadataCount
        appendString(data, "x"); // key
        appendU32(data, 8); // STRING type
        appendU64(data, 0xFFFFFFFFFFFFFFFF); // huge length
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(data.data(), data.size()),
              "Oversized string length rejected");
    }

    // Test 7: Array element count overflow
    {
        std::vector<uint8_t> data;
        appendU32(data, 0x46554747);
        appendU32(data, 3);
        appendU64(data, 0);
        appendU64(data, 1);
        appendString(data, "tokenizer.ggml.tokens");
        appendU32(data, 9); // ARRAY
        appendU32(data, 8); // STRING elements
        appendU64(data, 100000001); // > 100M limit
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(data.data(), data.size()),
              "Excessive array count rejected");
    }

    // Test 8: Null data pointer
    {
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(nullptr, 100),
              "Null data pointer rejected");
    }

    // Test 9: Zero size
    {
        uint8_t dummy = 0;
        GGUFEmbeddedTokenizer tok;
        check(!tok.ParseGGUF(&dummy, 0),
              "Zero size rejected");
    }

    printf("\n=== Results: %d passed, %d failed ===\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
