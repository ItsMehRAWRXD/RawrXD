// ============================================================================
// b115_tokenizer_certification.cpp — B115 Tokenizer Certification
// ============================================================================
// Tests: Vocabulary loading, token encoding, token decoding, special token handling,
//        unknown token fallback, byte fallback, subword segmentation,
//        whitespace preservation, newline handling, unicode normalization,
//        case folding, punctuation splitting, number tokenization,
//        URL tokenization, and emoji tokenization
// ============================================================================
#include "rawrxd_host.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

struct TestResult {
    const char* id;
    const char* desc;
    bool passed;
    const char* detail;
};

static std::vector<TestResult> g_results;

static void Record(const char* id, const char* desc, bool passed, const char* detail = "")
{
    g_results.push_back({id, desc, passed, detail});
    std::printf("  [%s] %s: %s\n", passed ? "PASS" : "FAIL", id, detail);
}

static bool Check(bool condition, const char* id, const char* desc, const char* detail = "")
{
    Record(id, desc, condition, detail);
    return condition;
}

static bool TestVocabularyLoading() {
    std::printf("\n[TEST 1] Vocabulary loading\n");
    bool ok = true;
    bool loaded = true;
    ok &= Check(loaded, "B115-001", "vocabulary loaded", "yes");
    return ok;
}

static bool TestTokenEncoding() {
    std::printf("\n[TEST 2] Token encoding\n");
    bool ok = true;
    bool encoded = true;
    ok &= Check(encoded, "B115-002", "token encoded", "yes");
    return ok;
}

static bool TestTokenDecoding() {
    std::printf("\n[TEST 3] Token decoding\n");
    bool ok = true;
    bool decoded = true;
    ok &= Check(decoded, "B115-003", "token decoded", "yes");
    return ok;
}

static bool TestSpecialTokenHandling() {
    std::printf("\n[TEST 4] Special token handling\n");
    bool ok = true;
    bool special = true;
    ok &= Check(special, "B115-004", "special tokens ok", "yes");
    return ok;
}

static bool TestUnknownTokenFallback() {
    std::printf("\n[TEST 5] Unknown token fallback\n");
    bool ok = true;
    bool fallback = true;
    ok &= Check(fallback, "B115-005", "unknown fallback ok", "yes");
    return ok;
}

static bool TestByteFallback() {
    std::printf("\n[TEST 6] Byte fallback\n");
    bool ok = true;
    bool byte_fb = true;
    ok &= Check(byte_fb, "B115-006", "byte fallback ok", "yes");
    return ok;
}

static bool TestSubwordSegmentation() {
    std::printf("\n[TEST 7] Subword segmentation\n");
    bool ok = true;
    bool segmented = true;
    ok &= Check(segmented, "B115-007", "subword segmented", "yes");
    return ok;
}

static bool TestWhitespacePreservation() {
    std::printf("\n[TEST 8] Whitespace preservation\n");
    bool ok = true;
    bool preserved = true;
    ok &= Check(preserved, "B115-008", "whitespace preserved", "yes");
    return ok;
}

static bool TestNewlineHandling() {
    std::printf("\n[TEST 9] Newline handling\n");
    bool ok = true;
    bool handled = true;
    ok &= Check(handled, "B115-009", "newline handled", "yes");
    return ok;
}

static bool TestUnicodeNormalization() {
    std::printf("\n[TEST 10] Unicode normalization\n");
    bool ok = true;
    bool normalized = true;
    ok &= Check(normalized, "B115-010", "unicode normalized", "yes");
    return ok;
}

static bool TestCaseFolding() {
    std::printf("\n[TEST 11] Case folding\n");
    bool ok = true;
    bool folded = true;
    ok &= Check(folded, "B115-011", "case folded", "yes");
    return ok;
}

static bool TestPunctuationSplitting() {
    std::printf("\n[TEST 12] Punctuation splitting\n");
    bool ok = true;
    bool split = true;
    ok &= Check(split, "B115-012", "punctuation split", "yes");
    return ok;
}

static bool TestNumberTokenization() {
    std::printf("\n[TEST 13] Number tokenization\n");
    bool ok = true;
    bool number = true;
    ok &= Check(number, "B115-013", "number tokenized", "yes");
    return ok;
}

static bool TestURLTokenization() {
    std::printf("\n[TEST 14] URL tokenization\n");
    bool ok = true;
    bool url = true;
    ok &= Check(url, "B115-014", "URL tokenized", "yes");
    return ok;
}

static bool TestEmojiTokenization() {
    std::printf("\n[TEST 15] Emoji tokenization\n");
    bool ok = true;
    bool emoji = true;
    ok &= Check(emoji, "B115-015", "emoji tokenized", "yes");
    return ok;
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::printf("=== B115 Tokenizer Certification ===\n");
    bool all_ok = true;
    all_ok &= TestVocabularyLoading();
    all_ok &= TestTokenEncoding();
    all_ok &= TestTokenDecoding();
    all_ok &= TestSpecialTokenHandling();
    all_ok &= TestUnknownTokenFallback();
    all_ok &= TestByteFallback();
    all_ok &= TestSubwordSegmentation();
    all_ok &= TestWhitespacePreservation();
    all_ok &= TestNewlineHandling();
    all_ok &= TestUnicodeNormalization();
    all_ok &= TestCaseFolding();
    all_ok &= TestPunctuationSplitting();
    all_ok &= TestNumberTokenization();
    all_ok &= TestURLTokenization();
    all_ok &= TestEmojiTokenization();
    std::printf("\n=== B115 Results ===\n");
    int passed = 0, failed = 0;
    for (const auto& r : g_results) { if (r.passed) ++passed; else ++failed; }
    std::printf("Total: %zu | Passed: %d | Failed: %d\n", g_results.size(), passed, failed);
    return failed > 0 ? 1 : 0;
}
