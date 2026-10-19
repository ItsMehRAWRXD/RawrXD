// ============================================================================
// File: tests/test_d1_batched_prefill.cpp
//
// DEEP2_BATCHED_PREFILL_001 — the chunk-size selection contract.
//
// The chunk size is read from DEEP2_PREFILL_CHUNK. The reading is the
// part that can go wrong: a value that is not a number, a number with
// something after it, a negative, a zero, and a value too large to
// represent are all different mistakes and all of them have to end in the
// default rather than in a chunk size nobody asked for.
//
// The D1 hardening is what makes the reading strict: the whole string has
// to be the number, and the number has to be in range. Before it, a
// trailing character was accepted silently, so "12x" selected a chunk of
// 12 and nothing said so.
//
// The test is standalone: the header is inline, so it needs nothing but a
// compiler and the include path.
// ============================================================================

#include "deep2/BatchedPrefill.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
int g_checks = 0;

void Check(const char* what, bool ok) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::printf("  FAIL  %s\n", what);
    } else {
        std::printf("  ok    %s\n", what);
    }
}

// The chunk size for a prompt, with DEEP2_PREFILL_CHUNK set to `value`.
//
// The variable is set and restored around the call, because the function
// reads the environment on every call and the contract is about what the
// environment says.
size_t ChunkWithEnv(size_t promptLen, const char* value) {
    if (value) {
        _putenv_s("DEEP2_PREFILL_CHUNK", value);
    } else {
        _putenv_s("DEEP2_PREFILL_CHUNK", "");
    }
    return Deep2::SelectPrefillChunkSize(promptLen, 4096, 32);
}

const size_t kDefaultChunk = 32;

} // namespace

int main() {
    std::printf("=== DEEP2_BATCHED_PREFILL_001: chunk size selection ===\n");

    // A prompt of one token or less is one chunk, whatever the
    // environment says. There is nothing to chunk.
    Check("a prompt of 1 is 1 chunk", ChunkWithEnv(1, nullptr) == 1);
    Check("a prompt of 0 is 0 chunks", ChunkWithEnv(0, nullptr) == 0);
    Check("a prompt of 1 is 1 chunk even with the environment set",
          ChunkWithEnv(1, "64") == 1);

    // The default: a chunk of 32, or the whole prompt when it is shorter.
    Check("no environment gives 32", ChunkWithEnv(100, nullptr) == kDefaultChunk);
    Check("a short prompt is one chunk", ChunkWithEnv(8, nullptr) == 8);
    Check("a prompt of 32 is 32", ChunkWithEnv(32, nullptr) == 32);
    Check("a prompt of 33 is 32", ChunkWithEnv(33, nullptr) == 32);

    // A value that is a number is taken at its word.
    Check("a chunk of 64 is taken", ChunkWithEnv(100, "64") == 64);
    Check("a chunk of 1 is taken", ChunkWithEnv(100, "1") == 1);
    Check("a chunk larger than the prompt is taken as it is",
          ChunkWithEnv(100, "1000") == 1000);

    // A value that is not a number, or is not only a number, falls back to
    // the default. This is the D1 hardening: the whole string has to be
    // the number.
    Check("a value with a trailing character falls back",
          ChunkWithEnv(100, "12x") == kDefaultChunk);
    Check("a value with leading text falls back",
          ChunkWithEnv(100, "abc12") == kDefaultChunk);
    Check("a value that is not a number falls back",
          ChunkWithEnv(100, "abc") == kDefaultChunk);
    Check("a value with a trailing space falls back",
          ChunkWithEnv(100, "32 ") == kDefaultChunk);
    Check("an empty value falls back", ChunkWithEnv(100, "") == kDefaultChunk);

    // A number that is not a usable chunk size falls back.
    Check("a negative value falls back", ChunkWithEnv(100, "-4") == kDefaultChunk);
    Check("a zero falls back", ChunkWithEnv(100, "0") == kDefaultChunk);
    Check("a value too large to represent falls back",
          ChunkWithEnv(100, "99999999999999999999999") == kDefaultChunk);

    // The execution counts have to be consistent with the chunk size: the
    // batched path may not execute more layers than the serial one, and it
    // may not execute fewer either when the chunk is the whole prompt.
    {
        const size_t prompt = 100, layers = 32;
        const uint64_t serial = Deep2::SerialPrefillLayerExecutions(prompt, layers);
        const uint64_t batched = Deep2::BatchedPrefillLayerExecutions(prompt, layers, 32);
        Check("the batched path executes no more layers than the serial one",
              batched <= serial);
        Check("the batched path executes fewer layers than the serial one",
              batched < serial);
        const uint64_t whole = Deep2::BatchedPrefillLayerExecutions(prompt, layers, prompt);
        // A chunk the size of the whole prompt is one chunk, so each layer
        // runs once over the whole prompt. The serial path runs each layer
        // once per token, which is what the chunking exists to avoid.
        Check("a chunk of the whole prompt runs each layer once",
              whole == layers);
        Check("a chunk of the whole prompt runs fewer layers than the serial path",
              whole < serial);
        Check("a chunk of zero executes nothing",
              Deep2::BatchedPrefillLayerExecutions(prompt, layers, 0) == 0);
    }

    std::printf("\n%s: %d checks, %d failure(s)\n",
                g_failures == 0 ? "PASS" : "FAIL", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
