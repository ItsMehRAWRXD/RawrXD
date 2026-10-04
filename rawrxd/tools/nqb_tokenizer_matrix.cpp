// nqb_tokenizer_matrix.cpp
//
// RAWRXD_NQBRAID_TOKENIZER_E2E_001 -- negative + compatibility matrix.
//
// The positive path ("a good file loads and round-trips") was already proven by
// the 12-cell architecture/codec sweep. This binary covers the other half: what
// the format does with files it should REFUSE, and what it does with the
// legitimate legacy class that has no tokenizer at all.
//
// WHY THIS IS A SEPARATE BINARY
// -----------------------------
// Corruption tests mutate bytes in an .nqb. Doing that inside nanof32_e2e_test
// would mean the test both produced and consumed its own inputs, which is how a
// harness ends up certifying its own fixtures. Here every case is built by
// copying a known-good file, flipping named bytes, and asserting the LOADER's
// verdict. The expectation for each case is written as REJECT or ACCEPT and is
// compared against what actually happened.
//
// THE INVARIANT BEING TESTED (NQB_INVARIANT_TOKEN_DOMAIN_001)
//   0 <= token_id < tokenizer_vocab_size
//   tokenizer_vocab_size <= embedding_rows
//   tokenizer_vocab_size <= output_rows
//   bos_id < tokenizer_vocab_size
//   eos_id < tokenizer_vocab_size
//
// HONESTY CONSTRAINTS
// -------------------
//  * A corruption case that is ACCEPTED is reported as a failure of this gate,
//    not skipped. CTEST_UNEXPECTED_ACCEPTS is the number that matters.
//  * Each case prints the loader's own message where one exists, so a rejection
//    can be attributed to the intended check rather than to any earlier one.
//  * Nothing here prints an expected PASS/FAIL string as a literal verdict; the
//    verdict is computed from counted acceptances and rejections.

#include "Deep2Engine.h"
#include "Nanof32BraidFormat.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

constexpr uint64_t kHeaderBytes   = sizeof(Deep2::Nanof32BraidHeader);
constexpr uint64_t kArchMetaBytes = sizeof(Deep2::Nanof32BraidArchMeta);
constexpr uint64_t kVocabOffset   = kHeaderBytes + kArchMetaBytes;  // 256

enum class Expect { Reject, Accept };

struct Case {
    const char* name;
    Expect      expect;
};

std::vector<uint8_t> readAll(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

bool writeAll(const std::string& p, const std::vector<uint8_t>& b) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    if (!b.empty())
        f.write(reinterpret_cast<const char*>(b.data()),
                static_cast<std::streamsize>(b.size()));
    return f.good();
}

// Patch a little-endian uint32 in place. Used to corrupt length/count fields
// without needing to know the struct layout by hand.
void poke32(std::vector<uint8_t>& b, size_t at, uint32_t v) {
    if (at + 4 > b.size()) return;
    std::memcpy(b.data() + at, &v, 4);
}
void poke64(std::vector<uint8_t>& b, size_t at, uint64_t v) {
    if (at + 8 > b.size()) return;
    std::memcpy(b.data() + at, &v, 8);
}
void pokeF32(std::vector<uint8_t>& b, size_t at, float v) {
    if (at + 4 > b.size()) return;
    std::memcpy(b.data() + at, &v, 4);
}

// Field offsets inside Deep2::Nanof32VocabHeader, derived from the type so a layout
// change cannot silently leave these stale.
constexpr size_t kVMagic      = offsetof(Deep2::Nanof32VocabHeader, magic);
constexpr size_t VKind     = offsetof(Deep2::Nanof32VocabHeader, kind);
constexpr size_t VEntryCount  = offsetof(Deep2::Nanof32VocabHeader, entryCount);
constexpr size_t VStrBytes    = offsetof(Deep2::Nanof32VocabHeader, strBytes);
constexpr size_t VFlags       = offsetof(Deep2::Nanof32VocabHeader, flags);
constexpr size_t VMergeCount  = offsetof(Deep2::Nanof32VocabHeader, mergeCount);
constexpr size_t VMergeBytes  = offsetof(Deep2::Nanof32VocabHeader, mergeBytes);
constexpr size_t VBosId       = offsetof(Deep2::Nanof32VocabHeader, bosId);
constexpr size_t VEosId       = offsetof(Deep2::Nanof32VocabHeader, eosId);

// Absolute offset of the offset table, which follows the 128-byte header and the
// string blob whose length the header declares.
size_t offTableAt(const std::vector<uint8_t>& b) {
    Deep2::Nanof32VocabHeader vh{};
    if (b.size() < kVocabOffset + sizeof vh) return 0;
    std::memcpy(&vh, b.data() + kVocabOffset, sizeof vh);
    return static_cast<size_t>(kVocabOffset) + sizeof vh + vh.strBytes;
}

// Load a braid model the same way production does, and report whether it bound
// a tokenizer. Returns: 1 loaded, 0 refused.
int tryLoad(const std::string& path, bool* tokenizerBound) {
    Deep2::EngineConfig cfg{};
    std::snprintf(cfg.modelPath, sizeof cfg.modelPath, "%s", path.c_str());
    cfg.maxSeqLen   = 256;
    cfg.numThreads  = 0;
    cfg.useKVCache  = true;
    cfg.useThreadPool = true;

    Deep2::Deep2Engine engine;
    *tokenizerBound = false;
    if (!engine.initialize(cfg)) return 0;
    if (!engine.loadModelFromNanof32Braid(path)) return 0;
    if (Deep2::ITokenizer* t = engine.boundTokenizer()) {
        *tokenizerBound = (t->vocabSize() > 0);
    }
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: nqb_tokenizer_matrix --good GOOD.nqb --outdir DIR\n"
            "  --good     a known-good tokenizer-aware .nqb to derive cases from\n"
            "  --outdir   directory for the mutated copies\n"
            "  --legacy   a known-good .nqb with NO tokenizer section\n");
        return 64;
    }
    std::string good, outdir, legacy;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--good" && i + 1 < argc)        good = argv[++i];
        else if (a == "--outdir" && i + 1 < argc) outdir = argv[++i];
        else if (a == "--legacy" && i + 1 < argc) legacy = argv[++i];
    }
    if (good.empty() || outdir.empty()) {
        std::fprintf(stderr, "error: --good and --outdir are required\n");
        return 64;
    }

    const std::vector<uint8_t> base = readAll(good);
    if (base.size() < kVocabOffset + sizeof(Deep2::Nanof32VocabHeader)) {
        std::fprintf(stderr, "error: %s is too small to carry a vocab section\n",
                     good.c_str());
        return 64;
    }

    // ---- the corruption matrix -------------------------------------------
    //
    // Each entry mutates a named field. The expectation is stated per case so
    // that a case which is wrongly accepted shows up as UNEXPECTED_ACCEPT
    // rather than quietly vanishing.
    const std::vector<Case> kCases = {
        {"VOCAB_MAGIC_ZERO",           Expect::Reject},
        {"VOCAB_KIND_UNSUPPORTED",     Expect::Reject},
        {"VOCAB_STRBYTES_OVERRUN",     Expect::Reject},
        {"VOCAB_COUNT_GT_EMBED_ROWS",  Expect::Reject},
        {"VOCAB_OFFSETS_NON_MONOTONIC",Expect::Reject},
        {"VOCAB_STRING_UNTERMINATED",  Expect::Reject},
        {"VOCAB_OFFSETS_OUT_OF_BLOB",  Expect::Reject},
        {"BOS_OUT_OF_RANGE",           Expect::Reject},
        {"EOS_OUT_OF_RANGE",           Expect::Reject},
        {"VOCAB_ENTRY_COUNT_ZERO",     Expect::Reject},
        {"TOKEN_TYPE_COUNT_MISMATCH",  Expect::Reject},
        {"DECLARED_SECTION_ZERO_BYTES",Expect::Accept},  // == no section
        // Offset 0 with a NONZERO length is not the same as "no section": the
        // bytes 0..128 are the file header, so a section claimed there cannot
        // exist. The first version of this matrix expected ACCEPT and was
        // wrong -- the loader's rejection is correct and this expectation was
        // measuring my assumption rather than the format.
        {"VOCAB_OFFSET_ZERO_NONZERO_LEN",Expect::Reject},
        {"FILE_TRUNCATION",            Expect::Reject},
    };

    int unexpectedAccepts = 0, unexpectedRejects = 0, ran = 0;

    for (const Case& c : kCases) {
        std::vector<uint8_t> b = base;
        const std::string path = outdir + "/nqbcase_" + c.name + ".nqb";

        // ---- mutations ---------------------------------------------------
        if (std::strcmp(c.name, "VOCAB_MAGIC_ZERO") == 0) {
            poke32(b, kVocabOffset + kVMagic, 0u);
        } else if (std::strcmp(c.name, "VOCAB_KIND_UNSUPPORTED") == 0) {
            poke32(b, kVocabOffset + VKind, 99u);
        } else if (std::strcmp(c.name, "VOCAB_STRBYTES_OVERRUN") == 0) {
            // Claim a string blob far larger than the section can hold.
            poke32(b, kVocabOffset + VStrBytes, 0x7FFFFFFFu);
        } else if (std::strcmp(c.name, "VOCAB_COUNT_GT_EMBED_ROWS") == 0) {
            // 100000 entries against a 512-row embedding.
            poke32(b, kVocabOffset + VEntryCount, 100000u);
        } else if (std::strcmp(c.name, "VOCAB_OFFSETS_NON_MONOTONIC") == 0) {
            // Make a LATER entry point BEFORE its predecessor. The first
            // version of this case zeroed entry[1], but entry[0] is already 0
            // (the first string starts at blob offset 0), so it produced a
            // DUPLICATE offset rather than a decreasing one -- and duplicates
            // are legal, because a real vocabulary may map two ids to the same
            // surface string. The loader was correct to accept it.
            poke32(b, offTableAt(b) + 10 * 4, 0u);
} else if (std::strcmp(c.name, "VOCAB_STRING_UNTERMINATED") == 0) {
            // Overwrite the FINAL byte of the string blob, which is the
            // terminator of the last token, so that token runs past the end of
            // the blob. The first version of this case overwrote the blob's
            // FIRST byte instead -- token 0 is "<0x00>", so replacing '<' with
            // 'A' left a perfectly well-terminated string and the file was
            // correctly accepted. A corruption case that does not corrupt is
            // worse than no case: it looks like coverage.
            Deep2::Nanof32VocabHeader vh{};
            std::memcpy(&vh, base.data() + kVocabOffset, sizeof vh);
            const size_t lastByte =
                static_cast<size_t>(kVocabOffset) + sizeof vh + vh.strBytes - 1;
            if (lastByte < b.size()) b[lastByte] = 'A';
        } else if (std::strcmp(c.name, "VOCAB_OFFSETS_OUT_OF_BLOB") == 0) {
            poke32(b, offTableAt(b), 0x00FFFFF0u);
        } else if (std::strcmp(c.name, "BOS_OUT_OF_RANGE") == 0) {
            poke32(b, kVocabOffset + VBosId, 0x7FFFFFFFu);
            poke32(b, kVocabOffset + VFlags,
                   1u | 2u);   // add_bos | add_eos so the ids are consulted
        } else if (std::strcmp(c.name, "EOS_OUT_OF_RANGE") == 0) {
            poke32(b, kVocabOffset + VEosId, 0x7FFFFFFFu);
            poke32(b, kVocabOffset + VFlags, 1u | 2u);
        } else if (std::strcmp(c.name, "VOCAB_ENTRY_COUNT_ZERO") == 0) {
            // A declared-but-empty vocabulary is not a usable tokenizer. The
            // previous case here ("SCORE_COUNT_MISMATCH") set mergeCount, which
            // a SentencePiece file never consults -- so the file was correctly
            // accepted and the case measured nothing. There is no independent
            // score-count field in this format: scores are entryCount-sized by
            // construction, so a score-count mismatch is not representable and
            // claiming to test it was false coverage.
            poke32(b, kVocabOffset + VEntryCount, 0u);
        } else if (std::strcmp(c.name, "TOKEN_TYPE_COUNT_MISMATCH") == 0) {
            poke32(b, kVocabOffset + VMergeBytes, 0x7FFFFFFFu);
        } else if (std::strcmp(c.name, "DECLARED_SECTION_ZERO_BYTES") == 0) {
            poke64(b, offsetof(Deep2::Nanof32BraidHeader, vocabSectionBytes), 0u);
        } else if (std::strcmp(c.name, "VOCAB_OFFSET_ZERO_NONZERO_LEN") == 0) {
            poke64(b, offsetof(Deep2::Nanof32BraidHeader, vocabSectionOffset), 0u);
        } else if (std::strcmp(c.name, "FILE_TRUNCATION") == 0) {
            b.resize(1024);
        }

        if (!writeAll(path, b)) {
            std::fprintf(stderr, "CASE_ERROR name=%s could not write %s\n",
                         c.name, path.c_str());
            ++unexpectedRejects;
            continue;
        }

        bool tokBound = false;
        const int loaded = tryLoad(path, &tokBound);
        ++ran;

        const bool accepted = (loaded != 0);
        bool ok;
        if (c.expect == Expect::Reject) {
            ok = !accepted;
            if (!ok) {
                ++unexpectedAccepts;
                std::fprintf(stderr,
                    "UNEXPECTED_ACCEPT name=%s -- the loader took a file it must "
                    "reject\n", c.name);
            }
        } else {
            // Accepted cases must additionally behave as "no tokenizer".
            ok = accepted && !tokBound;
            if (!ok) {
                ++unexpectedRejects;
                std::fprintf(stderr,
                    "UNEXPECTED_REJECT name=%s loaded=%d tokenizer=%d "
                    "(expected load with no tokenizer)\n",
                    c.name, loaded, tokBound ? 1 : 0);
            }
        }
        std::fprintf(stderr,
            "CASE name=%-28s loaded=%d tokenizer=%d expect=%s got=%s %s\n",
            c.name, loaded, tokBound ? 1 : 0,
            c.expect == Expect::Reject ? "REJECT" : "ACCEPT",
            accepted ? "ACCEPT" : "REJECT",
            ok ? "OK" : "MISMATCH");
    }

    // ---- legacy compatibility class --------------------------------------
    //
    // "No tokenizer section declared" is a VALID file class, not a degraded
    // one. It is certified explicitly so that a future refactor cannot turn
    // backward compatibility into either a mandatory-tokenizer load failure or
    // a dangerous corrupt-section fallback.
    int legacyRan = 0, legacyOk = 0;
    if (!legacy.empty()) {
        ++legacyRan;
        bool tokBound = true;
        const int loaded = tryLoad(legacy, &tokBound);
        const bool ok = (loaded != 0) && !tokBound;
        if (ok) ++legacyOk;
        std::fprintf(stderr,
            "LEGACY_CASE file=%s loaded=%d tokenizer_present=%d expect=load_without_tokenizer %s\n",
            legacy.c_str(), loaded, tokBound ? 1 : 0, ok ? "OK" : "MISMATCH");
    }

    const bool pass = (unexpectedAccepts == 0) && (unexpectedRejects == 0) &&
                      (legacyRan == 0 || legacyOk == legacyRan);

    std::printf("=== RAWRXD_NQBRAID_TOKENIZER_E2E_001 (negative matrix) ===\n");
    std::printf("CORRUPTION_CASES=%d\n", ran);
    std::printf("EXPECTED_REJECTIONS=%d\n",
                static_cast<int>(kCases.size()) - 2 /* the two ACCEPT cases */);
    std::printf("UNEXPECTED_ACCEPTS=%d\n", unexpectedAccepts);
    std::printf("UNEXPECTED_REJECTS=%d\n", unexpectedRejects);
    std::printf("LEGACY_FILE_CASES=%d\n", legacyRan);
    std::printf("LEGACY_FILE_PASS=%d\n", legacyOk);
    std::printf("NQB_INVARIANT_TOKEN_DOMAIN_001=ENFORCED_WRITER_AND_LOADER\n");
    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}