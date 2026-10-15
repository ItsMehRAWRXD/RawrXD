// ============================================================================
// Integration tests: the input-validation boundary as applied to the real
// model loader (GGUFLoader::Open), plus the metadata-truncation fix.
//
// These are NOT unit tests of the sanitizer in isolation (tests/
// test_input_sanitizer.cpp covers that). They prove that wiring the sanitizer
// into GGUFLoader actually changes runtime behaviour for hostile inputs, and
// that a legitimate minimal model still loads.
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#  define _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#endif

#include "test_harness.h"
#include "gguf_loader.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// ---- Minimal GGUF writer ---------------------------------------------------
constexpr uint32_t kMagic = 0x46554747u;   // "GGUF"
constexpr uint32_t kVersion = 3;

void putU32(std::vector<uint8_t>& b, uint32_t v)
{
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFFu));
}

void putU64(std::vector<uint8_t>& b, uint64_t v)
{
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFFu));
}

void putStr(std::vector<uint8_t>& b, const std::string& s)
{
    putU64(b, s.size());
    b.insert(b.end(), s.begin(), s.end());
}

/// GGUF value type codes used here.
enum GgufType : uint32_t {
    GGUF_U32 = 4,
    GGUF_STRING = 8,
    GGUF_U64 = 10,
};

const std::string& tmpDir()
{
    static const std::string d =
        (fs::temp_directory_path() / "rawrxd_loader_tests").generic_string();
    return d;
}

std::string freshPath(const char* name)
{
    static std::error_code ec;
    fs::create_directories(fs::u8path(tmpDir()), ec);
    std::string p = tmpDir() + "/" + name;
    fs::remove(fs::u8path(p), ec);
    return p;
}

void writeBytes(const std::string& path, const std::vector<uint8_t>& bytes)
{
    std::ofstream f(fs::u8path(path), std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

/// Header-only GGUF v3: enough for GGUFLoader::Open() to succeed.
void writeHeaderOnly(const std::string& path)
{
    std::vector<uint8_t> b;
    putU32(b, kMagic);
    putU32(b, kVersion);
    putU64(b, 0);   // tensor count
    putU64(b, 0);   // metadata kv count
    writeBytes(path, b);
}

/// Header + one numeric metadata KV of the given type/value.
/// Used to exercise the uint32 truncation fix in ParseMetadata().
void writeWithU64Kv(const std::string& path, const std::string& key, uint64_t value)
{
    std::vector<uint8_t> b;
    putU32(b, kMagic);
    putU32(b, kVersion);
    putU64(b, 0);   // tensor count
    putU64(b, 1);   // one metadata kv
    putStr(b, key);
    putU32(b, GGUF_U64);
    putU64(b, value);
    writeBytes(path, b);
}

/// Header + one uint32 metadata KV (the legitimate encoding).
void writeWithU32Kv(const std::string& path, const std::string& key, uint32_t value)
{
    std::vector<uint8_t> b;
    putU32(b, kMagic);
    putU32(b, kVersion);
    putU64(b, 0);   // tensor count
    putU64(b, 1);   // one metadata kv
    putStr(b, key);
    putU32(b, GGUF_U32);
    putU32(b, value);
    writeBytes(path, b);
}

} // anonymous namespace

// ============================================================================
// Rejections: hostile or malformed inputs must fail closed
// ============================================================================

TEST(GGUFLoaderHardening, RejectsDisallowedExtension) {
    const std::string p = freshPath("model_payload.exe");
    // A file with a valid GGUF header but an INVALID extension: the extension
    // allow-list must stop it before anything reads the contents.
    writeHeaderOnly(p);

    GGUFLoader loader;
    CHECK_FALSE(loader.Open(p));
    CHECK_FALSE(loader.GetLastOpenError().empty());
    // The reason must name the security policy, not a generic I/O failure.
    CHECK(loader.GetLastOpenError().find("BadExtension") != std::string::npos);
}

TEST(GGUFLoaderHardening, RejectsNulByteInPath) {
    GGUFLoader loader;
    const std::string malicious(std::string(freshPath("real_model.gguf")) + std::string("\0.exe", 5), 0);
    CHECK_FALSE(loader.Open(malicious));
    CHECK(loader.GetLastOpenError().find("NullByte") != std::string::npos);
}

TEST(GGUFLoaderHardening, RejectsControlCharacterInPath) {
    GGUFLoader loader;
    const std::string p = tmpDir() + std::string("/mod\x01" "el.gguf");
    CHECK_FALSE(loader.Open(p));
    CHECK(loader.GetLastOpenError().find("ControlChar") != std::string::npos);
}

TEST(GGUFLoaderHardening, RejectsOverlongPath) {
    GGUFLoader loader;
    const std::string p = "C:/" + std::string(5000, 'a') + ".gguf";
    CHECK_FALSE(loader.Open(p));
    CHECK(loader.GetLastOpenError().find("TooLong") != std::string::npos);
}

TEST(GGUFLoaderHardening, RejectsRelativeModelPath) {
    GGUFLoader loader;
    CHECK_FALSE(loader.Open("relative/model.gguf"));
    CHECK(loader.GetLastOpenError().find("NotAllowed") != std::string::npos);
}

TEST(GGUFLoaderHardening, RejectsMissingFileWithAReason) {
    GGUFLoader loader;
    const std::string p = freshPath("does_not_exist.gguf");
    CHECK_FALSE(loader.Open(p));
    CHECK(loader.GetLastOpenError().find("IoError") != std::string::npos);
    CHECK(loader.GetLastOpenError().find(p) != std::string::npos);
}

TEST(GGUFLoaderHardening, RejectsDirectoryAsModel) {
    GGUFLoader loader;
    // The temp directory is absolute but is not a model file.
    std::error_code ec;
    const std::string d = tmpDir();
    fs::create_directories(fs::u8path(d), ec);
    CHECK_FALSE(loader.Open(d));
    CHECK_FALSE(loader.GetLastOpenError().empty());
}

// ============================================================================
// Acceptance: a legitimate model must still load
// ============================================================================

TEST(GGUFLoaderHardening, AcceptsValidMinimalGguf) {
    const std::string p = freshPath("valid_minimal.gguf");
    writeHeaderOnly(p);

    GGUFLoader loader;
    CHECK(loader.Open(p));
    CHECK(loader.GetLastOpenError().empty());   // success clears the reason
    CHECK(loader.GetHeader().magic == kMagic);
    CHECK_EQ(loader.GetHeader().version, static_cast<uint32_t>(3));
    CHECK(loader.Close());
}

TEST(GGUFLoaderHardening, ClearsReasonAfterSuccessfulOpen) {
    const std::string bad = freshPath("bad.exe");
    writeHeaderOnly(bad);
    const std::string good = freshPath("good.gguf");
    writeHeaderOnly(good);

    GGUFLoader loader;
    CHECK_FALSE(loader.Open(bad));
    CHECK_FALSE(loader.GetLastOpenError().empty());
    // A subsequent successful open must not inherit the stale failure reason.
    CHECK(loader.Open(good));
    CHECK(loader.GetLastOpenError().empty());
}

TEST(GGUFLoaderHardening, AcceptsInRangeU32Metadata) {
    const std::string p = freshPath("in_range_dim.gguf");
    // 4096 is the normal encoding for llama.embedding_length.
    writeWithU32Kv(p, "llama.embedding_length", 4096);

    GGUFLoader loader;
    CHECK(loader.Open(p));
    CHECK(loader.ParseMetadata());
    CHECK_EQ(loader.GetMetadata().embedding_dim, static_cast<uint32_t>(4096));
}

// ============================================================================
// The truncation fix: file-controlled uint64 must not silently narrow
// ============================================================================

TEST(GGUFLoaderHardening, RejectsOutOfRangeU64MetadataInsteadOfTruncating) {
    const std::string p = freshPath("out_of_range_dim.gguf");
    // The old code assigned this directly into a uint32_t, silently becoming 8.
    // Now it must be refused.
    writeWithU64Kv(p, "llama.embedding_length", 0x100000008ULL);

    GGUFLoader loader;
    CHECK(loader.Open(p));
    bool threw = false;
    try {
        loader.ParseMetadata();
    } catch (const std::exception&) {
        threw = true;   // ParseMetadata reports the out-of-range value
    }
    CHECK(threw);
}

TEST(GGUFLoaderHardening, AcceptsMaxU32MetadataValue) {
    const std::string p = freshPath("max_u32_dim.gguf");
    // Exactly UINT32_MAX must still be accepted: the guard rejects only values
    // that genuinely cannot be represented, not merely large ones.
    //
    // NOTE: this asserts the GUARD's contract (no throw) rather than the final
    // value of meta.vocab_size. ParseMetadata() runs GGUFVocabResolver
    // afterwards, which may legitimately override a detected field - that is
    // separate behaviour, not the truncation guard.
    writeWithU64Kv(p, "llama.vocab_size",
                   static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()));

    GGUFLoader loader;
    CHECK(loader.Open(p));
    bool threw = false;
    try {
        loader.ParseMetadata();
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK_FALSE(threw);   // representable value must not be rejected
}

extern "C" int runGGUFLoaderHardeningSuite()
{
    return RUN_ALL_TESTS();
}
