// ============================================================================
// gguf_reader_realness_probe.cpp
// ============================================================================
// Proves gguf_reader_* performs real parsing instead of fabricating results.
//
// Original behaviour (all CRITICAL):
//   gguf_reader_open          -> valid=true, numTensors=42 for ANY path,
//                                fopen never called (nonexistent files "worked")
//   gguf_reader_get_tensor    -> empty body, info left uninitialised
//   gguf_reader_load_tensor   -> always nullptr
//   bpe_decode                -> literal "[tok] " for every token
//
// Builds a synthetic GGUF file with a known tensor count and verifies the
// reader reports exactly that count, resolves a real tensor, and rejects
// bogus paths.
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

extern "C" {
void* gguf_reader_open(const char* path);
void gguf_reader_close(void* handle);
uint32_t gguf_reader_num_tensors(void* handle);
void gguf_reader_get_tensor(void* handle, uint32_t idx, void* info);
void* gguf_reader_load_tensor(void* handle, const char* name);
void bpe_decode(const uint32_t* tokens, uint32_t count, char* text, uint32_t maxChars);
}

namespace
{
int g_fail = 0;

void Report(const char* name, bool ok, const std::string& detail)
{
    std::printf("%-40s %s  %s\n", name, ok ? "PASS" : "FAIL", detail.c_str());
    if (!ok) ++g_fail;
}

void PushU32(std::vector<uint8_t>& v, uint32_t x)
{
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
}

void PushU64(std::vector<uint8_t>& v, uint64_t x)
{
    for (int i = 0; i < 8; ++i) v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
}

void PushStr(std::vector<uint8_t>& v, const char* s)
{
    const uint64_t len = std::strlen(s);
    PushU64(v, len);
    for (uint64_t i = 0; i < len; ++i) v.push_back(static_cast<uint8_t>(s[i]));
}

// Build a GGUF with `tensorCount` tensors, one of which is named `witness`.
// metadataCount = 0 keeps the layout deterministic.
std::vector<uint8_t> BuildGguf(uint64_t tensorCount, uint64_t alignment)
{
    std::vector<uint8_t> v;
    v.push_back('G'); v.push_back('G'); v.push_back('U'); v.push_back('F');
    PushU32(v, 3);              // version
    PushU64(v, tensorCount);    // tensor count
    PushU64(v, 0);              // metadata count

    for (uint64_t i = 0; i < tensorCount; ++i) {
        const char* name = (i == 0) ? "witness" : "layer.weight";
        PushStr(v, name);
        PushU32(v, 1);          // n_dims
        PushU64(v, 4);          // ne[0]
        PushU32(v, 0);          // ggml type F32
        PushU64(v, i * 16);     // offset
    }

    while ((v.size() % alignment) != 0) v.push_back(0);
    // Tensor payload: a recognisable byte pattern.
    for (int i = 0; i < 64; ++i) v.push_back(static_cast<uint8_t>(0xA0 + i));
    return v;
}

bool WriteFile(const char* path, const std::vector<uint8_t>& data)
{
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    const size_t n = fwrite(data.data(), 1, data.size(), f);
    fclose(f);
    return n == data.size();
}
} // namespace

int main()
{
    // Write fixtures next to the executable so relative paths are not dependent
    // on the process working directory.
    char selfPath[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    char* slash = strrchr(selfPath, '\\');
    if (slash) *slash = '\0';

    char goodPath[MAX_PATH];
    char junkPath[MAX_PATH];
    snprintf(goodPath, sizeof(goodPath), "%s\\gguf_probe_good.gguf", selfPath);
    snprintf(junkPath, sizeof(junkPath), "%s\\gguf_probe_junk.bin", selfPath);

    // ---- 1. Real tensor count is reported, not the literal 42 -----
    const uint64_t kTensors = 5;  // deliberately different from 42
    const std::vector<uint8_t> good = BuildGguf(kTensors, 32);
    if (!WriteFile(goodPath, good)) {
        std::printf("cannot write test gguf at '%s'\n", goodPath);
        return 2;
    }

    void* h = gguf_reader_open(goodPath);
    Report("opens_real_gguf", h != nullptr, h ? "handle returned" : "null handle");
    if (h) {
        const uint32_t n = gguf_reader_num_tensors(h);
        Report("tensor_count_is_real", n == kTensors,
               "reported " + std::to_string(n) + " expected " + std::to_string(kTensors) +
                   (n == 42 ? " (FABRICATED 42)" : ""));

        // ---- 2. get_tensor populates info (was an empty body) ----
        std::vector<uint8_t> info(256, 0xAB);  // poison to detect "left untouched"
        gguf_reader_get_tensor(h, 0, info.data());
        char gotName[128] = {0};
        memcpy(gotName, info.data(), 128);
        Report("get_tensor_fills_info", strcmp(gotName, "witness") == 0,
               std::string("name='") + gotName + "'");

        // ---- 3. load_tensor resolves real data (was always nullptr) ----
        void* data = gguf_reader_load_tensor(h, "witness");
        Report("load_tensor_returns_data", data != nullptr,
               data ? "pointer into mapped file" : "nullptr");

        // ---- 4. absent tensor must NOT fabricate a pointer ----
        void* missing = gguf_reader_load_tensor(h, "no.such.tensor");
        Report("absent_tensor_returns_null", missing == nullptr,
               missing ? "FABRICATED a pointer" : "correctly null");

        gguf_reader_close(h);
    }

    // ---- 5. Nonexistent file must fail (was valid=true for any path) ----
    void* bogus = gguf_reader_open("definitely_missing_model_file.gguf");
    Report("missing_file_rejected", bogus == nullptr,
           bogus ? "returned a handle for a nonexistent file" : "correctly rejected");
    if (bogus) gguf_reader_close(bogus);

    // ---- 6. Non-GGUF content must fail ----
    {
        std::vector<uint8_t> junk(256, 0x00);
        junk[0] = 'N'; junk[1] = 'O'; junk[2] = 'T'; junk[3] = 'G';
        WriteFile(junkPath, junk);
    }
    void* junk = gguf_reader_open(junkPath);
    Report("non_gguf_rejected", junk == nullptr,
           junk ? "accepted a non-GGUF file" : "correctly rejected");
    if (junk) gguf_reader_close(junk);

    // ---- 7. bpe_decode must not emit the literal "[tok]" ----
    {
        const uint32_t toks[3] = {72, 105, 33};  // 'H','i','!'
        char text[64] = {0};
        bpe_decode(toks, 3, text, sizeof(text));
        const bool literal = strstr(text, "[tok]") != nullptr;
        Report("bpe_decode_not_literal", !literal,
               std::string("decoded='") + text + "'");

        const uint32_t hi[2] = {1000, 2000};
        char text2[64] = {0};
        bpe_decode(hi, 2, text2, sizeof(text2));
        Report("bpe_decode_high_ids_distinct",
               strstr(text2, "[tok]") == nullptr && std::strlen(text2) > 0,
               std::string("decoded='") + text2 + "'");
    }

    std::remove(goodPath);
    std::remove(junkPath);

    std::printf("\n[gguf-reader] failures=%d\n", g_fail);
    std::printf("[gguf-reader] %s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}