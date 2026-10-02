// GgufMetadataProbe.cpp — RAWRXD_GGUF_METADATA_PROBE_001
// Real GGUF header parser.
//
// Layout (GGUF v2/v3):
//   char   magic[4]   = "GGUF"
//   u32    version
//   u64    tensor_count
//   u64    metadata_kv_count
//   kv[metadata_kv_count]
//     key:   u64 length + bytes
//     type:  u32
//     value: depends on type
//
// Only the header region is read; tensor data is never touched.

#include "models/GgufMetadataProbe.h"
#include "deep2/ReceiptAuthority.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace rawrxd::models
{
    namespace {

    // GGUF value type ids.
    enum : uint32_t {
        T_UINT8 = 0, T_INT8 = 1, T_UINT16 = 2, T_INT16 = 3,
        T_UINT32 = 4, T_INT32 = 5, T_FLOAT32 = 6, T_BOOL = 7,
        T_STRING = 8, T_ARRAY = 9, T_UINT64 = 10, T_INT64 = 11, T_FLOAT64 = 12
    };

    // Fixed byte width of a scalar type; 0 means variable length.
    uint32_t scalarWidth(uint32_t t) {
        switch (t) {
            case T_UINT8: case T_INT8: case T_BOOL: return 1;
            case T_UINT16: case T_INT16: return 2;
            case T_UINT32: case T_INT32: case T_FLOAT32: return 4;
            case T_UINT64: case T_INT64: case T_FLOAT64: return 8;
            default: return 0;
        }
    }

    struct Cursor {
        const std::vector<unsigned char>& buf;
        size_t pos = 0;
        bool   bad = false;

        explicit Cursor(const std::vector<unsigned char>& b) : buf(b) {}

        bool need(size_t n) const { return pos + n <= buf.size(); }

        uint8_t  u8()  { if (!need(1)) { bad = true; return 0; }  return buf[pos++]; }
        uint16_t u16() { if (!need(2)) { bad = true; return 0; }
                         uint16_t v = uint16_t(buf[pos]) | (uint16_t(buf[pos+1]) << 8);
                         pos += 2; return v; }
        uint32_t u32() { if (!need(4)) { bad = true; return 0; }
                         uint32_t v = uint32_t(buf[pos]) | (uint32_t(buf[pos+1]) << 8) |
                                      (uint32_t(buf[pos+2]) << 16) | (uint32_t(buf[pos+3]) << 24);
                         pos += 4; return v; }
        uint64_t u64() { if (!need(8)) { bad = true; return 0; }
                         uint64_t v = 0;
                         for (int i = 7; i >= 0; --i) v = (v << 8) | buf[pos + size_t(i)];
                         pos += 8; return v; }
        std::string str() {
            const uint64_t n = u64();
            if (bad || n > buf.size() || !need(size_t(n))) { bad = true; return {}; }
            std::string s(reinterpret_cast<const char*>(buf.data() + pos), size_t(n));
            pos += size_t(n);
            return s;
        }
        // Skip a value of the given type, recursing into arrays.
        void skipValue(uint32_t type) {
            if (bad) return;
            if (type == T_STRING) { (void)str(); return; }
            if (type == T_ARRAY) {
                const uint32_t elem = u32();
                const uint64_t n    = u64();
                if (bad) return;
                for (uint64_t i = 0; i < n; ++i) skipValue(elem);
                return;
            }
            const uint32_t w = scalarWidth(type);
            if (w == 0) { bad = true; return; }
            pos += w;
            if (pos > buf.size()) bad = true;
        }
    };

    GgufInfo g_last;

    // general.file_type is a ggml_ftype enum, not a human string. These are the
    // values ggml defines; an unlisted value is reported numerically rather
    // than guessed at, so an unknown encoding can never read as a known one.
    const char* ggmlFtypeName(uint32_t ft) {
        switch (ft) {
            case  0: return "F32";
            case  1: return "F16";
            case  2: return "Q4_0";
            case  3: return "Q4_1";
            case  7: return "Q8_0";
            case  8: return "Q5_0";
            case  9: return "Q5_1";
            case 10: return "Q2_K";
            case 11: return "Q3_K_S";
            case 12: return "Q3_K_M";
            case 13: return "Q3_K_L";
            case 14: return "Q4_K_S";
            case 15: return "Q4_K_M";
            case 16: return "Q5_K_S";
            case 17: return "Q5_K_M";
            case 18: return "Q6_K";
            case 19: return "IQ2_XXS";
            case 20: return "IQ2_XS";
            case 21: return "IQ3_XXS";
            case 22: return "IQ1_S";
            case 23: return "IQ4_NL";
            case 24: return "IQ3_S";
            case 25: return "IQ2_S";
            case 26: return "IQ2_M";
            case 27: return "IQ4_XS";
            case 28: return "IQ1_M";
            case 29: return "BF16";
            case 30: return "Q4_0_4_4";
            case 31: return "Q4_0_4_8";
            case 32: return "Q4_0_8_8";
            case 33: return "TQ1_0";
            case 34: return "TQ2_0";
            default: {
                static thread_local std::string buf;
                buf = "FTYPE_" + std::to_string(ft);
                return buf.c_str();
            }
        }
    }

    // A modern GGUF header is not small. The tokenizer block alone (token strings
    // plus token_type, plus merges) runs to several MiB at a 256K
    // vocabulary, so a fixed 8 MiB window desynchronised the KV walk on
    // gemma3 and newer models and silently yielded arch= but quant="" with
    // valid=false. Escalate the window until the walk completes.
    GgufInfo probeWithWindow(const std::string& path, std::size_t window) {
        GgufInfo info;

        std::ifstream in(path, std::ios::binary);
        if (!in) { info.error = "cannot open " + path; return info; }

        std::vector<unsigned char> buf(window);
        in.read(reinterpret_cast<char*>(buf.data()), std::streamsize(buf.size()));
        buf.resize(size_t(in.gcount()));
        in.close();

        if (buf.size() < 24) { info.error = "file shorter than a GGUF header"; return info; }
        if (std::memcmp(buf.data(), "GGUF", 4) != 0) {
            info.error = "bad magic (not a GGUF file)";
            return info;
        }

        Cursor c(buf);
        c.pos = 4;
        info.version         = c.u32();
        info.tensorCount     = c.u64();
        info.metadataKvCount = c.u64();
        if (c.bad) { info.error = "truncated header"; return info; }

        // Walk the KV block, keeping only the keys we understand.
        const uint64_t limit = info.metadataKvCount < 100000 ? info.metadataKvCount : 100000;
        for (uint64_t i = 0; i < limit && !c.bad; ++i) {
            const std::string key = c.str();
            if (c.bad) break;
            const uint32_t type = c.u32();
            if (c.bad) break;

            if (type == T_STRING) {
                const std::string val = c.str();
                if (c.bad) break;
                if (key == "general.architecture") info.architecture = val;
                else if (key == "general.name")      info.name = val;
                else if (key.size() > 20 && key.compare(key.size() - 20, 20,
                         ".quantization_type") == 0) info.quantization = val;
            } else if (type == T_UINT32 && key == "general.file_type") {
                // Quantization is normally stored here, as a UINT32 enum --
                // not as a "<arch>.quantization_type" string, which most real
                // files do not carry. Reading only the string form left
                // quantization empty for every model, so the dump column
                // showed "?" across the whole catalog.
                const uint32_t ft = c.u32();
                if (c.bad) break;
                info.quantization = ggmlFtypeName(ft);
                info.fileType = ft;
            } else {
                if (key == "general.architecture" || key == "general.name") {
                    // We wanted these as strings but they are not; skip cleanly.
                }
                c.skipValue(type);
            }
        }

        if (c.bad) { info.error = "metadata walk desynchronised (header exceeds window)"; return info; }

        std::error_code ec;
        info.fileSizeBytes = std::filesystem::file_size(std::filesystem::path(path), ec);
        info.valid = true;
        return info;
    }

    } // namespace

    GgufInfo probeGgufFile(const std::string& path) {
        // Escalate the window until the KV walk completes. A partial read is
        // reported as a failure rather than returned as a half-populated
        // record, so a caller can never mistake a truncated header for
        // "this model simply has no quantization".
        static const std::size_t kWindows[] = {
            8u << 20, 32u << 20, 128u << 20, 512u << 20
        };
        GgufInfo last;
        for (std::size_t w : kWindows) {
            last = probeWithWindow(path, w);
            if (last.valid) { last.error.clear(); return last; }
            // Stop escalating once the window covers the whole file.
            std::error_code ec;
            const auto sz = std::filesystem::file_size(std::filesystem::path(path), ec);
            if (!ec && w >= sz) break;
        }
        return last;
    }

    void probeGgufMetadata(const std::string& modelPath) { g_last = probeGgufFile(modelPath); }

    // probeAllGgufMetadata() is defined in ModelCatalogAuthority.cpp, which
    // owns the record walk. It is not redefined here.

    int         getGgufVersion()      { return int(g_last.version); }
    std::string getGgufArch()         { return g_last.architecture; }
    std::string getGgufName()         { return g_last.name; }
    std::string getQuantization()     { return g_last.quantization; }
    uint64_t    getFileSizeBytes()    { return g_last.fileSizeBytes; }

    void writeGgufMetadataProbeReceipt() {
        const std::string path = "_rawr_gguf_metadata_probe_receipt.txt";
        receipt::beginGate(path, "RAWRXD_GGUF_METADATA_PROBE_001");
        receipt::writeKeyValueInt(path, "GGUF_VALID", g_last.valid ? 1 : 0);
        receipt::writeKeyValueInt(path, "GGUF_VERSION", int(g_last.version));
        receipt::writeKeyValueInt(path, "TENSOR_COUNT", (int64_t)g_last.tensorCount);
        receipt::writeKeyValueInt(path, "METADATA_KV_COUNT", (int64_t)g_last.metadataKvCount);
        receipt::writeKeyValue(path, "GGUF_ARCH", g_last.architecture);
        receipt::writeKeyValue(path, "GGUF_NAME", g_last.name);
        receipt::writeKeyValue(path, "QUANTIZATION", g_last.quantization);
        receipt::writeKeyValueInt(path, "FILE_SIZE_BYTES", (int64_t)g_last.fileSizeBytes);
        receipt::writeKeyValue(path, "PARSE_ERROR", g_last.error);
        receipt::endGate(path, g_last.valid ? "PASS" : "FAIL");
    }
}
