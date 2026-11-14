/**
 * gguf_meta_dump.cpp - print every GGUF metadata key/value pair.
 *
 * Purpose: the REAP16 GLM and Nemotron exports fail inside Ollama's bundled
 * llama.cpp with GGML_ASSERT(obj_new), while their ORIGINAL source files load
 * fine. That points at a metadata inconsistency introduced by the exporter, not
 * at an architecture gap. This tool makes the two header sets diffable.
 *
 * Build:
 *   cl /nologo /std:c++17 /EHsc /O2 tools\gguf_meta_dump.cpp /Fe:tools\gguf_meta_dump.exe
 *
 * Usage:
 *   gguf_meta_dump.exe <model.gguf> [--filter substr]
 */
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

enum GfType : uint32_t {
    GF_UINT8 = 0, GF_INT8 = 1, GF_UINT16 = 2, GF_INT16 = 3,
    GF_UINT32 = 4, GF_INT32 = 5, GF_FLOAT32 = 6, GF_BOOL = 7,
    GF_STRING = 8, GF_ARRAY = 9, GF_UINT64 = 10, GF_INT64 = 11, GF_FLOAT64 = 12,
};

struct Reader {
    const uint8_t* base = nullptr;
    size_t size = 0;
    size_t pos = 0;

    bool need(size_t n) const { return pos + n <= size; }

    template <typename T>
    T readLE() {
        if (!need(sizeof(T))) { pos = size; return T{}; }
        T v{};
        std::memcpy(&v, base + pos, sizeof(T));
        pos += sizeof(T);
        return v;
    }

    std::string readString() {
        const uint64_t n = readLE<uint64_t>();
        if (!need(static_cast<size_t>(n))) { pos = size; return {}; }
        std::string s(reinterpret_cast<const char*>(base + pos), static_cast<size_t>(n));
        pos += static_cast<size_t>(n);
        return s;
    }
};

const char* typeName(uint32_t t) {
    switch (t) {
        case GF_UINT8: return "u8";     case GF_INT8: return "i8";
        case GF_UINT16: return "u16";   case GF_INT16: return "i16";
        case GF_UINT32: return "u32";   case GF_INT32: return "i32";
        case GF_FLOAT32: return "f32";  case GF_BOOL: return "bool";
        case GF_STRING: return "str";   case GF_ARRAY: return "arr";
        case GF_UINT64: return "u64";   case GF_INT64: return "i64";
        case GF_FLOAT64: return "f64";
        default: return "?";
    }
}

// Render one scalar value. Arrays are summarised, never fully expanded: tokenizer
// arrays hold ~250k entries and would drown the interesting keys.
std::string renderValue(Reader& r, uint32_t type, bool& ok) {
    char buf[256];
    switch (type) {
        case GF_UINT8:  return std::to_string(r.readLE<uint8_t>());
        case GF_INT8:   return std::to_string(r.readLE<int8_t>());
        case GF_UINT16: return std::to_string(r.readLE<uint16_t>());
        case GF_INT16:  return std::to_string(r.readLE<int16_t>());
        case GF_UINT32: return std::to_string(r.readLE<uint32_t>());
        case GF_INT32:  return std::to_string(r.readLE<int32_t>());
        case GF_UINT64: return std::to_string(r.readLE<uint64_t>());
        case GF_INT64:  return std::to_string(r.readLE<int64_t>());
        case GF_FLOAT32: { std::snprintf(buf, sizeof(buf), "%.9g", r.readLE<float>()); return buf; }
        case GF_FLOAT64: { std::snprintf(buf, sizeof(buf), "%.17g", r.readLE<double>()); return buf; }
        case GF_BOOL:   return r.readLE<uint8_t>() ? "true" : "false";
        case GF_STRING: { const std::string s = r.readString();
                          if (s.size() > 120) return s.substr(0, 117) + "...";
                          return s; }
        case GF_ARRAY: {
            const uint32_t et = r.readLE<uint32_t>();
            const uint64_t n = r.readLE<uint64_t>();
            // Summarise: element type, count, and the first few values when the
            // element type is numeric and the array is short enough to be useful.
            std::string out = std::string(typeName(et)) + "[" + std::to_string(n) + "]";
            const bool small = n <= 12 && et != GF_STRING && et != GF_ARRAY;
            if (small) {
                out += " =";
                for (uint64_t i = 0; i < n; ++i) {
                    std::string v = renderValue(r, et, ok);
                    if (!ok) return out;
                    out += " " + v;
                }
                return out;
            }
            // Skip the payload without materialising it.
            for (uint64_t i = 0; i < n; ++i) {
                if (!r.need(0)) { ok = false; return out; }
                switch (et) {
                    case GF_UINT8: case GF_INT8: case GF_BOOL: r.pos += 1; break;
                    case GF_UINT16: case GF_INT16: r.pos += 2; break;
                    case GF_UINT32: case GF_INT32: case GF_FLOAT32: r.pos += 4; break;
                    case GF_UINT64: case GF_INT64: case GF_FLOAT64: r.pos += 8; break;
                    case GF_STRING: r.readString(); break;
                    default: ok = false; return out;
                }
            }
            return out;
        }
        default: ok = false; return "<unprintable>";
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: %s <model.gguf> [--filter substr]\n", argv[0]);
        return 2;
    }
    const std::string path = argv[1];
    std::string filter;
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--filter") == 0 && i + 1 < argc) filter = argv[++i];
    }

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) { std::printf("META_FAIL stage=open\n"); return 3; }
    // _ftelli64: plain ftell returns a 32-bit long on Windows, so any model over
    // 2 GiB wrapped negative and was reported as empty.
#ifdef _WIN32
    _fseeki64(f, 0, SEEK_END);
    const long long fsz = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
#else
    fseeko(f, 0, SEEK_END);
    const long long fsz = static_cast<long long>(ftello(f));
    fseeko(f, 0, SEEK_SET);
#endif
    if (fsz <= 0) { std::fclose(f); std::printf("META_FAIL stage=empty\n"); return 3; }

    // Only the header region is needed: metadata ends before tensor data.
    const size_t kMaxHeader = 512ull * 1024 * 1024;
    const size_t want = static_cast<size_t>(fsz) < kMaxHeader ? static_cast<size_t>(fsz) : kMaxHeader;
    std::vector<uint8_t> buf(want);
    const size_t got = std::fread(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    if (got < 24) { std::printf("META_FAIL stage=short_read\n"); return 3; }

    Reader r{buf.data(), got, 0};
    const uint32_t magic = r.readLE<uint32_t>();
    if (magic != 0x46554747u) { std::printf("META_FAIL stage=magic\n"); return 4; }
    const uint32_t version = r.readLE<uint32_t>();
    const uint64_t n_tensors = r.readLE<uint64_t>();
    const uint64_t n_kv = r.readLE<uint64_t>();
    std::printf("FILE=%s\nVERSION=%u N_TENSORS=%llu N_KV=%llu\n",
                path.c_str(), version,
                static_cast<unsigned long long>(n_tensors),
                static_cast<unsigned long long>(n_kv));

    size_t shown = 0;
    bool ok = true;
    for (uint64_t i = 0; i < n_kv && ok; ++i) {
        const std::string key = r.readString();
        if (r.pos >= r.size) { ok = false; break; }
        const uint32_t t = r.readLE<uint32_t>();
        const size_t val_off = r.pos;
        const std::string val = renderValue(r, t, ok);
        if (!ok) break;
        if (!filter.empty() && key.find(filter) == std::string::npos) continue;
        std::printf("KV %s : %s = %s   @value_offset=%zu\n",
                    key.c_str(), typeName(t), val.c_str(), val_off);
        ++shown;
    }
    std::printf("META_DUMP_END ok=%d shown=%zu parsed_pos=%zu\n",
                ok ? 1 : 0, shown, r.pos);
    return ok ? 0 : 5;
}