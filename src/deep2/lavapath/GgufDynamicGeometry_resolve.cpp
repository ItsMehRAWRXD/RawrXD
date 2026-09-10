// GgufDynamicGeometry_resolve.cpp — public resolve entry (ONE authority)
#include "GgufDynamicGeometry_internal.hpp"
#include <cstring>

namespace Deep2 {
namespace gguf_geom {

static bool readKv(FILE* f, Scratch& s, bool& ok) {
    for (uint64_t i = 0; i < s.out->metadataCount && ok; ++i) {
        std::string key = rdStr(f, ok);
        uint32_t vt = rdU32(f, ok);
        if (!ok) break;
        std::string val;
        switch (vt) {
        case 0: { uint8_t v=0; ok=fread(&v,1,1,f)==1; val=std::to_string((unsigned)v); break; }
        case 1: { int8_t v=0; ok=fread(&v,1,1,f)==1; val=std::to_string((int)v); break; }
        case 2: { uint16_t v=0; ok=fread(&v,1,2,f)==2; val=std::to_string(v); break; }
        case 3: { int16_t v=0; ok=fread(&v,1,2,f)==2; val=std::to_string(v); break; }
        case 4: val = std::to_string(rdU32(f, ok)); break;
        case 5: { int32_t v=0; ok=fread(&v,1,4,f)==4; val=std::to_string(v); break; }
        case 6: val = std::to_string(rdF32(f, ok)); break;
        case 7: { uint8_t v=0; ok=fread(&v,1,1,f)==1; val=v?"true":"false"; break; }
        case 8: val = rdStr(f, ok); break;
        case 9:
            if (isPerLayerGeomArrayKey(key)) {
                if (!takeArrayMaxPositive(f, s, key, ok)) ok = false;
            } else if (!skipVal(f, 9, ok)) {
                ok = false;
            }
            val = "[array]";
            break;
        case 10: val = std::to_string(rdU64(f, ok)); break;
        case 11: { int64_t v=0; ok=fread(&v,1,8,f)==8; val=std::to_string(v); break; }
        case 12: val = std::to_string(rdF64(f, ok)); break;
        default: ok = false; break;
        }
        if (!ok) break;
        if (vt != 9) applyKey(s, key, val);
        /* vt==9: takeArrayMaxPositive already applied, or skipped. */
    }
    return ok;
}

} // namespace gguf_geom

bool GgufResolveDynamicGeometry(const char* path, GgufDynamicGeometry* out) {
    using namespace gguf_geom;
    if (!out) return false;
    std::memset(out, 0, sizeof(*out));
    Scratch s;
    s.out = out;
    if (!path || !path[0])
        return block(s, "GGUF_MAGIC", "empty path");

    FILE* f = nullptr;
#if defined(_MSC_VER)
    if (fopen_s(&f, path, "rb") != 0 || !f)
        return block(s, "GGUF_MAGIC", "cannot open model file");
#else
    f = fopen(path, "rb");
    if (!f) return block(s, "GGUF_MAGIC", "cannot open model file");
#endif

    bool ok = true;
    uint32_t magic = rdU32(f, ok);
    if (!ok || magic != kMagic) {
        fclose(f);
        return block(s, "GGUF_MAGIC", "magic != GGUF");
    }
    out->magicOk = 1;
    out->version = rdU32(f, ok);
    out->tensorCount = rdU64(f, ok);
    out->metadataCount = rdU64(f, ok);
    if (!ok) {
        fclose(f);
        return block(s, "GGUF_VERSION", "header read truncated");
    }
    if (out->version < 1 || out->version > 3) {
        fclose(f);
        return block(s, "GGUF_VERSION", "unsupported GGUF version");
    }
    if (out->tensorCount == 0 || out->tensorCount > kMaxTensors ||
        out->metadataCount == 0 || out->metadataCount > kMaxKv) {
        fclose(f);
        return block(s, "METADATA_BOUNDS", "tensor/metadata count out of bounds");
    }
    out->boundsOk = 1;
    if (!readKv(f, s, ok)) {
        fclose(f);
        return block(s, "METADATA_BOUNDS", "KV walk truncated or invalid type");
    }
    fclose(f);
    return finalize(s);
}

} // namespace Deep2
