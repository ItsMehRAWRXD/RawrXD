#pragma once
// Product owns candidate semantics. Win32 owns presentation.
// Copy only: text, position/range, generation, identity. No ranking/infer.
#include <cstdint>
#include <cstring>
#include <string>
namespace rawr::product {

enum GhostSource : uint8_t { GhostSrcNone = 0, GhostSrcProduct = 1, GhostSrcLegacy = 2 };

struct ProductGhostCopy {
    const char* text = nullptr;
    uint64_t gen = 0;
    uint64_t id = 0;
    int line = 0;
    int col = 0;
};

struct Win32GhostView {
    std::string content;
    bool visible = false;
    bool pending = false;
    bool accepted = false;
    int line = -1;
    int col = -1;
    uint64_t gen = 0;
    uint64_t id = 0;
    uint8_t source = GhostSrcNone;
};

inline uint64_t GhostIdent(const char* t) {
    uint32_t h = 2166136261u;
    if (!t) return 0;
    while (*t) {
        h ^= (uint8_t)*t++;
        h *= 16777619u;
    }
    return h;
}

inline bool BindProductGhost(Win32GhostView& v, const ProductGhostCopy& c) {
    if (!c.text || !c.text[0] || c.gen == 0) return false;
    v.content = c.text;
    v.gen = c.gen;
    v.id = c.id ? c.id : GhostIdent(c.text);
    v.line = c.line;
    v.col = c.col;
    v.source = GhostSrcProduct;
    v.visible = true;
    v.pending = false;
    v.accepted = false;
    return true;
}

inline bool BindLegacyGhost(Win32GhostView& v, const char*) {
    (void)v;
    return false;
}

inline void ReflectGhostGen(Win32GhostView& v, uint64_t docGen) {
    if (v.gen != docGen) v.visible = false;
}

inline bool GhostViewMayPaint(const Win32GhostView& v, uint64_t docGen) {
    return v.source == GhostSrcProduct && v.visible && v.gen == docGen &&
           !v.content.empty();
}

} // namespace rawr::product
