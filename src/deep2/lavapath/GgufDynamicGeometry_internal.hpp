// GgufDynamicGeometry_internal.hpp — shared parse scratch (not public API)
#pragma once
#include "GgufDynamicGeometry.hpp"
#include <cstdint>
#include <string>
#include <cstdio>

namespace Deep2 {
namespace gguf_geom {

constexpr uint32_t kMagic = 0x46554747;
constexpr uint64_t kMaxKv = 1ull << 20;
constexpr uint64_t kMaxTensors = 1ull << 20;
constexpr uint64_t kMaxStr = 1ull << 24;
constexpr uint64_t kMaxArr = 1ull << 28;

struct Scratch {
    GgufDynamicGeometry* out = nullptr;
    std::string arch;
    uint32_t layers = 0, hidden = 0, ffn = 0, heads = 0, kvHeads = 0;
    uint32_t headDim = 0, context = 0, ropeDim = 0;
    float rmsEps = 0.f, ropeBase = 0.f, ropeScaling = 0.f;
    bool hasArch = false, hasLayers = false, hasHidden = false, hasFfn = false;
    bool hasHeads = false, hasKvHeads = false, hasContext = false;
    bool hasRmsEps = false, hasRopeBase = false, hasRopeDim = false;
    bool hasRopeScaling = false, hasKeyLength = false;
    bool headDimDerived = false;
};

uint32_t rdU32(FILE* f, bool& ok);
uint64_t rdU64(FILE* f, bool& ok);
float rdF32(FILE* f, bool& ok);
double rdF64(FILE* f, bool& ok);
std::string rdStr(FILE* f, bool& ok);
bool skipVal(FILE* f, uint32_t t, bool& ok);
bool endsWith(const std::string& s, const char* suf);
bool isBlockCountKey(const std::string& key);
bool isHeadCountKey(const std::string& k);
void applyKey(Scratch& s, const std::string& key, const std::string& val);
bool finalize(Scratch& s);
bool block(Scratch& s, const char* at, const char* why);
bool isPerLayerGeomArrayKey(const std::string& key);
bool takeArrayMaxPositive(FILE* f, Scratch& s, const std::string& key,
                          bool& ok);
bool applyRopeBaseArchCompat(Scratch& s);

} // namespace gguf_geom
} // namespace Deep2
