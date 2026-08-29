/*
 * llama_ref_parity_probe.cpp — EXTERNAL measuring stick for PARITY-CERT-001
 *
 * NOT a Deep2 dependency. Separate process only.
 * Deep2 remains deep2_inference_deps=NONE (no Ollama / no llama link into Deep2).
 *
 * Build: tools/parity_ref/build_llama_ref_probe.ps1
 * Usage: llama_ref_parity_probe.exe [model.gguf] [prompt] [n_predict]
 */
#include "llama.h"
#include "ggml.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
static void load_ggml_backends() {
    // Prebuilt llama-direct: ggml_backend_load_* lives on ggml.dll; the
    // registry lives in ggml-base.dll. Load vulkan/llama.dll first so both
    // map as its dependencies (one registry), then call load_all on ggml.dll.
    SetDllDirectoryA(R"(F:\~dev\llama-direct\vulkan)");
    if (!LoadLibraryA(R"(F:\~dev\llama-direct\vulkan\llama.dll)")) {
        std::fprintf(stderr, "REF_BACKEND=FAIL LoadLibrary vulkan/llama.dll\n");
        return;
    }
    HMODULE h = GetModuleHandleA("ggml.dll");
    if (!h) {
        h = LoadLibraryA(R"(F:\~dev\llama-direct\vulkan\ggml.dll)");
    }
    if (!h) {
        std::fprintf(stderr, "REF_BACKEND=FAIL cannot resolve ggml.dll\n");
        return;
    }
    char modPath[MAX_PATH];
    GetModuleFileNameA(h, modPath, MAX_PATH);
    std::fprintf(stderr, "REF_BACKEND_DLL=%s\n", modPath);

    using load_fn = bool (*)(const char*);
    auto loadOne = reinterpret_cast<load_fn>(GetProcAddress(h, "ggml_backend_load"));
    if (!loadOne) {
        std::fprintf(stderr, "REF_BACKEND=FAIL ggml_backend_load missing\n");
        return;
    }
    // CPU-only measuring stick: Vulkan schedule introduces near-miss float drift.
    const char* cpuCandidates[] = {
        R"(F:\~dev\llama-direct\vulkan\ggml-cpu-zen4.dll)",
        R"(F:\~dev\llama-direct\vulkan\ggml-cpu-x64.dll)",
        nullptr
    };
    bool loaded = false;
    for (int i = 0; cpuCandidates[i]; ++i) {
        if (loadOne(cpuCandidates[i])) {
            std::fprintf(stderr, "REF_BACKEND_CPU=%s\n", cpuCandidates[i]);
            loaded = true;
            break;
        }
    }
    if (!loaded) {
        std::fprintf(stderr, "REF_BACKEND=FAIL cpu backend load\n");
    }
}
#else
static void load_ggml_backends() {}
#endif

static void printIds(const char* key, const std::vector<llama_token>& ids) {
    std::printf("%s=", key);
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) std::printf(",");
        std::printf("%d", static_cast<int>(ids[i]));
    }
    std::printf("\n");
}

static const char* stageDumpDir() {
    return std::getenv("RAWRXD_STAGE_DUMP_DIR");
}

static void digestVec(const char* key, int pos, const float* data, int n);

// Gate A: overwrite kqv_out with clean PRE_O authority.
// Prefer RAWRXD_FORCE_PRE_O_EXPAND_V=1 → PRE_O := GQA_expand(V) per layer @ pos0.
// Fallback: RAWRXD_FORCE_PRE_O_BIN (2048 f32) applied to kqv_out-0 only.
static std::vector<float> g_forcePreO;
static bool g_forcePreOLoaded = false;
static int g_forcePreOHits = 0;
static constexpr int kMaxForceLayers = 32;
static constexpr int kNq = 32, kNkv = 4, kHd = 64;
static std::vector<float> g_layerV[kMaxForceLayers]; // pos0 V stash for expand

static void gqaExpand(const float* v, float* out) {
    const int group = kNq / kNkv;
    for (int qh = 0; qh < kNq; ++qh) {
        const int kv = qh / group;
        std::memcpy(out + qh * kHd, v + kv * kHd, (size_t)kHd * sizeof(float));
    }
}

static bool loadForcePreO() {
    if (g_forcePreOLoaded) return !g_forcePreO.empty();
    g_forcePreOLoaded = true;
    const char* p = std::getenv("RAWRXD_FORCE_PRE_O_BIN");
    if (!p || !p[0]) return false;
    FILE* f = std::fopen(p, "rb");
    if (!f) {
        std::fprintf(stderr, "FORCE_PRE_O=FAIL open %s\n", p);
        return false;
    }
    g_forcePreO.resize(2048);
    const size_t n = std::fread(g_forcePreO.data(), sizeof(float), 2048, f);
    std::fclose(f);
    if (n != 2048) {
        std::fprintf(stderr, "FORCE_PRE_O=FAIL read n=%zu want=2048\n", n);
        g_forcePreO.clear();
        return false;
    }
    std::printf("FORCE_PRE_O=LOADED path=%s n=2048\n", p);
    fflush(stdout);
    return true;
}

static int parseLayerSuffix(const char* name, const char* prefix) {
    const size_t plen = std::strlen(prefix);
    if (std::strncmp(name, prefix, plen) != 0) return -1;
    char* end = nullptr;
    long v = std::strtol(name + plen, &end, 10);
    if (end == name + plen || v < 0) return -1;
    return (int)v;
}

// Gate A (FFN): overwrite ffn_norm-L with frozen Deep2 FFN_NORM_L bytes so
// subsequent ffn_gate / ffn_up mul_mat share identical operands.
static std::vector<float> g_forceFfnNorm;
static bool g_forceFfnNormLoaded = false;
static int g_forceFfnNormHits = 0;
static int g_forceFfnNormLayer = -1;

// Same-source FFN_INP: overwrite ffn_inp-L before RMSNorm so FFN_NORM/GATE
// consume Deep2's frozen post-attn residual (TODO_L10_FFN_INP_SAME_SOURCE).
static std::vector<float> g_forceFfnInp;
static bool g_forceFfnInpLoaded = false;
static int g_forceFfnInpHits = 0;
static int g_forceFfnInpLayer = -1;

static bool loadForceFfnNorm() {
    if (g_forceFfnNormLoaded) return !g_forceFfnNorm.empty();
    g_forceFfnNormLoaded = true;
    const char* p = std::getenv("RAWRXD_FORCE_FFN_NORM_BIN");
    if (!p || !p[0]) return false;
    if (const char* lyr = std::getenv("RAWRXD_FORCE_FFN_NORM_LAYER"))
        g_forceFfnNormLayer = std::atoi(lyr);
    else
        g_forceFfnNormLayer = 10;
    FILE* f = std::fopen(p, "rb");
    if (!f) {
        std::fprintf(stderr, "FORCE_FFN_NORM=FAIL open %s\n", p);
        return false;
    }
    g_forceFfnNorm.resize(2048);
    const size_t n = std::fread(g_forceFfnNorm.data(), sizeof(float), 2048, f);
    std::fclose(f);
    if (n != 2048) {
        std::fprintf(stderr, "FORCE_FFN_NORM=FAIL read n=%zu want=2048\n", n);
        g_forceFfnNorm.clear();
        return false;
    }
    std::printf("FORCE_FFN_NORM=LOADED path=%s n=2048 layer=%d\n", p, g_forceFfnNormLayer);
    fflush(stdout);
    return true;
}

static bool loadForceFfnInp() {
    if (g_forceFfnInpLoaded) return !g_forceFfnInp.empty();
    g_forceFfnInpLoaded = true;
    const char* p = std::getenv("RAWRXD_FORCE_FFN_INP_BIN");
    if (!p || !p[0]) return false;
    if (const char* lyr = std::getenv("RAWRXD_FORCE_FFN_INP_LAYER"))
        g_forceFfnInpLayer = std::atoi(lyr);
    else
        g_forceFfnInpLayer = 10;
    FILE* f = std::fopen(p, "rb");
    if (!f) {
        std::fprintf(stderr, "FORCE_FFN_INP=FAIL open %s\n", p);
        return false;
    }
    g_forceFfnInp.resize(2048);
    const size_t n = std::fread(g_forceFfnInp.data(), sizeof(float), 2048, f);
    std::fclose(f);
    if (n != 2048) {
        std::fprintf(stderr, "FORCE_FFN_INP=FAIL read n=%zu want=2048\n", n);
        g_forceFfnInp.clear();
        return false;
    }
    std::printf("FORCE_FFN_INP=LOADED path=%s n=2048 layer=%d\n", p, g_forceFfnInpLayer);
    fflush(stdout);
    return true;
}

static void maybeForceFfnNorm(struct ggml_tensor* t) {
    if (!t || !t->data || t->type != GGML_TYPE_F32) return;
    if (!loadForceFfnNorm()) return;
    const int layer = parseLayerSuffix(t->name, "ffn_norm-");
    if (layer < 0 || layer != g_forceFfnNormLayer || t->ne[0] != 2048) return;
    const int n_tok = (int)(t->ne[1] > 0 ? t->ne[1] : 1);
    const size_t stride = t->nb[1] / sizeof(float);
    const bool allCols = (std::getenv("RAWRXD_FORCE_FFN_NORM_ALL") != nullptr);
    const int nWrite = allCols ? n_tok : 1;
    for (int i = 0; i < nWrite; ++i) {
        float* col = (float*)t->data + (size_t)i * stride;
        std::memcpy(col, g_forceFfnNorm.data(), 2048 * sizeof(float));
    }
    ++g_forceFfnNormHits;
    std::printf("FORCE_FFN_NORM=APPLIED ffn_norm-%d cols=%d/%d hit=%d\n",
                layer, nWrite, n_tok, g_forceFfnNormHits);
    fflush(stdout);
}

static void maybeForceFfnInp(struct ggml_tensor* t) {
    if (!t || !t->data || t->type != GGML_TYPE_F32) return;
    if (!loadForceFfnInp()) return;
    const int layer = parseLayerSuffix(t->name, "ffn_inp-");
    if (layer < 0 || layer != g_forceFfnInpLayer || t->ne[0] != 2048) return;
    const int n_tok = (int)(t->ne[1] > 0 ? t->ne[1] : 1);
    const size_t stride = t->nb[1] / sizeof(float);
    const bool allCols = (std::getenv("RAWRXD_FORCE_FFN_INP_ALL") != nullptr);
    const int nWrite = allCols ? n_tok : 1;
    for (int i = 0; i < nWrite; ++i) {
        float* col = (float*)t->data + (size_t)i * stride;
        std::memcpy(col, g_forceFfnInp.data(), 2048 * sizeof(float));
    }
    ++g_forceFfnInpHits;
    std::printf("FORCE_FFN_INP=APPLIED ffn_inp-%d cols=%d/%d hit=%d\n",
                layer, nWrite, n_tok, g_forceFfnInpHits);
    fflush(stdout);
}

static void maybeForceKqvOut(struct ggml_tensor* t) {
    if (!t || !t->data || t->type != GGML_TYPE_F32) return;
    const int layer = parseLayerSuffix(t->name, "kqv_out-");
    if (layer < 0 || t->ne[0] != 2048) return;

    std::vector<float> forced(2048);
    const bool expandV = (std::getenv("RAWRXD_FORCE_PRE_O_EXPAND_V") != nullptr);
    if (expandV) {
        if (layer >= kMaxForceLayers || g_layerV[layer].size() != (size_t)(kNkv * kHd)) {
            std::printf("FORCE_PRE_O_EXPAND_V=SKIP layer=%d (no V stash)\n", layer);
            return;
        }
        gqaExpand(g_layerV[layer].data(), forced.data());
    } else if (layer == 0 && loadForcePreO()) {
        forced = g_forcePreO;
    } else {
        return;
    }

    const int n_tok = (int)(t->ne[1] > 0 ? t->ne[1] : 1);
    const size_t stride = t->nb[1] / sizeof(float);
    const bool allCols = (std::getenv("RAWRXD_FORCE_PRE_O_ALL") != nullptr);
    const int nWrite = allCols ? n_tok : 1;
    for (int i = 0; i < nWrite; ++i) {
        float* col = (float*)t->data + (size_t)i * stride;
        std::memcpy(col, forced.data(), 2048 * sizeof(float));
    }
    ++g_forcePreOHits;
    std::printf("FORCE_PRE_O=APPLIED kqv_out-%d cols=%d/%d hit=%d mode=%s\n",
                layer, nWrite, n_tok, g_forcePreOHits, expandV ? "EXPAND_V" : "BIN");
    if (std::getenv("RAWRXD_REF_CB_SPARSE") == nullptr) {
        char key[64];
        std::snprintf(key, sizeof(key), "ATTN_PRE_O_FORCED_%d", layer);
        digestVec(key, 0, forced.data(), 2048);
    }
    fflush(stdout);
}

// Collision-proof dump identity:
//   <side>_<stage>_pos<p>_layer<L>_{full|head<h>}_n<N>_seq<SSS>.bin
// Sidecar: same stem + .manifest.txt  (dtype, nelem, nbytes, layer, pos, head, fnv, l2)
static void writeStageDump(
    const char* side,
    const char* stage,
    int pos,
    int layer,
    int head,          // -1 => full contiguous vector
    const float* data,
    int n,
    std::uint64_t fnv,
    double l2)
{
    const char* dumpDir = stageDumpDir();
    if (!dumpDir || !data || n <= 0) return;

    char safeStage[128];
    std::snprintf(safeStage, sizeof(safeStage), "%s", stage);
    for (char* p = safeStage; *p; ++p) {
        if (*p == '/' || *p == '\\' || *p == ':' || *p == '*' || *p == '-' || *p == ' ') *p = '_';
    }

    static int s_seq = 0;
    const int seq = ++s_seq;
    char headTag[32];
    if (head < 0) std::snprintf(headTag, sizeof(headTag), "full");
    else std::snprintf(headTag, sizeof(headTag), "head%d", head);

    char stem[1024];
    std::snprintf(stem, sizeof(stem),
                  "%s\\%s_%s_pos%d_layer%d_%s_n%d_seq%03d",
                  dumpDir, side, safeStage, pos, layer, headTag, n, seq);

    char binPath[1100], manPath[1100];
    std::snprintf(binPath, sizeof(binPath), "%s.bin", stem);
    std::snprintf(manPath, sizeof(manPath), "%s.manifest.txt", stem);

    // Refuse overwrite — identity collision must fail loudly.
    FILE* probe = std::fopen(binPath, "rb");
    if (probe) {
        std::fclose(probe);
        std::printf("[STAGE_DUMP_COLLISION] path=%s REFUSING_OVERWRITE\n", binPath);
        fflush(stdout);
        return;
    }

    FILE* f = std::fopen(binPath, "wb");
    if (!f) {
        std::printf("[STAGE_DUMP_FAIL] open %s\n", binPath);
        return;
    }
    const size_t nbytes = (size_t)n * sizeof(float);
    if (std::fwrite(data, 1, nbytes, f) != nbytes) {
        std::fclose(f);
        std::printf("[STAGE_DUMP_FAIL] write %s\n", binPath);
        return;
    }
    std::fclose(f);

    FILE* mf = std::fopen(manPath, "w");
    if (mf) {
        std::fprintf(mf,
            "side=%s\n"
            "stage=%s\n"
            "pos=%d\n"
            "layer=%d\n"
            "head=%d\n"
            "head_tag=%s\n"
            "dtype=f32\n"
            "nelem=%d\n"
            "nbytes=%zu\n"
            "fnv=%016llx\n"
            "l2=%.17g\n"
            "seq=%d\n"
            "path=%s\n",
            side, stage, pos, layer, head, headTag, n, nbytes,
            (unsigned long long)fnv, l2, seq, binPath);
        std::fclose(mf);
    }

    // Append to directory-level manifest index
    char idxPath[1024];
    std::snprintf(idxPath, sizeof(idxPath), "%s\\DUMP_MANIFEST.jsonl", dumpDir);
    FILE* idx = std::fopen(idxPath, "a");
    if (idx) {
        std::fprintf(idx,
            "{\"side\":\"%s\",\"stage\":\"%s\",\"pos\":%d,\"layer\":%d,\"head\":%d,"
            "\"nelem\":%d,\"nbytes\":%zu,\"fnv\":\"%016llx\",\"l2\":%.17g,\"seq\":%d,\"bin\":\"%s\"}\n",
            side, stage, pos, layer, head, n, nbytes,
            (unsigned long long)fnv, l2, seq, binPath);
        std::fclose(idx);
    }

    std::printf("[STAGE_DUMP] %s nelem=%d head=%d seq=%03d fnv=%016llx\n",
                binPath, n, head, seq, (unsigned long long)fnv);
    fflush(stdout);
}

static void digestVecEx(const char* key, int pos, int layer, int head,
                        const float* data, int n);

static void digestVec(const char* key, int pos, const float* data, int n) {
    digestVecEx(key, pos, /*layer*/0, /*head*/-1, data, n);
}

static void digestVecEx(const char* key, int pos, int layer, int head,
                        const float* data, int n) {
    if (!data || n <= 0) {
        std::printf("[STAGE_DIGEST] side=llama key=%s pos=%d MISSING\n", key, pos);
        return;
    }
    double minV = 0, maxV = 0, ss = 0, sum = 0, maxAbs = 0;
    bool any = false;
    std::uint64_t h = 14695981039346656037ull;
    int nf = 0;
    for (int i = 0; i < n; ++i) {
        const float v = data[i];
        std::uint32_t bits = 0;
        if (!std::isfinite(v)) {
            ++nf;
            bits = 0xFFFFFFFFu;
        } else {
            std::memcpy(&bits, &v, 4);
            const double d = (double)v;
            if (!any) { minV = maxV = d; any = true; }
            else { if (d < minV) minV = d; if (d > maxV) maxV = d; }
            sum += d;
            ss += d * d;
            const double a = (d < 0.0) ? -d : d;
            if (a > maxAbs) maxAbs = a;
        }
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    const double l2 = std::sqrt(ss);
    std::printf("[STAGE_DIGEST] side=llama key=%s pos=%d layer=%d head=%d n=%d l2=%.9e max_abs=%.9e min=%.9e max=%.9e sum=%.9e fnv=%016llx nf=%d\n",
                key, pos, layer, head, n, l2, maxAbs, minV, maxV, sum,
                (unsigned long long)h, nf);
    fflush(stdout);
    writeStageDump("llama", key, pos, layer, head, data, n, h, l2);
}

// Layer-output bisect: ask for key nodes. Opt-in: RAWRXD_REF_CB_EVAL=1
// NOTE: enabling this can change scheduling numerics enough to flip the BOS tip;
// use only for activation bisect, not tip certification.
static bool cbEval(struct ggml_tensor* t, bool ask, void* /*user_data*/) {
    if (!t || !t->name[0]) return false;
    const char* name = t->name;
    const bool listAll = (std::getenv("RAWRXD_REF_CB_LIST") != nullptr);
    const bool expandV = (std::getenv("RAWRXD_FORCE_PRE_O_EXPAND_V") != nullptr);
    const bool sparseMode = (std::getenv("RAWRXD_REF_CB_SPARSE") != nullptr);
    static bool s_sparseParsed = false;
    static bool s_sparseLayers[64] = {};
    if (sparseMode && !s_sparseParsed) {
        s_sparseParsed = true;
        const char* p = std::getenv("RAWRXD_REF_CB_SPARSE");
        while (p && *p) {
            while (*p == ' ' || *p == ',') ++p;
            if (!*p) break;
            char* end = nullptr;
            long v = std::strtol(p, &end, 10);
            if (end == p) break;
            if (v >= 0 && v < 64) s_sparseLayers[v] = true;
            p = end;
        }
        std::printf("REF_CB_SPARSE=1 layers=");
        for (int i = 0; i < 64; ++i) if (s_sparseLayers[i]) std::printf("%d,", i);
        std::printf("\n");
        fflush(stdout);
    }
    const bool isQ = (std::strncmp(name, "Qcur", 4) == 0);
    const bool isK = (std::strncmp(name, "Kcur", 4) == 0);
    const bool isV = (std::strncmp(name, "Vcur", 4) == 0);
    const bool isKqv = (std::strncmp(name, "kqv_out-", 8) == 0);
    int maxLayer = 1;
    if (const char* p = std::getenv("RAWRXD_REF_CB_MAX_LAYER")) maxLayer = std::atoi(p);
    else if (sparseMode) maxLayer = 21;
    auto layerOf = [&](const char* prefix) -> int {
        return parseLayerSuffix(name, prefix);
    };
    const int lyrAttnNorm = layerOf("attn_norm-");
    const int lyrAttnOut = layerOf("attn_out-");
    const int lyrFfnInp = layerOf("ffn_inp-");
    const int lyrFfnNorm = layerOf("ffn_norm-");
    const int lyrFfnOut = layerOf("ffn_out-");
    const int lyrFfnGate = layerOf("ffn_gate-");
    const int lyrFfnUp = layerOf("ffn_up-");
    const int lyrFfnAct = layerOf("ffn_swiglu-");
    const int lyrLout = layerOf("l_out-");
    const int lyrKqv = layerOf("kqv_out-");
    const int lyrQkv = (isQ || isK || isV) ? (
        (std::strcmp(name, "Qcur") == 0 || std::strcmp(name, "Kcur") == 0 || std::strcmp(name, "Vcur") == 0)
            ? 0
            : parseLayerSuffix(name, isQ ? "Qcur-" : (isK ? "Kcur-" : "Vcur-")))
        : -1;

    const bool forceFfnNorm = (std::getenv("RAWRXD_FORCE_FFN_NORM_BIN") != nullptr);
    int forceFfnLayer = 10;
    if (const char* p = std::getenv("RAWRXD_FORCE_FFN_NORM_LAYER")) forceFfnLayer = std::atoi(p);
    const bool forceFfnInp = (std::getenv("RAWRXD_FORCE_FFN_INP_BIN") != nullptr);
    int forceFfnInpLayer = 10;
    if (const char* p = std::getenv("RAWRXD_FORCE_FFN_INP_LAYER")) forceFfnInpLayer = std::atoi(p);

    bool want = listAll ||
        (std::strcmp(name, "result_norm") == 0) ||
        (std::strcmp(name, "result_output") == 0) ||
        (std::strcmp(name, "embd") == 0) ||
        (std::strncmp(name, "embd-", 5) == 0);
    // Same-operand FFN Gate A: must observe ffn_norm (to inject) + gate/up (to score).
    if (forceFfnNorm) {
        want = want ||
            (lyrFfnNorm == forceFfnLayer) ||
            (lyrFfnGate == forceFfnLayer) ||
            (lyrFfnUp == forceFfnLayer);
    }
    if (forceFfnInp) {
        want = want ||
            (lyrFfnInp == forceFfnInpLayer) ||
            (lyrFfnNorm == forceFfnInpLayer) ||
            (lyrFfnGate == forceFfnInpLayer) ||
            (lyrFfnUp == forceFfnInpLayer);
    }
    if (sparseMode) {
        // Clean-authority sparse: force path (V+kqv all layers) + selected l_out + tip
        want = want ||
            (expandV && isV && lyrQkv >= 0 && lyrQkv <= maxLayer) ||
            (expandV && isKqv && lyrKqv >= 0 && lyrKqv <= maxLayer) ||
            (lyrLout >= 0 && lyrLout < 64 && s_sparseLayers[lyrLout]);
    } else {
        want = want ||
            (isKqv && lyrKqv >= 0 && lyrKqv <= maxLayer) ||
            (lyrLout >= 0 && lyrLout <= maxLayer) ||
            (lyrAttnOut >= 0 && lyrAttnOut <= maxLayer) ||
            (lyrAttnNorm >= 0 && lyrAttnNorm <= maxLayer) ||
            (lyrFfnInp >= 0 && lyrFfnInp <= maxLayer) ||
            (lyrFfnNorm >= 0 && lyrFfnNorm <= maxLayer) ||
            (lyrFfnOut >= 0 && lyrFfnOut <= maxLayer) ||
            (lyrFfnGate >= 0 && lyrFfnGate <= maxLayer) ||
            (lyrFfnUp >= 0 && lyrFfnUp <= maxLayer) ||
            (lyrFfnAct >= 0 && lyrFfnAct <= maxLayer) ||
            (lyrQkv >= 0 && lyrQkv <= maxLayer);
    }
    if (ask) return want;
    if (!want) return true;
    if (listAll && std::getenv("RAWRXD_REF_CB_LIST_ONLY") != nullptr) {
        std::printf("REF_NODE name=%s type=%d ne0=%lld ne1=%lld ne2=%lld\n",
                    name, (int)t->type, (long long)t->ne[0], (long long)t->ne[1], (long long)t->ne[2]);
        return true;
    }
    if (t->type != GGML_TYPE_F32) {
        std::printf("REF_TENSOR name=%s type=%d SKIP_NON_F32\n", name, (int)t->type);
        return true;
    }
    if (!t->data) return true;

    // Gate A inject + authoritative PRE_O dump from kqv_out-L itself.
    if (isKqv && lyrKqv >= 0) {
        maybeForceKqvOut(t);
        const int64_t ne0 = t->ne[0];
        const int64_t ne1 = t->ne[1] > 0 ? t->ne[1] : 1;
        const int64_t ne2 = t->ne[2] > 0 ? t->ne[2] : 1;
        char preKey[64];
        std::snprintf(preKey, sizeof(preKey), "ATTN_PRE_O_%d", lyrKqv);
        std::printf("REF_KQV_SHAPE name=%s ne=[%lld,%lld,%lld] nb=[%zu,%zu,%zu]\n",
                    name, (long long)ne0, (long long)ne1, (long long)ne2,
                    (size_t)t->nb[0], (size_t)t->nb[1], (size_t)t->nb[2]);
        if (ne2 > 1) {
            const int n_head = (int)ne1;
            const int head_dim = (int)ne0;
            const int n_tok = (int)ne2;
            const size_t tokBytes = t->nb[2];
            const size_t headBytes = t->nb[1];
            std::vector<float> flat((size_t)n_head * (size_t)head_dim);
            for (int tok = 0; tok < n_tok; ++tok) {
                const char* base = (const char*)t->data + (size_t)tok * tokBytes;
                for (int h = 0; h < n_head; ++h) {
                    const float* src = (const float*)(base + (size_t)h * headBytes);
                    std::memcpy(flat.data() + (size_t)h * (size_t)head_dim,
                                src, (size_t)head_dim * sizeof(float));
                }
                if (!sparseMode) digestVec(preKey, tok, flat.data(), (int)flat.size());
            }
        } else if (ne0 == 2048) {
            const int n_tok = (int)ne1;
            const size_t stride = t->nb[1] / sizeof(float);
            for (int i = 0; i < n_tok; ++i) {
                const float* col = (const float*)t->data + (size_t)i * stride;
                if (!sparseMode) digestVec(preKey, i, col, 2048);
            }
        } else {
            std::printf("REF_KQV_SKIP unexpected ne0=%lld (want 2048 or 3D heads)\n",
                        (long long)ne0);
        }
        return true;
    }

    // Audit-only: attn_out src[1] (must NOT reuse ATTN_PRE_O_0 — polluted prior goldens).
    if (std::strncmp(name, "attn_out-0", 10) == 0) {
        for (int si = 0; si < GGML_MAX_SRC; ++si) {
            struct ggml_tensor* s = t->src[si];
            if (!s || !s->data || s->type != GGML_TYPE_F32) continue;
            if (s->ne[0] != 2048) continue;
            const int n_tok = (int)(s->ne[1] > 0 ? s->ne[1] : 1);
            const size_t stride = s->nb[1] / sizeof(float);
            std::printf("REF_PRE_O_SRC src[%d] name=%s ne=[%lld,%lld,%lld] op=%d "
                        "(audit key=ATTN_PRE_O_SRC1 — not authority)\n",
                        si, s->name[0] ? s->name : "(unnamed)",
                        (long long)s->ne[0], (long long)s->ne[1], (long long)s->ne[2],
                        (int)s->op);
            for (int i = 0; i < n_tok; ++i) {
                const float* col = (const float*)s->data + (size_t)i * stride;
                digestVec("ATTN_PRE_O_SRC1", i, col, 2048);
            }
            break;
        }
    }

    // L0/L1 detailed Q/K/V ladder OR any-layer V stash for EXPAND_V force.
    static int s_qHits0 = 0, s_kHits0 = 0, s_vHits0 = 0;
    static int s_qHits1 = 0, s_kHits1 = 0, s_vHits1 = 0;
    int layerQkv = lyrQkv;
    const bool detailedQkv = (layerQkv == 0 || layerQkv == 1) && !sparseMode;
    const bool stashVOnly = expandV && isV && layerQkv >= 0 && layerQkv <= maxLayer;

    if ((detailedQkv && (isQ || isK || isV)) || stashVOnly) {
        const int64_t ne0 = t->ne[0];
        const int64_t ne1 = t->ne[1] > 0 ? t->ne[1] : 1;
        const int64_t ne2 = t->ne[2] > 0 ? t->ne[2] : 1;
        char canon[64];
        int hit = 1;
        if (isQ) {
            hit = (layerQkv == 0) ? ++s_qHits0 : ++s_qHits1;
            std::snprintf(canon, sizeof(canon), "%s_%d",
                          hit == 1 ? "Q_PRE_ROPE" : "Q_POST_ROPE", layerQkv);
        } else if (isK) {
            hit = (layerQkv == 0) ? ++s_kHits0 : ++s_kHits1;
            std::snprintf(canon, sizeof(canon), "%s_%d",
                          hit == 1 ? "K_PRE_ROPE" : "K_POST_ROPE", layerQkv);
        } else {
            if (layerQkv == 0) ++s_vHits0; else if (layerQkv == 1) ++s_vHits1;
            std::snprintf(canon, sizeof(canon), "V_%d", layerQkv);
        }
        if (detailedQkv) {
            std::printf("REF_QKV_SHAPE name=%s layer=%d hit=%d ne=[%lld,%lld,%lld] key=%s\n",
                        name, layerQkv, hit,
                        (long long)ne0, (long long)ne1, (long long)ne2, canon);
        }
        auto stashPos0 = [&](const float* col, int n) {
            if (isV && layerQkv >= 0 && layerQkv < kMaxForceLayers && n == kNkv * kHd) {
                g_layerV[layerQkv].assign(col, col + n);
            }
        };
        if (ne2 > 1) {
            const int n_head = (int)ne1;
            const int head_dim = (int)ne0;
            const int n_tok = (int)ne2;
            const size_t tokBytes = t->nb[2];
            const size_t headBytes = t->nb[1];
            std::vector<float> flat((size_t)n_head * (size_t)head_dim);
            for (int tok = 0; tok < n_tok; ++tok) {
                const char* base = (const char*)t->data + (size_t)tok * tokBytes;
                for (int h = 0; h < n_head; ++h) {
                    const float* src = (const float*)(base + (size_t)h * headBytes);
                    std::memcpy(flat.data() + (size_t)h * (size_t)head_dim, src, (size_t)head_dim * sizeof(float));
                }
                if (detailedQkv) digestVec(canon, tok, flat.data(), (int)flat.size());
                if (tok == 0) stashPos0(flat.data(), (int)flat.size());
            }
        } else {
            const int n_embd = (int)ne0;
            const int n_tok = (int)ne1;
            const size_t stride = t->nb[1] / sizeof(float);
            for (int i = 0; i < n_tok; ++i) {
                const float* col = (const float*)t->data + (size_t)i * stride;
                if (detailedQkv) digestVec(canon, i, col, n_embd);
                if (i == 0) stashPos0(col, n_embd);
            }
        }
        return true;
    }

    // Inject frozen Deep2 FFN_INP before RMSNorm (same-source ownership).
    if (lyrFfnInp >= 0) maybeForceFfnInp(t);
    // Inject frozen Deep2 FFN_NORM before gate/up consume it.
    if (lyrFfnNorm >= 0) maybeForceFfnNorm(t);

    const int n_embd = (int)t->ne[0];
    const int n_tok = (int)t->ne[1] > 0 ? (int)t->ne[1] : 1;
    if (n_embd <= 0) return true;
    const size_t stride = t->nb[1] / sizeof(float);
    const char* canon = name;
    char canonBuf[64];
    if (std::strcmp(name, "embd") == 0) {
        canon = "PROMPT_EMBED";
    } else if (lyrAttnNorm >= 0) {
        std::snprintf(canonBuf, sizeof(canonBuf), "ATTN_NORM_%d", lyrAttnNorm);
        canon = canonBuf;
    } else if (lyrAttnOut >= 0) {
        std::snprintf(canonBuf, sizeof(canonBuf), "ATTN_OUT_%d", lyrAttnOut);
        canon = canonBuf;
    } else if (lyrFfnInp >= 0) {
        if (forceFfnInp && lyrFfnInp == forceFfnInpLayer)
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_INP_FORCE_DEEP2_%d", lyrFfnInp);
        else
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_INP_%d", lyrFfnInp);
        canon = canonBuf;
    } else if (lyrFfnNorm >= 0) {
        // After force: dump as FFN_NORM_FORCE_DEEP2_X when injection armed.
        if (forceFfnNorm && lyrFfnNorm == forceFfnLayer)
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_NORM_FORCE_DEEP2_X_%d", lyrFfnNorm);
        else if (forceFfnInp && lyrFfnNorm == forceFfnInpLayer)
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_NORM_FORCE_DEEP2_INP_%d", lyrFfnNorm);
        else
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_NORM_%d", lyrFfnNorm);
        canon = canonBuf;
    } else if (lyrFfnGate >= 0) {
        if (forceFfnNorm && lyrFfnGate == forceFfnLayer)
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_GATE_FORCE_DEEP2_X_%d", lyrFfnGate);
        else if (forceFfnInp && lyrFfnGate == forceFfnInpLayer)
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_GATE_FORCE_DEEP2_INP_%d", lyrFfnGate);
        else
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_GATE_%d", lyrFfnGate);
        canon = canonBuf;
    } else if (lyrFfnUp >= 0) {
        if (forceFfnNorm && lyrFfnUp == forceFfnLayer)
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_UP_FORCE_DEEP2_X_%d", lyrFfnUp);
        else if (forceFfnInp && lyrFfnUp == forceFfnInpLayer)
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_UP_FORCE_DEEP2_INP_%d", lyrFfnUp);
        else
            std::snprintf(canonBuf, sizeof(canonBuf), "FFN_UP_%d", lyrFfnUp);
        canon = canonBuf;
    } else if (lyrFfnAct >= 0) {
        std::snprintf(canonBuf, sizeof(canonBuf), "FFN_ACT_%d", lyrFfnAct);
        canon = canonBuf;
    } else if (lyrFfnOut >= 0) {
        std::snprintf(canonBuf, sizeof(canonBuf), "FFN_DOWN_%d", lyrFfnOut);
        canon = canonBuf;
    } else if (lyrLout >= 0) {
        std::snprintf(canonBuf, sizeof(canonBuf), "LAYER%d_OUT", lyrLout);
        canon = canonBuf;
    } else if (std::strcmp(name, "result_norm") == 0) {
        canon = "FINAL_NORM";
    } else if (std::strcmp(name, "result_output") == 0) {
        canon = "LOGITS";
    } else {
        std::snprintf(canonBuf, sizeof(canonBuf), "TENS_%s", name);
        for (char* p = canonBuf; *p; ++p) if (*p == '-') *p = '_';
        canon = canonBuf;
    }
    for (int i = 0; i < n_tok; ++i) {
        const float* col = (const float*)t->data + (size_t)i * stride;
        digestVec(canon, i, col, n_embd);
        // Tip = last prefill column (matches Deep2 TIP_* / greedy sample source)
        if (i + 1 == n_tok) {
            if (std::strcmp(canon, "FINAL_NORM") == 0) {
                digestVec("TIP_FINAL_NORM", i, col, n_embd);
            } else if (std::strcmp(canon, "LOGITS") == 0) {
                digestVec("TIP_LOGITS", i, col, n_embd);
                int argmax = 0;
                float best = col[0];
                for (int j = 1; j < n_embd; ++j) {
                    if (col[j] > best) { best = col[j]; argmax = j; }
                }
                std::printf("[STAGE_DIGEST] side=llama key=ARGMAX pos=%d id=%d logit=%.9f\n",
                            i, argmax, best);
                fflush(stdout);
            }
        }
    }
    return true;
}

static void dumpTop10(const char* key, float* logits, int n_vocab, const llama_vocab* vocab) {
    std::vector<std::pair<float, int>> scored;
    scored.reserve(static_cast<size_t>(n_vocab));
    for (int i = 0; i < n_vocab; ++i) scored.push_back({logits[i], i});
    const int k = std::min(10, n_vocab);
    std::partial_sort(scored.begin(), scored.begin() + k, scored.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });
    std::printf("%s=", key);
    for (int i = 0; i < k; ++i) {
        if (i) std::printf(",");
        char buf[256];
        const int n = llama_token_to_piece(vocab, scored[i].second, buf, (int)sizeof(buf), 0, true);
        std::string piece = (n > 0) ? std::string(buf, buf + n) : std::string();
        for (char& c : piece) {
            if (c == ',' || c == '\n' || c == '\r' || c == '\'') c = ' ';
        }
        std::printf("%d:%.6f:'%s'", scored[i].second, scored[i].first, piece.c_str());
    }
    std::printf("\n");
    if (k > 0) {
        std::printf("REF_SELECTED_ID=%d\n", scored[0].second);
        std::printf("REF_SELECTED_LOGIT=%.6f\n", scored[0].first);
    }
    // Batch-2 BOS near-miss pair (comma vs newline)
    if (n_vocab > 29892) {
        std::printf("REF_LOGIT_13=%.9f\n", logits[13]);
        std::printf("REF_LOGIT_29892=%.9f\n", logits[29892]);
        std::printf("REF_DELTA_13_minus_29892=%.9f\n", logits[13] - logits[29892]);
    }
}

int main(int argc, char** argv) {
    const char* modelPath = R"(F:\~dev\tinyllama_fresh.gguf)";
    const char* prompt = "hello";
    int nPredict = 15;
    if (argc >= 2) modelPath = argv[1];
    if (argc >= 3) prompt = argv[2];
    if (argc >= 4) nPredict = std::atoi(argv[3]);

    std::printf("PARITY-CERT-001\n");
    std::printf("side=reference\n");
    std::printf("reference_backend=llama.cpp\n");
    std::printf("note=external_measuring_stick_only_not_a_deep2_dependency\n");
    std::printf("model=%s\n", modelPath);
    std::printf("prompt=%s\n", prompt);
    std::printf("max_new_tokens=%d\n", nPredict);
    std::printf("temperature=0\n");
    std::printf("top_k=1\n");
    fflush(stdout);

    // Map llama.dll first so ggml.dll / ggml-base.dll resolve as ITS dependencies
    // (avoids a second ggml copy with an empty backend registry).
    SetDllDirectoryA(R"(F:\~dev\llama-direct\vulkan)");
    if (!LoadLibraryA(R"(F:\~dev\llama-direct\vulkan\llama.dll)")) {
        std::fprintf(stderr, "REF_BACKEND=FAIL LoadLibrary llama.dll\n");
        return 2;
    }
    load_ggml_backends();
    llama_backend_init();

    llama_model_params mparams = llama_model_default_params();
    mparams.n_gpu_layers = 0; // CPU: deterministic measuring stick
    llama_model* model = llama_model_load_from_file(modelPath, mparams);
    if (!model) {
        std::fprintf(stderr, "REF_LOAD=FAIL\n");
        return 2;
    }
    const llama_vocab* vocab = llama_model_get_vocab(model);

    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx = 2048;
    cparams.n_batch = 512;
    // Default: logits-only (matches llama-completion greedy). Opt-in embeddings via RAWRXD_REF_EMBED=1.
    const bool wantEmb = (std::getenv("RAWRXD_REF_EMBED") != nullptr);
    cparams.embeddings = wantEmb;
    // Layer-bisect digests via ggml eval callback. Opt-in: can perturb tip numerics.
    const bool wantCb = (std::getenv("RAWRXD_REF_CB_EVAL") != nullptr);
    if (wantCb) {
        cparams.cb_eval = cbEval;
        cparams.cb_eval_user_data = nullptr;
    }
    llama_context* ctx = llama_init_from_model(model, cparams);
    if (!ctx) {
        std::fprintf(stderr, "REF_CTX=FAIL\n");
        llama_model_free(model);
        return 2;
    }
    if (wantEmb) llama_set_embeddings(ctx, true);
    std::printf("REF_LOAD=PASS\n");
    std::printf("REF_EMBEDDINGS=%d\n", wantEmb ? 1 : 0);
    std::printf("REF_CB_EVAL=%d\n", wantCb ? 1 : 0);
    std::printf("REF_N_EMBD=%d\n", llama_model_n_embd(model));
    std::printf("REF_ROPE_FREQ_SCALE_TRAIN=%.9f\n",
                (double)llama_model_rope_freq_scale_train(model));

    std::vector<llama_token> promptTokens;
    // Numerical ladder: RAWRXD_FORCE_IDS=1,21521,9312 (overrides tokenize)
    if (const char* forceIds = std::getenv("RAWRXD_FORCE_IDS")) {
        const char* p = forceIds;
        while (*p) {
            while (*p == ' ' || *p == ',') ++p;
            if (!*p) break;
            char* end = nullptr;
            long v = std::strtol(p, &end, 10);
            if (end == p) break;
            promptTokens.push_back(static_cast<llama_token>(v));
            p = end;
        }
        std::printf("REF_FORCE_IDS=1 count=%zu\n", promptTokens.size());
    } else {
        promptTokens.resize(64);
        int nTok = llama_tokenize(vocab, prompt, (int32_t)std::strlen(prompt),
                               promptTokens.data(), (int32_t)promptTokens.size(),
                               /*add_special*/ true, /*parse_special*/ true);
        if (nTok < 0) {
            promptTokens.resize((size_t)(-nTok));
            nTok = llama_tokenize(vocab, prompt, (int32_t)std::strlen(prompt),
                               promptTokens.data(), (int32_t)promptTokens.size(),
                               true, true);
        }
        if (nTok < 0) {
            std::fprintf(stderr, "REF_TOKENIZE=FAIL\n");
            return 2;
        }
        promptTokens.resize((size_t)nTok);
    }
    if (promptTokens.empty()) {
        std::fprintf(stderr, "REF_TOKENIZE=FAIL empty\n");
        return 2;
    }
    const int n = (int)promptTokens.size();
    printIds("REF_PROMPT_IDS", promptTokens);

    if (wantEmb) {
        // Prefill with logits/emb requested for every position.
        llama_batch batch = llama_batch_init(n, 0, 1);
        for (int i = 0; i < n; ++i) {
            batch.token[i] = promptTokens[(size_t)i];
            batch.pos[i] = i;
            batch.n_seq_id[i] = 1;
            batch.seq_id[i][0] = 0;
            batch.logits[i] = 1;
        }
        batch.n_tokens = n;
        if (llama_decode(ctx, batch) != 0) {
            std::fprintf(stderr, "REF_PREFILL=FAIL\n");
            llama_batch_free(batch);
            return 2;
        }
        llama_batch_free(batch);
        const int n_embd = llama_model_n_embd(model);
        for (int i = 0; i < n; ++i) {
            float* emb = llama_get_embeddings_ith(ctx, i);
            digestVec("REF_FINAL_HIDDEN", i, emb, n_embd);
        }
    } else {
        // Logits-only path (completion-equivalent)
        llama_batch batch = llama_batch_get_one(promptTokens.data(), n);
        if (llama_decode(ctx, batch) != 0) {
            std::fprintf(stderr, "REF_PREFILL=FAIL\n");
            return 2;
        }
    }

    float* logits = llama_get_logits_ith(ctx, wantEmb ? (n - 1) : -1);
    if (!logits) logits = llama_get_logits(ctx);
    const int n_vocab = llama_vocab_n_tokens(vocab);
    dumpTop10("REF_TOP10", logits, n_vocab, vocab);

    llama_sampler* sampler = llama_sampler_chain_init(llama_sampler_chain_default_params());
    llama_sampler_chain_add(sampler, llama_sampler_init_greedy());

    std::vector<llama_token> gen;
    gen.reserve((size_t)nPredict);
    for (int t = 0; t < nPredict; ++t) {
        const llama_token id = llama_sampler_sample(sampler, ctx, -1);
        llama_sampler_accept(sampler, id);
        gen.push_back(id);
        if (llama_vocab_is_eog(vocab, id)) break;

        llama_batch step = llama_batch_get_one(const_cast<llama_token*>(&gen.back()), 1);
        if (llama_decode(ctx, step) != 0) {
            std::fprintf(stderr, "REF_DECODE=FAIL at %d\n", t);
            break;
        }
    }

    printIds("REF_GEN_IDS", gen);
    std::printf("REF_GEN_COUNT=%zu\n", gen.size());
    std::printf("REF_SIDE=DONE\n");
    fflush(stdout);

    llama_sampler_free(sampler);
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return gen.empty() ? 1 : 0;
}
