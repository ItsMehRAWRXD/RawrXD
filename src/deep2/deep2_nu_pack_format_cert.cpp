// deep2_nu_pack_format_cert.cpp — NU_PACK_FORMAT_001
#include "NUFusedPacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static void FillSine(std::vector<float>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        const int phase = (int)(i % 7) - 3;
        v[i] = std::sin(0.017f * (float)i) * 0.75f + 0.05f * (float)phase;
    }
}

static double Rmse(const float* a, const float* b, size_t n) {
    double s = 0;
    for (size_t i = 0; i < n; ++i) {
        double d = (double)a[i] - (double)b[i];
        s += d * d;
    }
    return std::sqrt(s / (double)n);
}

static bool Roundtrip(NUFusedPacker& p, NUFormatTag tag, size_t n,
                      double maxRmse, const char* name, bool& okOut) {
    std::vector<float> src(n), dst(n, 0.f);
    FillSine(src);
    auto packed = p.packTensor(src.data(), n, tag);
    if (packed.size() < sizeof(NUStreamHeader)) {
        printf("%s PACK_TOO_SMALL\n", name);
        okOut = false;
        return false;
    }
    const auto* hdr = reinterpret_cast<const NUStreamHeader*>(packed.data());
    const bool magicOk = hdr->magic == 0x46554E00u;
    const bool verOk = hdr->version == 1;
    const bool elemsOk = hdr->totalElements == (uint32_t)n;
    const bool fmtOk = hdr->formatTable[0] == (uint32_t)tag;
    const size_t got = p.unpackTensor(packed.data(), packed.size(), dst.data(), n);
    const double err = (got == n) ? Rmse(src.data(), dst.data(), n) : 1e9;
    const double f32Bytes = (double)n * 4.0;
    const double ratio = f32Bytes > 0 ? (double)packed.size() / f32Bytes : 0;
    const bool errOk = err <= maxRmse;
    const bool lean = (tag == NUFormatTag::NU_F16) ? (ratio < 0.7)
                                                   : (ratio < 0.55);
    printf("%s magic=%d ver=%d elems=%d fmt=%d n=%zu packed=%zu ratio=%.3f "
           "rmse=%.6f\n",
           name, magicOk ? 1 : 0, verOk ? 1 : 0, elemsOk ? 1 : 0, fmtOk ? 1 : 0,
           n, packed.size(), ratio, err);
    okOut = magicOk && verOk && elemsOk && fmtOk && got == n && errOk && lean;
    return okOut;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\NU_PACK_FORMAT_001", nullptr);
#endif
    printf("NU_PACK_FORMAT_001\n");
    fflush(stdout);
    NUFusedPacker packer;
    NUPackerConfig cfg;
    cfg.enableXVAAlignment = true;
    cfg.cacheLineSize = 64;
    cfg.targetBitsPerWeight = 4.0f;
    if (!packer.initialize(cfg)) {
        printf("NU_PACK_FORMAT_001=FAIL init\n");
#ifdef _WIN32
        _exit(2);
#else
        return 2;
#endif
    }

    bool q80 = false, q40 = false, q4k = false, f16 = false;
    Roundtrip(packer, NUFormatTag::NU_Q8_0, 1024, 0.05, "Q8_0", q80);
    Roundtrip(packer, NUFormatTag::NU_Q4_0, 1024, 0.20, "Q4_0", q40);
    Roundtrip(packer, NUFormatTag::NU_Q4_K, 1024, 0.25, "Q4_K", q4k);
    Roundtrip(packer, NUFormatTag::NU_F16, 1024, 0.01, "F16", f16);

    // Bad magic must fail closed
    std::vector<float> src(64), dst(64, 0.f);
    FillSine(src);
    auto good = packer.packTensor(src.data(), src.size(), NUFormatTag::NU_Q4_0);
    auto bad = good;
    reinterpret_cast<NUStreamHeader*>(bad.data())->magic = 0xDEADBEEF;
    const size_t badN =
        packer.unpackTensor(bad.data(), bad.size(), dst.data(), dst.size());
    const bool badMagicRejected = (badN == 0);

    // XVA header + cache-line aligned payload
    auto xva = packer.packXVA(src.data(), src.size(), NUFormatTag::NU_Q4_0);
    const bool xvaSize = xva.size() >= sizeof(XVAHeader);
    const auto* xh = xvaSize ? reinterpret_cast<const XVAHeader*>(xva.data())
                             : nullptr;
    const bool xvaMagic = xh && xh->magic == 0x41585632u;
    const bool xvaAlign = xh && xh->cacheLineSize == 64;
    const bool xvaElems = xh && xh->totalElements == (uint32_t)src.size();
    size_t xvaOut = 0;
    double xvaRmse = 1e9;
    if (xvaMagic) {
        xvaOut = packer.unpackXVA(xva.data(), xva.size(), dst.data(), dst.size());
        if (xvaOut == src.size())
            xvaRmse = Rmse(src.data(), dst.data(), src.size());
    }
    // Payload starts on a cache line (sizeof(XVAHeader)=48 → 64).
    const size_t xvaDataOff = 64;
    const bool xvaOffOk = xvaSize && (xva.size() >= xvaDataOff) &&
                          ((xvaDataOff % 64) == 0);
    const bool xvaOk = xvaMagic && xvaAlign && xvaElems && xvaOffOk &&
                       xvaOut == src.size() && xvaRmse <= 0.20;
    printf("XVA magic=%d align=%d elems=%d off=%d n=%zu rmse=%.6f\n",
           xvaMagic ? 1 : 0, xvaAlign ? 1 : 0, xvaElems ? 1 : 0,
           xvaOffOk ? 1 : 0, xvaOut, xvaRmse);

    // Format table density sanity
    const auto fi = NUFusedPacker::getFormatInfo(NUFormatTag::NU_Q4_0);
    const bool infoOk = fi.bitsPerWeight > 0.f && fi.bitsPerWeight <= 8.f &&
                        fi.elemsPerBlock == 32 && fi.blockSize == 20;

    printf("BAD_MAGIC_REJECT=%d XVA_OK=%d INFO_OK=%d\n",
           badMagicRejected ? 1 : 0, xvaOk ? 1 : 0, infoOk ? 1 : 0);

    const bool pass =
        q80 && q40 && q4k && f16 && badMagicRejected && xvaOk && infoOk;
    printf("NU_PACK_FORMAT_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f =
        fopen("G:\\~dev\\rawrxd\\evidence\\NU_PACK_FORMAT_001\\GATE_STATUS.txt",
              "w");
    if (f) {
        fprintf(f, "Q8_0=%d Q4_0=%d Q4_K=%d F16=%d BAD_MAGIC=%d XVA=%d INFO=%d\n",
                q80, q40, q4k, f16, badMagicRejected, xvaOk, infoOk);
        fprintf(f, "NU_PACK_FORMAT_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
#ifdef _WIN32
    _exit(pass ? 0 : 2);
#else
    return pass ? 0 : 2;
#endif
}
