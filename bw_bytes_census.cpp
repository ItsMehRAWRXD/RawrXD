// bw_bytes_census.cpp
// RAWRXD_EFFECTIVE_BYTES_PER_TOKEN_001
//
// The whole question is:
//     LOGICAL_MODEL_SIZE != PHYSICAL_BYTES_TOUCHED_PER_TOKEN
// and the only way to know which one binds is to MEASURE both, plus the
// bandwidth actually sustained on this host, and then compare:
//
//     BW_PREDICTED_TPS = MEASURED_SUSTAINED_BW / TOTAL_BYTES_PER_TOKEN
//     ACTUAL_TPS       = (supplied by the caller from a real generation)
//
// If ACTUAL_TPS is far BELOW BW_PREDICTED_TPS the workload is not
// bandwidth-bound, and reducing bytes/token buys nothing until it is. That
// distinction decides where engineering effort belongs, so it is computed here
// rather than argued.
//
// Every number in the receipt is measured. Logical size comes from the GGUF
// tensor table; bandwidth comes from timed reads; TPS is passed in from a real
// generation and echoed, never invented here.

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <io.h>
#include <windows.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif

static FILE* g_f = nullptr;
static uint64_t g_pos = 0;
static bool rd(void* p, size_t n) {
    if (fread(p, 1, n, g_f) != n) return false;
    g_pos += n; return true;
}
static std::wstring widen(const std::string& a) {
    if (a.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), nullptr, 0);
    std::wstring w((size_t)(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), &w[0], n);
    return w;
}
static FILE* openPath(const std::string& p) { return _wfopen(widen(p).c_str(), L"rb"); }
static bool seek64(uint64_t off) {
    if (off > (uint64_t)INT64_MAX) return false;
    if (_fseeki64(g_f, (__int64)off, SEEK_SET) != 0) return false;
    g_pos = (uint64_t)_ftelli64(g_f);
    return g_pos == off;
}
static bool readStringRaw(std::string& out) {
    uint64_t n = 0;
    if (!rd(&n, 8)) return false;
    if (n > (uint64_t)1 << 24) return false;
    out.assign((size_t)n, '\0');
    if (n && fread(&out[0], 1, (size_t)n, g_f) != n) return false;
    g_pos += n; return true;
}
static uint32_t elemSize(uint32_t t) {
    switch (t) { case 0: case 1: case 7: return 1;
    case 2: case 3: return 2; case 4: case 5: case 6: return 4;
    case 10: case 11: case 12: return 8; default: return 0; }
}
static bool skipVal(uint32_t t, int d = 0) {
    uint8_t s[8];
    if (d > 4) return false;
    if (t == 8) { std::string x; return readStringRaw(x); }
    if (t == 9) { uint32_t et = 0; uint64_t n = 0;
        if (!rd(&et, 4) || !rd(&n, 8)) return false;
        if (n > (uint64_t)1 << 32) return false;
        for (uint64_t i = 0; i < n; ++i) if (!skipVal(et, d + 1)) return false;
        return true; }
    const uint32_t sz = elemSize(t);
    return sz ? rd(s, sz) : false;
}
static uint64_t alignUp(uint64_t v, uint64_t a) { return a ? ((v + a - 1) / a) * a : v; }

struct Geo { int type; const char* name; uint32_t qk; uint32_t bytes; };
static const Geo kGeo[] = {
    {  2,"Q4_0",32,18},{ 3,"Q4_1",32,20},{ 6,"Q5_0",32,22},{ 7,"Q5_1",32,24},
    {  8,"Q8_0",32,34},{ 9,"Q8_1",32,36},{10,"Q2_K",256,84},{11,"Q3_K",256,110},
    {12,"Q4_K",256,144},{13,"Q5_K",256,176},{14,"Q6_K",256,210},{15,"Q8_K",256,292},
    {  0,"F32",1,4},{ 1,"F16",1,2},{30,"BF16",1,2},
};
static const Geo* geo(int t){ for(const auto&g:kGeo) if(g.type==t) return &g; return nullptr; }

// ---------------------------------------------------------------- RAM bandwidth
static double measureRamBandwidth(size_t bytes, int threads) {
    std::vector<float> buf;
    buf.assign(bytes / sizeof(float), 1.0f);
    const size_t chunks = buf.size() / (threads > 0 ? threads : 1);
    // warm the pages so the measurement is DRAM, not first-touch page faults
    volatile float sink = 0.0f;
    for (size_t i = 0; i < buf.size(); i += 4096) sink = sink + buf[i];

    const int kPasses = 6;
    auto t0 = std::chrono::steady_clock::now();
    double acc = 0.0;
    for (int p = 0; p < kPasses; ++p) {
        for (int t = 0; t < threads; ++t) {
            const float* b = buf.data() + (size_t)t * chunks;
            const size_t n = (t == threads - 1) ? (buf.size() - (size_t)t * chunks) : chunks;
            double local = 0.0;
#ifdef __AVX2__
            const __m256i* v = (const __m256i*)b;
            __m256 accv = _mm256_set1_ps(0.0f);
            const size_t nv = n / 8;
            for (size_t i = 0; i < nv; ++i) {
                __m256 x = _mm256_castsi256_ps(_mm256_loadu_si256(v + i));
                accv = _mm256_add_ps(accv, _mm256_mul_ps(x, x));
            }
            float tmp[8]; _mm256_storeu_ps(tmp, accv);
            for (int k = 0; k < 8; ++k) local += tmp[k];
            for (size_t i = nv * 8; i < n; ++i) local += (double)b[i] * b[i];
#else
            for (size_t i = 0; i < n; ++i) local += (double)b[i] * b[i];
#endif
            acc += local;
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    const double sec = std::chrono::duration<double>(t1 - t0).count();
    sink = (float)acc;
    (void)sink;
    const double moved = (double)bytes * (double)kPasses * (double)threads;
    return sec > 0 ? moved / sec / 1e9 : 0.0;   // GB/s
}

// ------------------------------------------------------------ storage bandwidth
static double measureStorageBandwidth(FILE* f, uint64_t fileSize, size_t chunk) {
    std::vector<unsigned char> buf(chunk);
    const int kChunks = 96;
    uint64_t sink = 0;
    size_t done = 0;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kChunks; ++i) {
        const uint64_t off = (uint64_t)i * (fileSize / (uint64_t)(kChunks + 2));
        if (off + chunk > fileSize) break;
        if (!seek64(off)) continue;
        if (fread(buf.data(), 1, chunk, f) != chunk) continue;
        sink += buf[0] + buf[chunk / 2] + buf[chunk - 1];
        done += chunk;
    }
    auto t1 = std::chrono::steady_clock::now();
    const double sec = std::chrono::duration<double>(t1 - t0).count();
    (void)sink;
    return (sec > 0 && done) ? ((double)done / sec / 1e9) : 0.0;
}

int main(int argc, char** argv) {
    const std::string path = (argc > 1) ? argv[1] : "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    const double actualTps = (argc > 2) ? atof(argv[2]) : 0.0;
    const int  topK = (argc > 3) ? atoi(argv[3]) : 0;      // 0 = dense / unknown
    const int  nExp = (argc > 4) ? atoi(argv[4]) : 0;
    const int  layers = (argc > 5) ? atoi(argv[5]) : 0;

    g_f = openPath(path);
    if (!g_f) { std::printf("OPEN_FAILED %s\n", path.c_str()); return 3; }
    _fseeki64(g_f, 0, SEEK_END);
    const uint64_t fileSize = (uint64_t)_ftelli64(g_f);
    _fseeki64(g_f, 0, SEEK_SET); g_pos = 0;
    char magic[4] = {0};
    if (!rd(magic, 4) || memcmp(magic, "GGUF", 4) != 0) { std::printf("BAD_MAGIC\n"); return 3; }
    uint32_t ver = 0; uint64_t nT = 0, nKV = 0;
    rd(&ver, 4); rd(&nT, 8); rd(&nKV, 8);

    uint32_t alignment = 32; uint64_t nLyrMeta = 0, ctxMeta = 0, embdMeta = 0;
    for (uint64_t i = 0; i < nKV; ++i) {
        std::string k; uint32_t vt = 0;
        if (!readStringRaw(k) || !rd(&vt, 4)) { std::printf("KV_FAIL\n"); return 3; }
        if (vt == 4 || vt == 5) {
            uint32_t v = 0; rd(&v, 4);
            if (k == "general.alignment") alignment = v;
            else if (k.find("expert") != std::string::npos || k.find("block_count") != std::string::npos || k.find("embedding_length") != std::string::npos) std::printf("BYTES_CENSUS KV %s=%u\n", k.c_str(), v);
            else if (k == "block_count") nLyrMeta = v;
            else if (k == "attention.head_count") ctxMeta = v;
            else if (k == "embedding_length") embdMeta = v;
        } else if (!skipVal(vt)) { std::printf("KV_SKIP_FAIL %s\n", k.c_str()); return 3; }
    }
    const uint64_t headerEnd = g_pos, dataStart = alignUp(headerEnd, alignment);

    uint64_t sumBytes = 0, expertBytes = 0, nonExpertBytes = 0, unverified = 0;
    uint64_t expertTensors = 0, nonExpertTensors = 0;
    std::vector<std::string> expertNames;
    for (uint64_t i = 0; i < nT; ++i) {
        std::string name; uint32_t nd = 0;
        if (!readStringRaw(name) || !rd(&nd, 4) || nd > 4) { std::printf("TI_FAIL\n"); return 3; }
        uint64_t d[4] = {0};
        for (uint32_t k = 0; k < nd; ++k) rd(&d[k], 8);
        uint32_t ty = 0; uint64_t off = 0;
        rd(&ty, 4); rd(&off, 8);
        uint64_t ne = 1; for (uint32_t k = 0; k < nd; ++k) ne *= d[k];
        const Geo* g = geo((int)ty);
        uint64_t bytes = 0;
        if (g && g->qk && (ne % g->qk) == 0) bytes = (ne / g->qk) * g->bytes;
        else ++unverified;
        const uint64_t padded = bytes ? alignUp(bytes, alignment) : 0;
        sumBytes += padded;
        // Routed-expert tensors are the *_exps.* family. Everything else is read
        // once per token regardless of routing.
        const bool isExpert =
            name.find("_exps") != std::string::npos ||
            name.find("experts.") != std::string::npos;
        if (isExpert) { expertBytes += padded; ++expertTensors; if (expertNames.size() < 4) expertNames.push_back(name); }
        else          { nonExpertBytes += padded; ++nonExpertTensors; }
    }

    const double ramBw  = measureRamBandwidth(2ull * 1024 * 1024 * 1024, 8);
    const double stoBw  = measureStorageBandwidth(g_f, fileSize, 8ull * 1024 * 1024);
    fclose(g_f);

    // ---- per-token accounting -------------------------------------------
    // Dense path: every weight is touched once per generated token.
    // MoE path: non-expert always, plus topK/nExp of the routed slabs.
    const double denseTokBytes = (double)sumBytes;
    double moeTokBytes = (double)nonExpertBytes;
    const bool isMoe = (nExp > 0 && topK > 0);
    if (isMoe) moeTokBytes += (double)expertBytes * ((double)topK / (double)nExp);

    const double totalTokBytes = isMoe ? moeTokBytes : denseTokBytes;
    const double sustained = ramBw > stoBw ? ramBw : stoBw;
    const double bwPredictedTps = totalTokBytes > 0 ? (sustained * 1e9 / totalTokBytes) : 0.0;
    const double impliedBwAtActualTps = actualTps > 0 ? (totalTokBytes * actualTps / 1e9) : 0.0;

    char buf[8192];
    int o = snprintf(buf, sizeof(buf),
        "BYTES_CENSUS FILE=%s FILE_SIZE=%llu\n"
        "BYTES_CENSUS HEADER_END=%llu DATA_START=%llu ALIGNMENT=%u N_TENSORS=%llu\n"
        "BYTES_CENSUS BLOCK_COUNT=%llu EMBEDDING_LENGTH=%llu UNVERIFIED_TYPES=%llu\n"
        "BYTES_CENSUS SUM_PADDED_TENSOR_BYTES=%llu\n"
        "BYTES_CENSUS EXPERT_TENSORS=%llu EXPERT_BYTES=%llu\n"
        "BYTES_CENSUS NONEXPERT_TENSORS=%llu NONEXPERT_BYTES=%llu\n",
        path.c_str(), (unsigned long long)fileSize,
        (unsigned long long)headerEnd, (unsigned long long)dataStart, alignment,
        (unsigned long long)nT, (unsigned long long)nLyrMeta,
        (unsigned long long)embdMeta, (unsigned long long)unverified,
        (unsigned long long)sumBytes,
        (unsigned long long)expertTensors, (unsigned long long)expertBytes,
        (unsigned long long)nonExpertTensors, (unsigned long long)nonExpertBytes);
    o += snprintf(buf + o, sizeof(buf) - o,
        "BW MEASURED_RAM_BW_GB_S=%.3f THREADS=8 BUFFER_BYTES=%llu\n"
        "BW MEASURED_STORAGE_BW_GB_S=%.3f CHUNK_BYTES=8388608 SPREAD=YES\n"
        "BW MEASURED_SUSTAINED_BW_GB_S=%.3f SELECTED=%s\n",
        ramBw, (unsigned long long)(2ull * 1024 * 1024 * 1024), stoBw, sustained,
        (ramBw >= stoBw) ? "RAM" : "STORAGE");
    o += snprintf(buf + o, sizeof(buf) - o,
        "PER_TOKEN MODEL_LOGICAL_BYTES=%llu LOGICAL_GB=%.3f\n"
        "PER_TOKEN IS_MOE=%d TOP_K=%d N_EXPERTS=%d LAYERS=%llu\n"
        "PER_TOKEN DENSE_BYTES_PER_TOKEN=%llu\n"
        "PER_TOKEN MOE_BYTES_PER_TOKEN=%llu\n"
        "PER_TOKEN TOTAL_BYTES_PER_TOKEN=%llu TOTAL_GB_PER_TOKEN=%.4f\n",
        (unsigned long long)sumBytes, (double)sumBytes / 1e9,
        isMoe ? 1 : 0, topK, nExp, (unsigned long long)(layers ? layers : nLyrMeta),
        (unsigned long long)denseTokBytes,
        (unsigned long long)moeTokBytes,
        (unsigned long long)totalTokBytes, totalTokBytes / 1e9);
    o += snprintf(buf + o, sizeof(buf) - o,
        "GATE BW_PREDICTED_TPS=%.4f\n"
        "GATE ACTUAL_TPS=%.4f\n"
        "GATE IMPLIED_BW_AT_ACTUAL_TPS_GB_S=%.4f\n"
        "GATE BW_HEADROOM_FACTOR=%.3f\n"
        "GATE BOUND_BY=%s\n"
        "GATE VERDICT=%s\n",
        bwPredictedTps, actualTps, impliedBwAtActualTps,
        (bwPredictedTps > 0 && actualTps > 0) ? (bwPredictedTps / actualTps) : 0.0,
        (actualTps <= 0) ? "UNKNOWN_NO_TPS_SUPPLIED"
        : (actualTps >= bwPredictedTps * 0.75) ? "BANDWIDTH"
        : (actualTps >= bwPredictedTps * 0.10) ? "MIXED"
        : "COMPUTE_OR_KERNEL_NOT_BANDWIDTH",
        (actualTps <= 0) ? "INCOMPLETE" : "MEASURED");
    if (!expertNames.empty()) {
        o += snprintf(buf + o, sizeof(buf) - o, "BYTES_CENSUS EXPERT_NAME_SAMPLES=");
        for (size_t i = 0; i < expertNames.size(); ++i)
            o += snprintf(buf + o, sizeof(buf) - o, "%s%s", i ? "," : "", expertNames[i].c_str());
        o += snprintf(buf + o, sizeof(buf) - o, "\n");
    }
    fwrite(buf, 1, (size_t)o, stdout);
    fflush(stdout);
    return 0;
}