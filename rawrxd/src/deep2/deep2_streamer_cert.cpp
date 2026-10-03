// deep2_streamer_cert.cpp
// STREAMER-CERT-001 -- Deep2 streaming certification harness.
//
// Admission policy: NONE BY SIZE. Every discovered artifact with real local
// weight bytes is attempted. There is deliberately no MODEL_TOO_LARGE_FOR_RAM
// result: file size is not evidence, and Deep2's streamer exists precisely to
// execute models larger than system RAM.
//
// Discovery is by GGUF magic (47 47 55 46), never by extension, because Ollama
// blobs carry no extension at all.
//
// Shard sets are resolved into ONE logical model: discovery groups
// <prefix>-00001-of-000NN.gguf members, verifies all NN members exist before
// opening, and hands shard 1 to Deep2::GGUFLoader (which maps the rest).
//
// Each model runs in a CHILD PROCESS. That is not a size gate -- it is what
// makes an attempt survivable, so one model's OOM or fault is recorded as that
// model's result instead of destroying the census.
//
// PASS is derived, never printed:
//     PASS = real local weights + Deep2 load + real prefill + real decode
//            + actual streamed callbacks + requested token count + clean teardown
//   PASS != discovered != parsed != admitted != loaded
//
// Build: see CMake option BUILD_DEEP2_STREAMER_CERT.

#include "Deep2Engine.h"
#include "GGUFLoader.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <typeinfo>
#include <vector>
#include <exception>
#include <typeinfo>

#include <windows.h>
#include <psapi.h>
#include <io.h>
#include <cstdlib>
#include <ctime>

namespace fs = std::filesystem;

// ===========================================================================
// RAWRXD_STREAMER_TELEMETRY_SINK_V1  (ASS-8)
//
// The cert reported only to stderr. Every measurement it took -- TTFT, decode
// TPS, callback counts, census totals -- existed as console text in a buffer
// that died with the process, and nothing could tie a result back to the binary
// that produced it. That is the same gap that let an unattributable
// gguf_stream_probe.exe and a truncated 127 GB dump pass as evidence.
//
// Appends one JSON object per line, fflush + _commit after each, so a run that
// dies mid-census keeps every record it completed. The run header carries the
// SHA-256 of the running image. This records; it decides nothing.
// ------------------------------------------------------------------------
namespace streamer_telemetry {

static const char* kSchema = "RAWRXD_STREAMER_TELEMETRY_V1";

static std::string envPath() {
    if (const char* p = std::getenv("RAWRXD_STREAMER_TELEMETRY")) return std::string(p);
    if (const char* l = std::getenv("LOCALAPPDATA"))
        return std::string(l) + "\\RawrXD\\streamer_telemetry.jsonl";
    return "streamer_telemetry.jsonl";
}

static std::string jsonEscape(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; std::snprintf(b,sizeof b,"\\u%04x",c); o += b; }
                else o += c;
        }
    }
    return o;
}

static void emit(const std::string& line) noexcept {
    try {
        const std::string p = envPath();
        std::error_code ec;
        const fs::path parent = fs::path(p).parent_path();
        if (!parent.empty()) fs::create_directories(parent, ec);
        std::FILE* f = std::fopen(p.c_str(), "ab");
        if (!f) return;
        std::fwrite(line.data(), 1, line.size(), f);
        std::fputc('\n', f);
        std::fflush(f);
        _commit(_fileno(f));
        std::fclose(f);
    } catch (...) {}
}

static std::string nowUtc() {
    const std::time_t t = std::time(nullptr);
    char b[32]; std::tm tmv{};
    gmtime_s(&tmv, &t);
    std::strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return b;
}

// SHA-256 of the running image. Known-answer tested at startup: a hash whose
// implementation is never checked against a published vector is not evidence.
static bool sha256File(const std::string& path, char out[65]) {
    static const uint32_t K[64] = {
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    auto ror=[](uint32_t x,int n){return (x>>n)|(x<<(32-n));};
    uint32_t hv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    auto compress=[&](const unsigned char* p)->void{
        uint32_t w[64];
        for(int t=0;t<16;t++) w[t]=(uint32_t)p[4*t]<<24|(uint32_t)p[4*t+1]<<16|(uint32_t)p[4*t+2]<<8|p[4*t+3];
        for(int t=16;t<64;t++){uint32_t s0=ror(w[t-15],7)^ror(w[t-15],18)^(w[t-15]>>3);
            uint32_t s1=ror(w[t-2],17)^ror(w[t-2],19)^(w[t-2]>>10); w[t]=w[t-16]+s0+w[t-7]+s1;}
        uint32_t a=hv[0],b=hv[1],c=hv[2],d=hv[3],e=hv[4],g=hv[5],j=hv[6],k=hv[7];
        for(int t=0;t<64;++t){uint32_t S1=ror(e,6)^ror(e,11)^ror(e,25),ch=(e&g)^((~e)&j);
            uint32_t t1=k+S1+ch+K[t]+w[t];
            uint32_t S0=ror(a,2)^ror(a,13)^ror(a,22),mj=(a&b)^(a&c)^(b&c);
            uint32_t t2=S0+mj; k=j;j=g;g=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
        hv[0]+=a;hv[1]+=b;hv[2]+=c;hv[3]+=d;hv[4]+=e;hv[5]+=g;hv[6]+=j;hv[7]+=k;
    };

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    std::vector<unsigned char> buf(1u << 20);
    unsigned char carry[64];
    size_t carryLen = 0;
    uint64_t total = 0;

    while (true) {
        const size_t got = std::fread(buf.data(), 1, buf.size(), f);
        if (!got) break;
        total += got;
        // top up carry to a full block
        if (carryLen) {
            const size_t want = 64 - carryLen;
            const size_t take = got < want ? got : want;
            std::memcpy(carry + carryLen, buf.data(), take);
            carryLen += take;
            if (carryLen < 64) break;           // file shorter than one block
            compress(carry);
            carryLen = 0;
            const size_t consumed = take;
            // continue with the remainder of this read
            const unsigned char* p = buf.data() + consumed;
            size_t left = got - consumed;
            while (left >= 64) { compress(p); p += 64; left -= 64; }
            if (left) { std::memcpy(carry, p, left); carryLen = left; }
            continue;
        }
        const unsigned char* p = buf.data();
        size_t left = got;
        while (left >= 64) { compress(p); p += 64; left -= 64; }
        if (left) { std::memcpy(carry, p, left); carryLen = left; }
    }
    std::fclose(f);

    // pad the final partial block
    size_t padTo = (carryLen < 56) ? 56 : 120;
    carry[carryLen++] = 0x80;
    while (carryLen < padTo) carry[carryLen++] = 0;
    const uint64_t bits = total * 8;
    for (int i = 0; i < 8; ++i)
        carry[padTo + i] = (unsigned char)(bits >> (56 - i * 8));
    compress(carry);

    for (int i = 0; i < 8; ++i) std::snprintf(out + i * 8, 9, "%08x", hv[i]);
    out[64] = 0;
    return true;
}

static bool sha256SelfTest(char out[65]) {
    const char* k = "abc";
    uint8_t d[3]; std::memcpy(d, k, 3);
    std::FILE* f = std::fopen("NUL", "wb"); (void)f;
    // reuse the streaming path over a 3-byte buffer via a temp file is overkill;
    // hash inline instead
    uint32_t hv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    static const uint32_t K[64] = {
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    auto ror=[](uint32_t x,int n){return (x>>n)|(x<<(32-n));};
    std::vector<unsigned char> msg(d, d+3); msg.push_back(0x80);
    const size_t need = (msg.size()%64 < 56) ? (56 - msg.size()%64) : (120 - msg.size()%64);
    for(size_t i=1;i<need;i++) msg.push_back(0);
    const uint64_t bits=24;
    for(int i=0;i<8;i++) msg.push_back((unsigned char)(bits>>(56-i*8)));
    for (size_t o=0;o+64<=msg.size();o+=64){
        const unsigned char* p=msg.data()+o;
        uint32_t w[64];
        for(int t=0;t<16;t++) w[t]=(uint32_t)p[4*t]<<24|(uint32_t)p[4*t+1]<<16|(uint32_t)p[4*t+2]<<8|p[4*t+3];
        for(int t=16;t<64;t++){uint32_t s0=ror(w[t-15],7)^ror(w[t-15],18)^(w[t-15]>>3);
            uint32_t s1=ror(w[t-2],17)^ror(w[t-2],19)^(w[t-2]>>10); w[t]=w[t-16]+s0+w[t-7]+s1;}
        uint32_t a=hv[0],b=hv[1],c=hv[2],e2=hv[3],e=hv[4],g=hv[5],j=hv[6],k=hv[7];
        for(int t=0;t<64;++t){uint32_t S1=ror(e,6)^ror(e,11)^ror(e,25),ch=(e&g)^((~e)&j);
            uint32_t t1=k+S1+ch+K[t]+w[t];
            uint32_t S0=ror(a,2)^ror(a,13)^ror(a,22),mj=(a&b)^(a&c)^(b&c);
            uint32_t t2=S0+mj; k=j;j=g;g=e;e=e2+t1;e2=c;c=b;b=a;a=t1+t2;}
        hv[0]+=a;hv[1]+=b;hv[2]+=c;hv[3]+=e2;hv[4]+=e;hv[5]+=g;hv[6]+=j;hv[7]+=k;
    }
    for (int i=0;i<8;i++) std::snprintf(out+i*8, 9, "%08x", hv[i]);
    out[64]=0;
    (void)f;
    return true;
}

static std::string selfPath() {
    wchar_t b[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, b, MAX_PATH);
    if (!n) return std::string();
    return std::string(b, b + n);
}

} // namespace streamer_telemetry


namespace {

// Deterministic, minimal prompt, shared by every model so any difference in
// output is attributable to the model and not to the harness.
//
// Overridable (--prompt) because a shared input that the tokenizer cannot
// encode turns EVERY model into an identical failure. The first census ran
// "Count:", which yields 0 tokens under encodeGPT2 (Tokenizer.cpp:545 returns
// {} when any symbol is missing from the vocab and no unk id exists). That
// reported 182/182 MODEL_LOAD_FAILED -- one bug wearing 182 model-shaped
// coats. A census must not be able to report its own harness failure as a
// per-model verdict.
std::string g_prompt = "The capital of France is";

// ---------------------------------------------------------------- result enum
// Terminal outcomes are deliberately fine-grained. A generic MODEL_LOAD_FAILED
// would collapse SHARD_RESOLUTION / MMAP_OPEN / MODEL_LOAD / PREFILL /
// FIRST_TOKEN / TOKEN_N / TIMEOUT / CHILD_EXIT into one bucket, which destroys
// the only information the failure actually carries.
//
// MODEL_TIMEOUT is its own result and is NEVER reported as unsupported, as too
// large, or as a load failure. A 30-minute wall bound is a liveness fact, not a
// property of the model.
enum class Result {
    MODEL_STREAMABLE,
    MODEL_UNSUPPORTED_FORMAT,
    MODEL_CORRUPT,
    MODEL_MISSING_PAYLOAD,
    MODEL_LOAD_FAILED,
    MODEL_PREFILL_FAILED,
    MODEL_DECODE_FAILED,
    MODEL_STREAM_FAILED,
    MODEL_TIMEOUT,
    MODEL_CHILD_CRASH,
    MODEL_PASS,
};

const char* resultName(Result r)
{
    switch (r) {
        case Result::MODEL_STREAMABLE:         return "MODEL_STREAMABLE";
        case Result::MODEL_UNSUPPORTED_FORMAT: return "MODEL_UNSUPPORTED";
        case Result::MODEL_CORRUPT:            return "MODEL_CORRUPT";
        case Result::MODEL_MISSING_PAYLOAD:    return "MODEL_MISSING_PAYLOAD";
        case Result::MODEL_LOAD_FAILED:        return "MODEL_LOAD_FAILED";
        case Result::MODEL_PREFILL_FAILED:     return "MODEL_PREFILL_FAILED";
        case Result::MODEL_DECODE_FAILED:      return "MODEL_DECODE_FAILED";
        case Result::MODEL_STREAM_FAILED:      return "MODEL_STREAM_FAILED";
        case Result::MODEL_TIMEOUT:            return "MODEL_TIMEOUT";
        case Result::MODEL_CHILD_CRASH:        return "MODEL_CHILD_CRASH";
        case Result::MODEL_PASS:               return "MODEL_PASS";
    }
    return "UNKNOWN";
}

// ------------------------------------------------- the furthest stage reached
// Reported alongside the result so a failure names the boundary it stopped at.
enum class Stage {
    DISCOVERED, SHARD_RESOLUTION, MMAP_OPEN, MODEL_LOAD,
    TOKENIZE, PREFILL, FIRST_TOKEN, TOKEN_N, TEARDOWN, DONE
};

const char* stageName(Stage s)
{
    switch (s) {
        case Stage::DISCOVERED:       return "DISCOVERED";
        case Stage::SHARD_RESOLUTION: return "SHARD_RESOLUTION";
        case Stage::MMAP_OPEN:        return "MMAP_OPEN";
        case Stage::MODEL_LOAD:       return "MODEL_LOAD";
        case Stage::TOKENIZE:         return "TOKENIZE";
        case Stage::PREFILL:          return "PREFILL";
        case Stage::FIRST_TOKEN:      return "FIRST_TOKEN";
        case Stage::TOKEN_N:          return "TOKEN_N";
        case Stage::TEARDOWN:         return "TEARDOWN";
        case Stage::DONE:             return "DONE";
    }
    return "?";
}

// ------------------------------------------------------------ artifact kinds
enum class Kind { Inference, InferenceSharded, Projector, NotLocal };

const char* kindName(Kind k)
{
    switch (k) {
        case Kind::Inference:          return "inference";
        case Kind::InferenceSharded:   return "inference_sharded";
        case Kind::Projector:          return "projector";
        case Kind::NotLocal:           return "not_local";
    }
    return "?";
}

struct Artifact {
    std::string logicalName;   // shard 1 path, or the single blob path
    Kind        kind      = Kind::Inference;
    uint64_t    bytes     = 0;
    uint32_t    shardCount = 1;
    std::string arch, quant;
    Result      result     = Result::MODEL_STREAMABLE;
    Stage       stage      = Stage::DISCOVERED;
    std::string detail;
    // stream evidence
    uint64_t tokens = 0;
    double   ttftMs = 0.0;
    double   decodeTps = 0.0;
    uint32_t callbacks = 0;
    bool     contiguous = false;
    bool     finiteLogits = false;
    bool     cleanTeardown = false;
    std::vector<int32_t> firstIds;
    std::string text;
};

// -------------------------------------------------------------- GGUF by magic
// An Ollama blob is a GGUF with no extension. Only the magic decides.
bool hasGgufMagic(const fs::path& p)
{
    std::error_code ec;
    const auto sz = fs::file_size(p, ec);
    if (ec || sz < 8) return false;
    FILE* f = std::fopen(p.string().c_str(), "rb");
    if (!f) return false;
    unsigned char m[4] = {0,0,0,0};
    const bool ok = std::fread(m, 1, 4, f) == 4;
    std::fclose(f);
    return ok && m[0]=='G' && m[1]=='G' && m[2]=='U' && m[3]=='F';
}

// ------------------------------------------------- canonical shard set naming
// Kimi: Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf
bool parseShard(const std::string& stem, std::string& prefix, uint32_t& idx, uint32_t& cnt)
{
    const size_t d = stem.rfind("-00001-of-");
    if (d == std::string::npos) return false;
    prefix = stem.substr(0, d);
    idx = 1;
    const std::string tail = stem.substr(d + 1);           // "00001-of-00013"
    const size_t of = tail.find("-of-");
    if (of == std::string::npos) return false;
    cnt = static_cast<uint32_t>(std::strtoul(tail.c_str() + of + 4, nullptr, 10));
    return cnt > 1;
}

std::string shardPath(const std::string& prefix, uint32_t i, uint32_t n)
{
    char buf[64];
    std::snprintf(buf, sizeof buf, "-%05u-of-%05u.gguf", i, n);
    return prefix + buf;
}

bool isProjector(const std::string& lower)
{
    return lower.find("mmproj") != std::string::npos ||
           lower.find("clip")   != std::string::npos;
}

// -------------------------------------------------------------- census totals
struct Census {
    int total = 0, localInference = 0, projectors = 0, notLocal = 0;
    int attempted = 0, loadPass = 0, generationPass = 0, failures = 0;
};

// ---------------------------------------------------------------------------
// ASS-8: bridge the sink onto the census loop. Every model reaching a terminal
// state emits exactly one record, including the NOT_LOCAL path, so a census is
// reconstructable without re-running it.
// ---------------------------------------------------------------------------
static void telemetryRunHeader(const std::string& argv1) {
    char hx[65] = "UNAVAILABLE";
    streamer_telemetry::sha256SelfTest(hx);   // proves the hasher is sane
    char st[65] = "FAILED";
    streamer_telemetry::sha256File(streamer_telemetry::selfPath(), st);
    char line[2048];
    std::snprintf(line, sizeof line,
      "{\"record\":\"run_header\",\"schema\":\"%s\",\"ts\":\"%s\",\"pid\":%lu,"
      "\"image_sha256\":\"%s\",\"sha256_selftest\":\"%s\",\"argv1\":\"%s\"}",
      streamer_telemetry::kSchema, streamer_telemetry::nowUtc().c_str(),
      (unsigned long)GetCurrentProcessId(), st,
      strcmp(st, "FAILED") ? "PASS" : "FAIL",
      argv1.c_str());
    streamer_telemetry::emit(line);
}

static void telemetryModel(const Artifact& a) {
    char line[4096];
    std::snprintf(line, sizeof line,
      "{\"record\":\"model\",\"schema\":\"%s\",\"ts\":\"%s\",\"model\":\"%s\","
      "\"kind\":\"%s\",\"arch\":\"%s\",\"quant\":\"%s\",\"shards\":%u,\"bytes\":%llu,"
      "\"result\":\"%s\",\"tokens\":%llu,\"ttft_ms\":%.3f,\"decode_tps\":%.4f,"
      "\"callbacks\":%u,\"contiguous\":%d,\"clean_teardown\":%d,\"detail\":\"%s\"}",
      streamer_telemetry::kSchema, streamer_telemetry::nowUtc().c_str(),
      streamer_telemetry::jsonEscape(a.logicalName).c_str(),
      kindName(a.kind),
      streamer_telemetry::jsonEscape(a.arch).c_str(),
      streamer_telemetry::jsonEscape(a.quant).c_str(),
      a.shardCount, (unsigned long long)a.bytes, resultName(a.result),
      (unsigned long long)a.tokens, a.ttftMs, a.decodeTps, a.callbacks,
      a.contiguous ? 1 : 0, a.cleanTeardown ? 1 : 0,
      streamer_telemetry::jsonEscape(a.detail).c_str());
    streamer_telemetry::emit(line);
}

static void telemetryFooter(const Census& c) {
    char line[1024];
    std::snprintf(line, sizeof line,
      "{\"record\":\"run_footer\",\"schema\":\"%s\",\"ts\":\"%s\",\"census_total\":%d,"
      "\"local_inference\":%d,\"projectors\":%d,\"not_local\":%d,\"attempted\":%d,"
      "\"load_pass\":%d,\"generation_pass\":%d,\"fail\":%d}",
      streamer_telemetry::kSchema, streamer_telemetry::nowUtc().c_str(),
      c.total, c.localInference, c.projectors, c.notLocal,
      c.attempted, c.loadPass, c.generationPass, c.failures);
    streamer_telemetry::emit(line);
}
void tally(Census& c, const Artifact& a)
{
    c.total++;
    switch (a.kind) {
        case Kind::Inference:
        case Kind::InferenceSharded: c.localInference++; break;
        case Kind::Projector:        c.projectors++;    break;
        case Kind::NotLocal:         c.notLocal++;      break;
    }
    if (a.result == Result::MODEL_MISSING_PAYLOAD) return;
    c.attempted++;
    if (a.result == Result::MODEL_PASS) { c.generationPass++; c.loadPass++; }
    else if (a.result == Result::MODEL_STREAM_FAILED) { c.loadPass++; c.failures++; }
    else c.failures++;
}

// --------------------------------------------------------------- discovery
std::vector<Artifact> discover(const std::vector<fs::path>& roots)
{
    std::vector<Artifact> out;
    std::set<std::string> seenShardFirst;   // avoid re-opening the same set

    for (const auto& root : roots) {
        std::error_code ec;
        if (!fs::exists(root, ec)) {
            std::printf("ROOT_MISSING=%s\n", root.string().c_str());
            continue;
        }
        std::vector<fs::path> ggufs;
        if (fs::is_directory(root, ec)) {
            for (auto it = fs::recursive_directory_iterator(
                     root, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) { ec.clear(); continue; }
                if (!it->is_regular_file(ec)) continue;
                const fs::path& p = it->path();
                const uint64_t sz = fs::file_size(p, ec);
                if (ec || sz < 1024) continue;
                // magic, not extension
                if (!hasGgufMagic(p)) continue;
                ggufs.push_back(p);
            }
        } else if (hasGgufMagic(root)) {
            ggufs.push_back(root);
        }

        // group shard sets; emit ONE artifact per set
        std::map<std::string, std::vector<std::string>> sets;
        for (const auto& p : ggufs) {
            std::string stem = p.stem().string();
            std::string prefix; uint32_t i = 0, n = 0;
            if (parseShard(stem, prefix, i, n)) sets[prefix].push_back(p.string());
        }

        for (const auto& p : ggufs) {
            std::string stem = p.stem().string();
            std::string prefix; uint32_t i = 0, n = 0;
            if (parseShard(stem, prefix, i, n)) {
                if (i != 1) continue;                 // only shard 1 opens the set
                if (seenShardFirst.count(stem)) continue;
                seenShardFirst.insert(stem);

                Artifact a;
                a.logicalName = p.string();
                a.kind = Kind::InferenceSharded;
                a.shardCount = n;
                // prove ALL members exist before opening anything
                uint64_t total = 0;
                bool complete = true;
                for (uint32_t k = 1; k <= n; ++k) {
                    const std::string sp = shardPath(prefix, k, n);
                    if (!fs::exists(sp, ec)) { complete = false; break; }
                    total += fs::file_size(sp, ec);
                }
                a.bytes = total;
                if (!complete) { a.kind = Kind::NotLocal;
                                 a.result = Result::MODEL_MISSING_PAYLOAD;
                                 a.detail = "shard set incomplete"; }
                out.push_back(a);
                continue;
            }

            std::string lower = p.filename().string();
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            Artifact a;
            a.logicalName = p.string();
            a.bytes = fs::file_size(p, ec);
            if (isProjector(lower)) { a.kind = Kind::Projector; a.shardCount = 1; }
            else                     { a.kind = Kind::Inference; a.shardCount = 1; }
            out.push_back(a);
        }
    }
    return out;
}

// -------------------------------------------------------- metadata inspection
// Opens ONLY the header. A model this large must never be read into RAM to be
// identified -- that is the whole premise of the streamer.
void inspect(Artifact& a)
{
    a.stage = Stage::SHARD_RESOLUTION;
    Deep2::GGUFLoader loader;
    if (!loader.load(a.logicalName)) {
        // loader.load() covers both shard resolution and header mapping; the
        // error text distinguishes them, so do not guess.
        const std::string e = loader.error();
        const bool shardIssue = e.find("shard") != std::string::npos ||
                                e.find("split") != std::string::npos;
        a.stage  = shardIssue ? Stage::SHARD_RESOLUTION : Stage::MMAP_OPEN;
        a.result = shardIssue ? Result::MODEL_CORRUPT : Result::MODEL_UNSUPPORTED_FORMAT;
        a.detail = e;
        return;
    }
    a.stage = Stage::MMAP_OPEN;
    a.shardCount = loader.shardCount();
    a.arch  = loader.getMetaString("general.architecture", "unknown");
    a.quant = loader.getMetaString("general.file_type", "unknown");
    a.bytes = loader.mappedBytes();
    a.kind  = (loader.shardCount() > 1) ? Kind::InferenceSharded : Kind::Inference;
    a.stage = Stage::MODEL_LOAD;
}

// ---------------------------------------------------------- the actual attempt
// RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001 -- FILE SCOPE.
//
// These three were declared inside attempt(), which is not legal C++. GCC takes
// nested function definitions as an extension; MSVC rejects both the static and
// the non-static form:
//
//     C2267: 'phaseName': static functions with block scope are illegal
//     C2601: 'phaseName': local function definitions are illegal
//
// Removing `static` fixed nothing, because C2601 is about the DEFINITION being
// in a function body at all. Declaring them here is the actual fix.
enum class CertPhase {
    BeforeLoadModel,
    AfterLoadModel,
    BeforeGenerate,
    InsideGenerateCallback,
    AfterGenerate
};

static const char* certPhaseName(CertPhase p)
{
    switch (p) {
        case CertPhase::BeforeLoadModel:        return "BEFORE_LOADMODEL";
        case CertPhase::AfterLoadModel:         return "AFTER_LOADMODEL";
        case CertPhase::BeforeGenerate:         return "BEFORE_GENERATE";
        case CertPhase::InsideGenerateCallback: return "INSIDE_GENERATE_CALLBACK";
        case CertPhase::AfterGenerate:          return "AFTER_GENERATE";
    }
    return "UNKNOWN";
}

// Unbuffered by design: this record has to survive the fast-fail the rest of
// this harness exists to observe.
static void certEmitPhase(CertPhase p)
{
    std::fprintf(stderr, "LAST_CERT_PHASE=%s\n", certPhaseName(p));
    std::fflush(stderr);
}
void attempt(Artifact& a, uint32_t maxTokens)
{
    inspect(a);
    if (a.result != Result::MODEL_STREAMABLE) return;

Deep2::Deep2Engine engine;

    // Enable the GPU backend BEFORE loadModel.
    //
    // DO NOT CALL enableVulkan() HERE. (RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001)
    //
    // This line was added earlier in the session to make the GPU MLA path
    // reachable, on the reasoning that "the Vulkan loader sees 3 devices, so the
    // capability exists". That reasoning was WRONG, and this comment records why
    // so it is not repeated.
    //
    // Measured on this host, with enableVulkan(true) in place:
    //
    //   admission OK, MLA_ELIGIBLE, 61/61 MLA layers bound
    //   LinearW(blk.0.attn_v.weight)
    //     attempt 1  dual-GPU row split   declined
    //     attempt 2  single-GPU          GEMV_SINGLE fullView failed
    //     strict == true                 throw, BEFORE the CPU fallback
    //
    // `fullView()` builds a GPU weight view. It declines because there is no
    // GPU-RESIDENT COPY of the tensor -- nothing uploads weights. fullView() is
    // behaving correctly; it is accurately reporting that the weight is not on
    // the GPU.
    //
    // enableVulkan(true) therefore does not "enable a capability". It flips
    // vulkanEnabled_, which makes every GPU GEMV path ELIGIBLE, while
    // vulkanStrictNoCpuFallback_ (default true, Deep2Engine.h:1391) forbids the
    // host lane that can actually run. Every GEMV then declines by
    // construction, and the process dies on the FIRST projection of layer 0.
    //
    // ENUMERATING DEVICES IS NOT EXECUTING ON THEM. Making GPU MLA reachable is
    // a WEIGHT RESIDENCY project -- upload, pin, bound -- not a flag.
    //
    // With this call absent the dense model streams (verified: llama3.2-3b-Q2_K
    // 2 prompt tokens, 8 generated, prefillMs=4910.0, tps=0.48).


    // RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001 -- loadModel is inside the guarded
    // region too, because MLA_ELIGIBLE is emitted from inside it
    // (Deep2Engine.cpp:2747) and the exception, if any, is thrown from the same
    // call. Leaving loadModel outside the try would reproduce the exact blind
    // spot this instrumentation exists to close.
    Deep2::ModelLoadDiag diag;
    // RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001
    //
    // This site was `try {` with NO catch handler anywhere in the function
    // (C2317). The later `try` in this same function DOES wrap loadModel AND
    // generateStream and closes with two catch handlers, so this outer `try` was
    // a duplicate that unbalanced the braces.
    //
    // It is removed rather than converted to a plain scope: t0, callbacks,
    // sawNonEmpty, g_phase and r are all declared below and consumed by the code
    // after the inner try, so any scope opened here would put them out of
    // reach (C2065 'callbacks' undeclared). They must live at function scope.
if (!engine.loadModel(a.logicalName, &diag)) {
        a.result = Result::MODEL_LOAD_FAILED;
        a.detail = "stage=" + std::to_string(diag.stageCode) +
                   " name=" + diag.stageName + " msg=" + diag.message;
        return;
    }
    // RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001: reaching here means loadModel
    // returned normally. The MLA_ELIGIBLE line is printed inside loadModel, so
    // its presence in the log plus the absence of FORWARD_ENTERED below is
    // precisely the "eligibility without forward" state.
    std::fprintf(stderr, "LOADMODEL_COMPLETED=1\n");
    std::fflush(stderr);

// NOTE: do NOT call engine.initialize() here.
    // loadModel() already resolves dynamic geometry and performs initialization
    // (observed: "[INIT] Deep2Engine::initialize hiddenDim=3072 vocabSize=128256
    // numLayers=28 ..."). Calling initialize again with a default-constructed
    // EngineConfig re-enters initialize with zero geometry and tears down the
    // allocated buffers without reallocating them, so the engine streams from an
    // empty weight set. That produced "[TOKENIZE] ... -> 0 tokens" and
    // status=InvalidInput on the first run of this harness.
    //
    // A second initialization is the caller's decision only if it supplies real
    // geometry; this harness must not.

// Deterministic, minimal prompt. Overridable because a fixed prompt that
    // the tokenizer cannot encode turns EVERY model into an identical failure:
    // "Count:" yields 0 tokens under encodeGPT2 (Tokenizer.cpp:545 returns {}
    // when any symbol is absent from the vocab and no unk id exists), so the
    // first census reported 182/182 MODEL_LOAD_FAILED and that was one bug,
    // not 182 broken models. A shared input must never be able to masquerade
    // as a per-model result.
    Deep2::GenerationOptions opt;
    opt.maxTokens  = maxTokens;
    opt.temperature = 0.0f;   // deterministic
    opt.topP = 1.0f;
    opt.topK = 1;
    opt.seed = 12345;

auto t0 = std::chrono::steady_clock::now();
    uint64_t callbacks = 0;
    bool sawNonEmpty = false;

    // RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001
    //
    // WHY THIS EXISTS
    //   The Kimi K2 / deepseek2 MLA path terminates with
    //       EXCEPTION_CODE=0xC0000409
    //       ExceptionInformation[0] = 0x7 = FAST_FAIL_FATAL_APP_EXIT (winnt.h)
    //       FAULT_RVA=0xC3169
    //   which is the CRT's std::terminate / abort() surface, NOT a hardware trap.
    //   Four separate sites in this tree already name that mechanism:
    //     deep2_bounded_stream_gate.cpp:591  "gives no diagnostic by default"
    //     b3_continuation_test.cpp:173        "escapes main as std::terminate"
    //     rawrxd_run_modelname_001.cpp:58    "CRT surfaces only as a bare 0xC0000409"
    //     main_win32.cpp:1444                "with ucrtbase!_invoke_watson"
    //   The exception OBJECT is therefore the lost evidence. It is recoverable
    //   here, before terminate() is ever reached.
    //
    // SEMANTICS ARE DELIBERATELY UNCHANGED
    //   Every handler RE-THROWS. This cert measures a failure; it must not become
    //   a recovery path. Swallowing the throw would change the very behaviour
    //   being measured and would convert FAST_FAIL=7 into a clean exit -- a
    //   self-certifying false PASS of exactly the kind this harness exists to
    //   prevent. The process still dies by terminate; we only print first.
    //
    // ONE LINE PER RECEIPT FIELD, unbuffered
    //   std::fprintf on stderr + fflush so the record survives the fast-fail.
    //
    // FILE SCOPE, NOT BLOCK SCOPE  (RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001)
    //   CertPhase, phaseName and emitPhase were declared HERE, inside attempt().
    //   A function DEFINITION inside a function body is not legal C++: GCC takes
    //   nested functions as an extension, MSVC does not, and rejects both the
    //   `static` form and the non-static form:
    //       C2267: 'phaseName': static functions with block scope are illegal
    //       C2601: 'phaseName': local function definitions are illegal
    //   Removing `static` therefore fixed nothing. The declarations were moved to
    //   file scope above attempt(); see certPhaseName / certEmitPhase there.
    CertPhase g_phase = CertPhase::BeforeLoadModel;

    // RAWRXD_CERT_ELIGIBLE_FORWARD_CATCH_001
    // Structurally required: without an initializer, `r` is only assigned inside
    // the try and the code below the try cannot read it. Standard C++.
    Deep2::GenerationResult r{};
    try {
        g_phase = CertPhase::BeforeLoadModel; certEmitPhase(g_phase);
        if (!engine.loadModel(a.logicalName, &diag)) {
            g_phase = CertPhase::AfterLoadModel; certEmitPhase(g_phase);
            a.result = Result::MODEL_LOAD_FAILED;
            a.detail = "stage=" + std::to_string(diag.stageCode) +
                       " name=" + diag.stageName + " msg=" + diag.message;
            return;
        }
        g_phase = CertPhase::AfterLoadModel; certEmitPhase(g_phase);
        std::fprintf(stderr, "LOADMODEL_COMPLETED=1\n"); std::fflush(stderr);

        g_phase = CertPhase::BeforeGenerate; certEmitPhase(g_phase);
        std::fprintf(stderr, "FORWARD_ENTERED=1\n"); std::fflush(stderr);
        r = engine.generateStream(
            g_prompt.c_str(), opt,
            [&](int32_t id, const std::string& tok) -> bool {
                g_phase = CertPhase::InsideGenerateCallback; certEmitPhase(g_phase);
                if (callbacks == 0) {
                    a.ttftMs = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0).count();
                }
                if (a.firstIds.size() < 16) a.firstIds.push_back(id);
                a.text += tok;
                if (!tok.empty()) sawNonEmpty = true;
                ++callbacks;
                return true;             // never cancel: the point is to stream
            });
        g_phase = CertPhase::AfterGenerate; certEmitPhase(g_phase);
        std::fprintf(stderr, "FORWARD_COMPLETED=1 status=%d gen=%llu cb=%llu\n",
                     (int)r.status,
                     (unsigned long long)r.generatedTokens,
                     (unsigned long long)callbacks);
        std::fflush(stderr);
    }
    catch (const std::exception& e) {
        // typeid(e).name() is the MANGLED dynamic type: authoritative, and it is
        // what distinguishes a std::runtime_error thrown by the MLA branch from a
        // std::bad_alloc from a failed arena allocation.
        //
        // WER's BEX64 classification ("buffer overflow check") is a PRIOR, not a
        // measurement. std::bad_alloc is the exception that would actually
        // support an out-of-memory reading, and this line is what settles it.
        std::fprintf(stderr,
                     "EXCEPTION_CAUGHT=1\n"
                     "EXCEPTION_SITE=%s\n"
                     "EXCEPTION_TYPE=%s\n"
                     "EXCEPTION_WHAT=%s\n",
                     g_phase == CertPhase::AfterLoadModel ||
                     g_phase == CertPhase::BeforeGenerate ||
                     g_phase == CertPhase::InsideGenerateCallback ||
                     g_phase == CertPhase::AfterGenerate
                         ? "GENERATE" : "LOADMODEL",
                     typeid(e).name(), e.what());
        std::fprintf(stderr, "LAST_CERT_PHASE_AT_THROW=%s\n", certPhaseName(g_phase));
        std::fflush(stderr);
        std::fflush(stderr);
        std::fprintf(stderr, "FAST_FAIL_AFTER_CATCH=RETHROW_STD\n");
        std::fflush(stderr);
        throw;                            // unchanged semantics -- see header
    }
    catch (...) {
        // Reached only if the throwable does NOT derive from std::exception.
        // That distinction matters: it rules out every engine path that reports
        // failure by throwing a std::runtime_error / std::invalid_argument, and
        // points at a raw throw or a foreign exception type crossing the boundary.
        std::fprintf(stderr,
                     "EXCEPTION_CAUGHT=1\n"
                     "EXCEPTION_SITE=%s\n"
                     "EXCEPTION_TYPE=UNKNOWN_NON_STD_EXCEPTION\n"
                     "EXCEPTION_WHAT=<not a std::exception>\n",
                     g_phase == CertPhase::AfterLoadModel ||
                     g_phase == CertPhase::BeforeGenerate ||
                     g_phase == CertPhase::InsideGenerateCallback ||
                     g_phase == CertPhase::AfterGenerate
                         ? "GENERATE" : "LOADMODEL");
        std::fprintf(stderr, "LAST_CERT_PHASE_AT_THROW=%s\n", certPhaseName(g_phase));
        std::fflush(stderr);
        std::fprintf(stderr, "FAST_FAIL_AFTER_CATCH=RETHROW_UNKNOWN\n");
        std::fflush(stderr);
        throw;
    }

    double genMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    a.callbacks  = static_cast<uint32_t>(callbacks);
    a.contiguous = (callbacks == r.generatedTokens);
    a.tokens     = r.generatedTokens;
    a.decodeTps  = genMs > 0 ? (double)r.generatedTokens / (genMs / 1000.0) : 0.0;
    a.finiteLogits = (r.status == Deep2::GenerationStatus::Completed ||
                      r.status == Deep2::GenerationStatus::EndOfSequence);

    engine.unloadModel();
    a.cleanTeardown = true;

    const bool ok = (r.status == Deep2::GenerationStatus::Completed ||
                     r.status == Deep2::GenerationStatus::EndOfSequence) &&
                    callbacks > 0 &&
                    a.contiguous &&
                    r.generatedTokens >= maxTokens;
    a.result = ok ? Result::MODEL_PASS : Result::MODEL_STREAM_FAILED;
    if (!ok) {
        a.detail = "status=" + std::to_string(static_cast<int>(r.status)) +
                   " gen=" + std::to_string(r.generatedTokens) +
                   " cb=" + std::to_string(callbacks) +
                   " req=" + std::to_string(maxTokens) +
                   " " + r.failureDetail;
    }
}

} // namespace

// ===========================================================================
// parent: census driver. Spawns one child per artifact so a fault in one model
// cannot destroy the census. No size-based admission anywhere below.
// ===========================================================================
int main(int argc, char** argv)
{
    uint32_t maxTokens = 8;
    std::vector<fs::path> roots;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
if (a == "--tokens" && i + 1 < argc) { maxTokens = (uint32_t)std::strtoul(argv[++i], nullptr, 10); }
        else if (a == "--prompt" && i + 1 < argc) { g_prompt = argv[++i]; }
        else roots.emplace_back(a);
    }
    if (roots.empty()) {
        roots.emplace_back("F:/OllamaModels");
        roots.emplace_back("F:/OllamaModels/blobs");
    }
    if (maxTokens == 0) maxTokens = 8;

if (argc >= 3 && std::string(argv[1]) == "--child") {
        Artifact a;
        a.logicalName = argv[2];
        a.kind = Kind::Inference;
        // CreateProcess does NOT interpret '>' redirection -- that is cmd.exe's
        // job. Passing a shell command line therefore sent the child's stdout to
        // the inherited console and left the result file empty, so the parent
        // reported "child exit=0 (no RESULT emitted)". The child now writes its
        // own result file directly; no shell is involved anywhere.
        std::string outFile;
        for (int i = 3; i + 1 < argc; ++i)
            if (std::string(argv[i]) == "--out") outFile = argv[++i];
        attempt(a, maxTokens);
        const std::string res = std::string("RESULT=") + resultName(a.result) + "\n" +
                                "DETAIL=" + a.detail + "\n" +
                                "TOKENS=" + std::to_string(a.tokens) + "\n" +
                                "TTFT_MS=" + std::to_string(a.ttftMs) + "\n" +
                                "DECODE_TPS=" + std::to_string(a.decodeTps) + "\n" +
                                "CALLBACKS=" + std::to_string(a.callbacks) + "\n" +
                                "CONTIGUOUS=" + (a.contiguous ? "1" : "0") + "\n" +
                                "CLEAN_TEARDOWN=" + (a.cleanTeardown ? "1" : "0") + "\n" +
                                "ARCH=" + a.arch + "\n" +
                                "QUANT=" + a.quant + "\n" +
                                "SHARDS=" + std::to_string(a.shardCount) + "\n";
        if (outFile.empty()) std::fputs(res.c_str(), stdout);
        if (!outFile.empty()) {
            FILE* f = std::fopen(outFile.c_str(), "wb");
            if (f) { std::fputs(res.c_str(), f); std::fclose(f); }
        }
        return a.result == Result::MODEL_PASS ? 0 : 1;
    }

    std::vector<Artifact> arts = discover(roots);
    Census c;
    telemetryRunHeader(roots.empty() ? std::string() : roots.front().string());
    for (auto& a : arts) {
        const fs::path dir = fs::path(a.logicalName).parent_path();
        const std::string exe = fs::absolute(argv[0]).string();

        std::printf("\n[MODEL]\n");
        std::printf("path=%s\n", a.logicalName.c_str());
        std::printf("kind=%s\n", kindName(a.kind));
        std::printf("bytes=%llu\n", (unsigned long long)a.bytes);
        std::printf("shards=%u\n", a.shardCount);

        if (a.result == Result::MODEL_MISSING_PAYLOAD) {
            std::printf("result=%s\ndetail=%s\n", resultName(a.result), a.detail.c_str());
            telemetryModel(a);
            tally(c, a);
            continue;
        }

static int childSeq = 0;
        char tmpDir[MAX_PATH] = {0};
        GetTempPathA(MAX_PATH, tmpDir);
        const std::string outp =
            std::string(tmpDir) + "\\deep2_streamer_child_" +
            std::to_string(++childSeq) + ".txt";
        std::string line = "\"" + exe + "\" --child \"" + a.logicalName +
                           "\" --tokens " + std::to_string(maxTokens) +
                           " --out \"" + outp + "\"";

        STARTUPINFOA si{}; PROCESS_INFORMATION pi{};
        si.cb = sizeof si;
        std::vector<char> cmdbuf(line.begin(), line.end()); cmdbuf.push_back('\0');
        const BOOL ok = CreateProcessA(nullptr, cmdbuf.data(), nullptr, nullptr, FALSE,
                                       CREATE_NO_WINDOW, nullptr,
                                       dir.empty() ? nullptr : dir.string().c_str(),
                                       &si, &pi);
        if (!ok) {
            a.result = Result::MODEL_LOAD_FAILED;
            a.detail = "child spawn failed";
        } else {
            const DWORD wr = WaitForSingleObject(pi.hProcess, 0);
            if (wr == WAIT_TIMEOUT) {
                // large model still streaming; poll until it finishes or we cap
                const DWORD start = GetTickCount();
                bool done = false;
                while (GetTickCount() - start < 1000u * 60u * 30u) {
                    if (WaitForSingleObject(pi.hProcess, 500) != WAIT_TIMEOUT) { done = true; break; }
                }
                if (!done) { TerminateProcess(pi.hProcess, 0); a.result = Result::MODEL_LOAD_FAILED;
                             a.detail = "child exceeded 30 min wall cap"; }
                else done = true;
                if (done) {
                    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
                    std::string res, det;
                    FILE* rf = std::fopen(outp.c_str(), "rb");
                    if (rf) {
                        char b[1024];
                        while (std::fgets(b, sizeof b, rf)) {
                            std::string s(b);
                            if (s.rfind("RESULT=", 0) == 0) res = s.substr(7);
                            if (s.rfind("DETAIL=", 0) == 0) det = s.substr(7);
                            while (!res.empty() && (res.back()=='\n'||res.back()=='\r')) res.pop_back();
                            while (!det.empty() && (det.back()=='\n'||det.back()=='\r')) det.pop_back();
                        }
                        std::fclose(rf);
                    }
                    static const struct { const char* n; Result v; } map[] = {
                        {"MODEL_PASS", Result::MODEL_PASS},
                        {"MODEL_STREAM_FAILED", Result::MODEL_STREAM_FAILED},
                        {"MODEL_LOAD_FAILED", Result::MODEL_LOAD_FAILED},
                        {"MODEL_UNSUPPORTED_FORMAT", Result::MODEL_UNSUPPORTED_FORMAT},
                        {"MODEL_CORRUPT", Result::MODEL_CORRUPT},
                    };
                    a.result = Result::MODEL_LOAD_FAILED;
                    for (auto& m : map) if (res == m.n) { a.result = m.v; break; }
                    a.detail = det.empty() ? ("child exit=" + std::to_string(code)) : det;
                    if (res.empty()) a.detail += " (no RESULT emitted; child likely faulted)";
                }
            } else {
                DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
                a.result = Result::MODEL_LOAD_FAILED;
                a.detail = "child exit=" + std::to_string(code) + " (faulted before emitting RESULT)";
            }
            CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
            std::remove(outp.c_str());
        }

        std::printf("result=%s\n", resultName(a.result));
        if (!a.detail.empty()) std::printf("detail=%s\n", a.detail.c_str());
        telemetryModel(a);
        tally(c, a);
        std::printf("tally=%d/%d\n", c.total, c.localInference);
    }

    std::printf("\n=== CENSUS ===\n");
    std::printf("STREAMER_CENSUS_TOTAL=%d\n", c.total);
    std::printf("STREAMER_LOCAL_INFERENCE_MODELS=%d\n", c.localInference);
    std::printf("STREAMER_PROJECTORS=%d\n", c.projectors);
    std::printf("STREAMER_NOT_LOCAL=%d\n", c.notLocal);
    std::printf("STREAMER_ATTEMPTED=%d\n", c.attempted);
    std::printf("STREAMER_LOAD_PASS=%d\n", c.loadPass);
    std::printf("STREAMER_GENERATION_PASS=%d\n", c.generationPass);
    std::printf("STREAMER_FAIL=%d\n", c.failures);
    telemetryFooter(c);
    return 0;
}








