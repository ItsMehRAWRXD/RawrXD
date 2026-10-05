#define NOMINMAX
// windows.h defines min/max as macros, which breaks every std::min/std::max
// call below. NOMINMAX is defined before ANY include so that whichever header
// pulls in windows.h first still sees it.

// ============================================================================
// nqb_production_reopen.cpp
// RAWRXD_NQB_PRODUCTION_REOPEN_001
//
// The production reopen gate for nanof32braid (.nqb) model containers.
//
// WHY A NEW INSTRUMENT
// --------------------
// The previous reopen probe (tools/nqb_reopen_parity_probe.cpp) called
// Nanof32BraidStreamer::readAllTensors(), which materialises EVERY tensor
// simultaneously. For the real artifact that is 3,212,749,888 elements:
// 12.85 GB of payloads and 6.43 GB of bfloat16 output live at the same instant,
// plus one transient compressed buffer per tensor. The instrument that was
// meant to prove the container reopens cannot run against the container that
// exists.
//
// SCOPE OF THE CLAIMS, STATED PRECISELY
// -------------------------------------
//   PHASE 1  STRUCTURAL.  Reverse footer chain walked one record at a time with
//            overflow-checked arithmetic, per-step geometry recorded, plus a
//            single sequential pass that hashes the whole file (SHA-256) and
//            scans every payload for NaN/Inf while producing per-tensor FNV-1a
//            digests. Bounded memory: one 8 MiB buffer.
//
//   PHASE 2  READER SELF-CONSISTENCY.  Nanof32BraidStreamer is driven one
//            tensor at a time and its output is compared, per tensor, against
//            (a) the payload bytes on disk and (b) bf16 computed with
//            Deep2::Float32ToBF16Bits -- the SAME primitive bfloat16_t(float)
//            calls. That proves the reader reproduced its own policy. It does
//            NOT prove the BF16 policy is numerically correct: the conversion is
//            a truncation, and a truncation is a deliberate loss of precision.
//            Independent BF16 correctness is a separate gate and is not claimed
//            here. This distinction is reported in the receipt as
//            READER_BF16_SELF_CONSISTENCY vs BF16_CONVERSION_INDEPENDENT_ORACLE
//            (the latter is always NOT_CLAIMED_HERE).
//
//   PHASE 3  FALSIFICATION.  A positive control (the verifier accepts an
//            uncorrupted file produced by the real writer) then four negative
//            controls, each of which must be DETECTED BY NAME through the same
//            verifier: payload byte flip, footer magic zeroed, one-byte
//            truncation, and stored headDim halved.
//
// NOTHING here asserts success. Every printed field is an observation. The
// verdict is computed. Exit 0 = PASS, 1 = FAIL, 2 = INVALID (the gate could not
// establish authority -- bad invocation, incomplete read, tool error).
//
// EXPECTED tensor/element/file-size counts are CLI INPUTS, never baked-in
// sources of truth: the gate measures and then compares against what the caller
// expected.
//
// Usage:
//   nqb_production_reopen <file.nqb> [options]
//     --expect-tensors N      --expect-elements N      --expect-file-bytes N
//     --manifest out.txt      --expect-manifest m.txt
//     --no-reader             --reader-cap-mb N
//     --negative-controls DIR --receipt out.txt
// ============================================================================

#include "deep2/Nanof32BraidFormat.hpp"
#include "deep2/Nanof32BraidStreamer.hpp"
#include "deep2/Nanof32BraidWriter.hpp"
#include "deep2/Nanof32BraidManifest.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows.h>

namespace {

// ===========================================================================
// SHA-256 -- used for tool/source/target identity so a receipt can be bound to
// the exact binary and the exact bytes it judged.
// ===========================================================================
struct Sha256 {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   bl;

    Sha256() {
        h[0]=0x6a09e667u; h[1]=0xbb67ae85u; h[2]=0x3c6ef372u; h[3]=0xa54ff53au;
        h[4]=0x510e527fu; h[5]=0x9b05688cu; h[6]=0x1f83d9abu; h[7]=0x5be0cd19u;
        total = 0; bl = 0;
    }
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
            0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
            0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
            0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
            0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
            0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
            0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
            0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
            0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|
                   (uint32_t(p[i*4+2])<<8)|uint32_t(p[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            const uint32_t ch = (e & f) ^ ((~e) & g);
            const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            const uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const void* d, size_t n) {
        const uint8_t* p = static_cast<const uint8_t*>(d);
        total += n;
        if (bl) {
            const size_t take = std::min(n, size_t(64) - bl);
            std::memcpy(buf + bl, p, take);
            bl += take; p += take; n -= take;
            if (bl == 64) { block(buf); bl = 0; }
        }
        while (n >= 64) { block(p); p += 64; n -= 64; }
        if (n) { std::memcpy(buf, p, n); bl = n; }
    }

    std::string hex() {
        // `bits` is captured BEFORE padding is appended, because update()
        // counts the padding into `total` too.
        const uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        pad = 0;
        while (bl != 56) update(&pad, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = uint8_t(bits >> (56 - 8*i));
        update(lenb, 8);
        static const char* hexd = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (int i = 0; i < 8; ++i)
            for (int b = 3; b >= 0; --b) {
                const uint8_t v = uint8_t(h[i] >> (8*b));
                out.push_back(hexd[v >> 4]);
                out.push_back(hexd[v & 15]);
            }
        return out;
    }
};

std::string sha256File(const std::string& path, bool* ok) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) { if (ok) *ok = false; return "UNREADABLE"; }
    Sha256 s;
    std::vector<char> buf(1u << 20);
    while (f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = f.gcount();
        if (got > 0) s.update(buf.data(), static_cast<size_t>(got));
    }
    if (ok) *ok = true;
    return s.hex();
}

std::string sha256SelfExe() {
    wchar_t path[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0) return "UNAVAILABLE";
    std::string p;
    for (DWORD i = 0; i < n; ++i) p.push_back(static_cast<char>(path[i]));
    bool ok = false;
    return sha256File(p, &ok);
}

// ===========================================================================
// check plumbing
// ===========================================================================
struct Check { std::string id; bool pass; std::string detail; };
std::vector<Check> g_checks;
bool        g_lastClean = false;
std::string g_lastFailures;

void chk(const char* id, bool pass, const std::string& detail) {
    g_checks.push_back(Check{id, pass, detail});
}

void snapshotRun(size_t from) {
    g_lastClean = true;
    g_lastFailures.clear();
    for (size_t i = from; i < g_checks.size(); ++i) {
        if (!g_checks[i].pass) {
            if (!g_lastClean) g_lastFailures += "; ";
            g_lastClean = false;
            g_lastFailures += g_checks[i].id;
        }
    }
}

constexpr uint64_t FNV_BASIS = 1469598103934665603ULL;
constexpr uint64_t FNV_PRIME = 1099511628211ULL;
inline uint64_t fnv1a(uint64_t h, const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= FNV_PRIME; }
    return h;
}
inline uint64_t fnvBegin() { return FNV_BASIS; }

std::string u64s(uint64_t v) { return std::to_string(v); }
std::string hex32(uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "%08X", v); return b; }
std::string dbl(double v) { char b[64]; std::snprintf(b, sizeof b, "%.6g", v); return b; }

// ---- overflow-checked arithmetic -------------------------------------------
// A corrupted footer must never be able to turn the verifier itself into
// undefined behaviour.
bool mulOvf(uint64_t a, uint64_t b, uint64_t& out) {
    if (a != 0 && b > UINT64_MAX / a) return true;
    out = a * b; return false;
}
bool addOvf(uint64_t a, uint64_t b, uint64_t& out) {
    if (b > UINT64_MAX - a) return true;
    out = a + b; return false;
}

// ===========================================================================
// the one canonical bits-per-weight decode
//
// Nanof32BraidFormat.hpp documents the field as fixed-point HUNDREDTHS:
//     uint32_t bitsPerWeight;   // fixed-point: 115 = 1.15 bits/weight
// and Nanof32BraidStreamer.cpp:61 prints it as "%u.%02u", i.e. v/100, v%100.
// Decoding happens here and ONLY here, so no caller can independently bless an
// ambiguous literal. The expectation is derived from the payload types actually
// present rather than written as a constant.
//
// WHY NOT TENTHS. Dividing by 10 would make the value 320 written by
// gguf_to_nqb_converter.cpp read as 32.0, which is the only argument for it.
// That argument is refuted by the value the same field carries for the braid:
// the writer emits 115 for NQBRAID_BRAID_115, and 115 hundredths is 1.15
// bits/weight -- the number the entire format is named for. Under tenths 115
// would be 11.5 bits/weight, which contradicts the format name, the field
// comment, the reader's own format string, and the size arithmetic the header
// was designed to support (1.15 bpw over 671e9 params ~= 98 GB).
//
// MEASURED over every .nqb in the tree (raw field vs the payload width actually
// present, both derived in this run's own geometry):
//
//   file                  rawBpW  quantTypes  payloadWidth  impliedBpW
//   test_model_q0.nqb        160       0            4 B         32
//   test_model_q1.nqb        160       1            2 B         16
//   test_model_moe.nqb       160       1            2 B         16
//   test_model.nqb           115       5            --          1.15
//   m_moe_q5.nqb             115       5            --          1.15
//   llama3.2-3b-real-f32      0       0            4 B         32
//   llama3.2-3b-real-q0    320       0            4 B         32
//
// The same raw value 160 appears against two different payload widths (4 B and
// 2 B), so 160 carries no information at all: it was a hardcoded constant in
// the DENSE_BF16 arm copied into the DENSE_F32 arm. It is wrong under hundredths
// AND under tenths. Only the braid row carries a semantically meaningful value,
// and that value selects hundredths.
//
// Correct dense values under the documented unit: F32 = 3200, BF16 = 1600.
// Both writers now derive them from sizeof() instead of typing a literal.
// ===========================================================================
constexpr double kNqBraidBitsPerWeightUnit = 100.0;

double decodedBitsPerWeight(const Deep2::Nanof32BraidHeader& h) {
    return static_cast<double>(h.bitsPerWeight) / kNqBraidBitsPerWeightUnit;
}

uint64_t payloadWidthBytes(uint32_t quant) {
    switch (quant) {
        case Deep2::NQBRAID_DENSE_F32:  return 4;
        case Deep2::NQBRAID_DENSE_BF16: return 2;
        default:                        return 0;
    }
}

// ===========================================================================
// tensor + region model
// ===========================================================================
struct TRec {
    std::string name;
    uint64_t    rows = 0, cols = 0, elements = 0;
    uint64_t    dataBytes = 0;
    uint64_t    dataBegin = 0, dataEnd = 0;   // dataEnd == footerBegin
    uint64_t    footerBegin = 0, footerEnd = 0;
    uint32_t    quant = 0, expert = 0;
    uint64_t    reverseIndex = 0;

uint64_t payloadHash = FNV_BASIS;   // FNV-1a over canonical F32 bytes
    Deep2::Sha256 shaAcc;              // SHA-256 over the same canonical bytes
    uint64_t bf16Hash    = FNV_BASIS;   // FNV-1a over host-order uint16 bf16 image
    uint64_t scannedFloats = 0, nanCount = 0, infCount = 0;
    double    minVal = 0.0, maxVal = 0.0;

    // phase 2 (reader)
    uint64_t readerElements = 0;
    uint64_t readerBf16Hash = 0;
    bool     readerFooterMatches = false;
    bool     readerBf16Matches   = false;
    double   bf16MaxAbsErr = 0.0;
    double   bf16MeanAbsErr = 0.0;
};

struct Bail {
    std::string cls;
    std::string why;
};

Bail bail(const char* c, std::string w) { return Bail{c, std::move(w)}; }

struct VerifyOpts {
    bool        streamPayload = true;
    bool        useReader     = true;
    uint64_t    readerCapBytes = 2ull * 1024 * 1024 * 1024;
    std::string expectManifest;
    uint64_t    expectTensors = 0, expectElements = 0, expectFileBytes = 0;
    bool        haveExpectTensors = false, haveExpectElements = false,
                haveExpectFileBytes = false;
    std::string sourceSetSha;
};

struct VerifyOut {
    uint64_t fileSize = 0, dataStart = 0;
    uint32_t headerNumTensors = 0;
    uint64_t headerParamCount = 0, headerBitsRaw = 0;
    double   headerBitsDecoded = 0.0;
    uint64_t vocabBytes = 0, vocabEntries = 0, vocabOffset = 0;
    uint64_t chainParamCount = 0;
    uint64_t payloadBytesExpected = 0, payloadBytesStreamed = 0;
    uint64_t shortReads = 0, nanValues = 0, infValues = 0, finiteValues = 0;
    uint64_t finalReverseHead = 0;
    uint64_t gaps = 0, overlaps = 0;
    uint64_t footerGeometryViolations = 0, arithmeticOverflows = 0;
    uint64_t footerMagicFailures = 0, footerNameFailures = 0, footerDupNames = 0;
    uint64_t footerShapeFailures = 0, footerQuantFailures = 0;
uint32_t distinctQuantTypes = 0;
    uint64_t peakBufferBytes = 0, peakReaderTensorBytes = 0;
    std::string targetSha256;
    std::string payloadIntegrityAuthority = "STRUCTURAL_ONLY";
    std::vector<TRec> tensors;
};

// ---------------------------------------------------------------------------
VerifyOut verifyFile(const std::string& path, const VerifyOpts& opt) {
    const size_t mark = g_checks.size();
    VerifyOut vo;

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) throw bail("IO", "cannot open " + path);

    f.seekg(0, std::ios::end);
    const int64_t endPos = f.tellg();
    if (endPos <= 0) throw bail("IO", "cannot determine file size");
    vo.fileSize = static_cast<uint64_t>(endPos);
    chk("FILE_OPEN", true, "opened=" + path);
    chk("FILE_SIZE_MEASURED", vo.fileSize >= sizeof(Deep2::Nanof32BraidHeader),
        "DISK_FILE_SIZE=" + u64s(vo.fileSize));

    // ---- header ------------------------------------------------------------
    Deep2::Nanof32BraidHeader hdr{};
    f.seekg(0, std::ios::beg);
    f.read(reinterpret_cast<char*>(&hdr), sizeof hdr);
    if (static_cast<size_t>(f.gcount()) != sizeof hdr) { snapshotRun(mark); throw bail("FORMAT", "short header read"); }

    chk("HEADER_MAGIC_VALID", hdr.magic == Deep2::NANO_F32_BRAID_MAGIC,
        "magic=0x" + hex32(hdr.magic));
    chk("HEADER_VERSION_VALID", hdr.version == Deep2::NANO_F32_BRAID_VERSION,
        "version=" + u64s(hdr.version));
    chk("HEADER_FILE_SIZE_MATCH", hdr.fileSize == vo.fileSize,
        "HEADER_FILE_SIZE=" + u64s(hdr.fileSize) + " DISK_FILE_SIZE=" + u64s(vo.fileSize));

    vo.headerNumTensors = hdr.numTensors;
    vo.headerParamCount = hdr.paramCount;
    vo.headerBitsRaw    = hdr.bitsPerWeight;
    vo.headerBitsDecoded = decodedBitsPerWeight(hdr);

    // ---- arch meta ---------------------------------------------------------
    Deep2::Nanof32BraidArchMeta meta{};
    f.seekg(static_cast<std::streamoff>(sizeof(Deep2::Nanof32BraidHeader)), std::ios::beg);
    f.read(reinterpret_cast<char*>(&meta), sizeof meta);
    if (static_cast<size_t>(f.gcount()) != sizeof meta) { snapshotRun(mark); throw bail("FORMAT", "short arch meta read"); }

    chk("ARCH_META_VALID",
        meta.numLayers > 0 && meta.hiddenDim > 0 && meta.numHeads > 0 &&
        meta.numKVHeads > 0 && meta.headDim > 0 && meta.vocabSize > 0,
        "layers=" + u64s(meta.numLayers) + " hidden=" + u64s(meta.hiddenDim) +
        " heads=" + u64s(meta.numHeads) + " kvheads=" + u64s(meta.numKVHeads) +
        " ARCH_HEAD_DIM_STORED=" + u64s(meta.headDim) +
        " ffn=" + u64s(meta.intermediateDim) + " vocab=" + u64s(meta.vocabSize) +
        " ctx=" + u64s(meta.contextLength) + " ropeTheta=" + u64s(static_cast<uint64_t>(meta.ropeTheta)));

    // A stored headDim that disagrees with hidden/heads halves qDim, kvDim and
    // the KV cache while every structural check still passes -- so it is
    // re-measured against the file, not against the source that wrote it.
    const uint64_t headDimDerived = meta.numHeads ? (meta.hiddenDim / meta.numHeads) : 0;
    chk("ARCH_HEAD_DIM_MATCH",
        headDimDerived != 0 && meta.headDim == headDimDerived,
        "ARCH_HEAD_DIM_STORED=" + u64s(meta.headDim) +
        " ARCH_HEAD_DIM_DERIVED_EXPECTED=" + u64s(headDimDerived));

    // ---- vocabulary section -------------------------------------------------
    vo.dataStart = sizeof(Deep2::Nanof32BraidHeader) + sizeof(Deep2::Nanof32BraidArchMeta);
    if (hdr.vocabSectionBytes != 0) {
        vo.vocabOffset = hdr.vocabSectionOffset;
        vo.vocabBytes  = hdr.vocabSectionBytes;

        chk("VOCAB_PLACED_AFTER_ARCH_META", hdr.vocabSectionOffset == vo.dataStart,
            "VOCAB_OFFSET=" + u64s(hdr.vocabSectionOffset) + " expected=" + u64s(vo.dataStart));

        const bool inRange =
            hdr.vocabSectionOffset >= vo.dataStart &&
            hdr.vocabSectionBytes <= vo.fileSize - hdr.vocabSectionOffset;
        chk("VOCAB_BOUNDS_VALID", inRange,
            "VOCAB_OFFSET=" + u64s(hdr.vocabSectionOffset) +
            " VOCAB_BYTES=" + u64s(hdr.vocabSectionBytes) +
            " fileSize=" + u64s(vo.fileSize));
        if (!inRange) { snapshotRun(mark); throw bail("FORMAT", "vocab section out of range"); }

        std::vector<uint8_t> vocab(static_cast<size_t>(hdr.vocabSectionBytes));
        f.seekg(static_cast<std::streamoff>(hdr.vocabSectionOffset), std::ios::beg);
        f.read(reinterpret_cast<char*>(vocab.data()), static_cast<std::streamsize>(vocab.size()));
        if (static_cast<uint64_t>(f.gcount()) != hdr.vocabSectionBytes) {
            snapshotRun(mark); throw bail("FORMAT", "short vocab read");
        }

        Deep2::Nanof32VocabHeader vh{};
        std::memcpy(&vh, vocab.data(), sizeof vh);
        chk("VOCAB_MAGIC_VALID", vh.magic == Deep2::NANO_F32_BRAID_VOCAB_MAGIC,
            "magic=0x" + hex32(vh.magic));

        const uint64_t n = vh.entryCount;
        uint64_t need = 0;
        if (mulOvf(n, 4, need)) { snapshotRun(mark); throw bail("ARITHMETIC_OVERFLOW", "vocab entry count overflow"); }
        need *= 3; need += 4; need += sizeof(Deep2::Nanof32VocabHeader);
        need += vh.strBytes; need += vh.mergeBytes;
        chk("VOCAB_STRUCTURE_VALID", need == hdr.vocabSectionBytes,
            "required=" + u64s(need) + " VOCAB_BYTES=" + u64s(hdr.vocabSectionBytes) +
            " entryCount=" + u64s(n) + " strBytes=" + u64s(vh.strBytes) +
            " mergeCount=" + u64s(vh.mergeCount) + " mergeBytes=" + u64s(vh.mergeBytes));

        bool offsetsOk = (n > 0);
        uint64_t firstBad = 0;
        {
            const uint8_t* base = vocab.data() + sizeof(Deep2::Nanof32VocabHeader);
            const uint32_t* offs = reinterpret_cast<const uint32_t*>(base + vh.strBytes);
            uint64_t prevEnd = 0;
            for (uint64_t i = 0; i < n; ++i) {
                const uint32_t o = offs[i];
                if (o >= vh.strBytes) { offsetsOk = false; firstBad = i; break; }
                uint64_t j = o;
                bool term = false;
                while (j < vh.strBytes) { if (base[j] == 0) { term = true; break; } ++j; }
                if (!term) { offsetsOk = false; firstBad = i; break; }
                if (i > 0 && o < prevEnd) { offsetsOk = false; firstBad = i; break; }
                prevEnd = j + 1;
            }
        }
        if (!offsetsOk) chk("VOCAB_OFFSETS_VALID", false, "firstBadEntry=" + u64s(firstBad));
        else            chk("VOCAB_OFFSETS_VALID", true, "entryCount=" + u64s(n) + " all offsets in blob and monotonic");

        chk("VOCAB_SPECIAL_IDS_IN_RANGE",
            vh.bosId >= -1 && vh.bosId < static_cast<int32_t>(n) &&
            vh.eosId >= -1 && vh.eosId < static_cast<int32_t>(n),
            "bos=" + u64s(static_cast<uint64_t>(vh.bosId)) +
            " eos=" + u64s(static_cast<uint64_t>(vh.eosId)) + " entries=" + u64s(n));

        vo.vocabEntries = n;
        vo.dataStart = hdr.vocabSectionOffset + hdr.vocabSectionBytes;
    } else {
        chk("VOCAB_ABSENT_DECLARED", hdr.vocabSectionOffset == 0,
            "no vocabulary section (valid state, not a defect)");
    }

    // ---- PHASE 1a: reverse footer chain, per-step geometry ------------------
    //
    // Each step records its own geometry and the two predicates that can fail:
    // the footer must begin at or after dataStart, and the payload it points at
    // must also begin at or after dataStart. head is then SET to the derived
    // payload begin, so termination at exactly dataStart is a consequence of
    // continuous geometry rather than of one closing sum.
    constexpr size_t FOOTER = sizeof(Deep2::Nanof32BraidTensorFooter);
    uint64_t head = vo.fileSize;
    std::unordered_map<std::string, uint64_t> seen;
    std::unordered_map<uint32_t, uint32_t> quantSeen;

    while (head > vo.dataStart) {
        if (head - vo.dataStart < FOOTER) {
            snapshotRun(mark);
            throw bail("STRUCTURAL_BOUNDS", "reverse chain: trailing bytes shorter than a footer before dataStart");
        }

        const uint64_t footerEnd   = head;
        const uint64_t footerBegin = head - FOOTER;
        if (footerBegin < vo.dataStart) { ++vo.footerGeometryViolations; snapshotRun(mark); throw bail("STRUCTURAL_BOUNDS", "PRED_FOOTER_BEGIN_GE_DATA_START violated"); }

        Deep2::Nanof32BraidTensorFooter ft{};
        f.seekg(static_cast<std::streamoff>(footerBegin), std::ios::beg);
        f.read(reinterpret_cast<char*>(&ft), FOOTER);
        if (static_cast<size_t>(f.gcount()) != FOOTER) { snapshotRun(mark); throw bail("FORMAT", "short footer read"); }

        const uint64_t idx = vo.tensors.size();
        if (ft.magic != Deep2::NANO_F32_BRAID_MAGIC) ++vo.footerMagicFailures;
        if (ft.quantType >= Deep2::NQBRAID_COUNT) ++vo.footerQuantFailures;
        quantSeen[ft.quantType] = 1;

        uint64_t elements = 0;
        if (mulOvf(ft.rows, ft.cols, elements)) {
            ++vo.arithmeticOverflows;
            snapshotRun(mark);
            throw bail("ARITHMETIC_OVERFLOW", "rows*cols overflows uint64 at reverse index " + u64s(idx));
        }

        const uint64_t width = payloadWidthBytes(ft.quantType);
        uint64_t expectBytes = 0;
        const bool widthKnown = width != 0 && !mulOvf(elements, width, expectBytes);
        if (!widthKnown || expectBytes != ft.dataBytes) ++vo.footerShapeFailures;

        size_t len = 0;
        while (len < sizeof(ft.name) && ft.name[len] != '\0') ++len;
        if (len == 0 || len == sizeof(ft.name)) ++vo.footerNameFailures;
        const std::string nm(ft.name, len);
        if (seen.find(nm) != seen.end()) ++vo.footerDupNames;
        seen[nm] = idx;

        const uint64_t payloadEnd = footerBegin;                 // PRED_PAYLOAD_END_EQ_FOOTER_BEGIN by construction
        if (ft.dataBytes > payloadEnd - vo.dataStart) {
            snapshotRun(mark);
            throw bail("STRUCTURAL_BOUNDS", "PRED_PAYLOAD_BEGIN_GE_DATA_START violated at reverse index " + u64s(idx));
        }
        const uint64_t payloadBegin = payloadEnd - ft.dataBytes;

        uint64_t run = 0;
        if (addOvf(vo.payloadBytesExpected, ft.dataBytes, run)) {
            ++vo.arithmeticOverflows; snapshotRun(mark); throw bail("ARITHMETIC_OVERFLOW", "payload byte total overflow");
        }
        vo.payloadBytesExpected = run;
        if (addOvf(vo.chainParamCount, elements, run)) {
            ++vo.arithmeticOverflows; snapshotRun(mark); throw bail("ARITHMETIC_OVERFLOW", "chain element total overflow");
        }
        vo.chainParamCount = run;

        TRec r;
        r.name = nm;
        r.rows = ft.rows; r.cols = ft.cols; r.elements = elements;
        r.dataBytes  = ft.dataBytes;
        r.dataBegin  = payloadBegin;
        r.dataEnd    = payloadEnd;
        r.footerBegin = footerBegin;
        r.footerEnd  = footerEnd;
        r.quant = ft.quantType; r.expert = ft.expertIndex;
        r.reverseIndex = idx;
        vo.tensors.push_back(r);

        head = payloadBegin;   // <- derived, not decremented by a constant
    }

    vo.finalReverseHead = head;
    vo.distinctQuantTypes = static_cast<uint32_t>(quantSeen.size());

    chk("FOOTER_CHAIN_REACHES_DATA_START", head == vo.dataStart,
        "FINAL_REVERSE_HEAD=" + u64s(head) + " DATA_START=" + u64s(vo.dataStart) +
        " steps=" + u64s(vo.tensors.size()));
    chk("FOOTER_GEOMETRY_PREDICATES_HELD", vo.footerGeometryViolations == 0,
        "violations=" + u64s(vo.footerGeometryViolations) +
        " (PRED_FOOTER_BEGIN_GE_DATA_START, PRED_PAYLOAD_BEGIN_GE_DATA_START)");
    chk("ARITHMETIC_OVERFLOW_FREE", vo.arithmeticOverflows == 0,
        "overflows=" + u64s(vo.arithmeticOverflows));

    // GAPS / OVERLAPS are DERIVED facts about region adjacency, not a second
    // closing sum: sort the regions ascending and require each to start exactly
    // where the previous one ended.
    {
        std::vector<size_t> ord(vo.tensors.size());
        for (size_t i = 0; i < ord.size(); ++i) ord[i] = i;
        std::sort(ord.begin(), ord.end(), [&](size_t a, size_t b) {
            return vo.tensors[a].dataBegin < vo.tensors[b].dataBegin;
        });
        uint64_t cursor = vo.dataStart;
        for (size_t i = 0; i < ord.size(); ++i) {
            const TRec& t = vo.tensors[ord[i]];
            if (t.dataBegin > cursor) ++vo.gaps;
            else if (t.dataBegin < cursor) ++vo.overlaps;
            cursor = t.footerEnd;
        }
        chk("REGIONS_ABUT_WITHOUT_GAP_OR_OVERLAP", vo.gaps == 0 && vo.overlaps == 0,
            "GAPS=" + u64s(vo.gaps) + " OVERLAPS=" + u64s(vo.overlaps));
    }

    chk("FOOTER_MAGIC_FAILURES_ZERO", vo.footerMagicFailures == 0,
        "FOOTER_MAGIC_FAILURES=" + u64s(vo.footerMagicFailures));
    chk("FOOTER_NAME_FAILURES_ZERO", vo.footerNameFailures == 0,
        "FOOTER_NAME_FAILURES=" + u64s(vo.footerNameFailures));
    chk("FOOTER_DUPLICATE_NAMES_ZERO", vo.footerDupNames == 0,
        "FOOTER_DUPLICATE_NAMES=" + u64s(vo.footerDupNames));
chk("FOOTER_SHAPE_FAILURES_ZERO", vo.footerShapeFailures == 0,
        "FOOTER_SHAPE_FAILURES=" + u64s(vo.footerShapeFailures));
    // The primary payload-geometry authority, stated without reference to any
    // descriptive metadata: for DENSE_F32 the stored bytes must be exactly four
    // per element. This is what the bitsPerWeight field merely *claims*.
    {
        uint64_t f32Tensors = 0, f32Bad = 0;
        for (const TRec& t : vo.tensors) {
            if (t.quant != Deep2::NQBRAID_DENSE_F32) continue;
            ++f32Tensors;
            uint64_t want = 0;
            if (mulOvf(t.elements, 4, want) || want != t.dataBytes) ++f32Bad;
        }
        chk("FOOTER_DATA_BYTES_EQ_ELEMENTS_X4", f32Bad == 0,
            "DENSE_F32_BYTES_PER_ELEMENT=4 denseF32Tensors=" + u64s(f32Tensors) +
            " violations=" + u64s(f32Bad));
    }
    chk("FOOTER_QUANT_FAILURES_ZERO", vo.footerQuantFailures == 0,
        "FOOTER_QUANT_FAILURES=" + u64s(vo.footerQuantFailures) +
        " distinctQuantTypes=" + u64s(vo.distinctQuantTypes));

    chk("TENSOR_COUNT_MATCH", vo.headerNumTensors == vo.tensors.size(),
        "HEADER_TENSOR_COUNT=" + u64s(vo.headerNumTensors) +
        " CHAIN_TENSOR_COUNT=" + u64s(vo.tensors.size()));

    // ONE aggregate element measurement, ONE boolean.
    chk("PARAM_COUNT_MATCH", vo.headerParamCount == vo.chainParamCount,
        "HEADER_PARAM_COUNT=" + u64s(vo.headerParamCount) +
        " CHAIN_PARAM_COUNT=" + u64s(vo.chainParamCount));

    // bits-per-weight: expectation derived from the payload types present.
    {
        uint64_t maxWidth = 0;
        for (const TRec& t : vo.tensors) maxWidth = std::max(maxWidth, payloadWidthBytes(t.quant));
        const double expectedBits = static_cast<double>(maxWidth * 8);
        chk("BITS_PER_WEIGHT_MATCH", maxWidth != 0 && vo.headerBitsDecoded == expectedBits,
            "HEADER_BITS_FIELD_RAW=" + u64s(vo.headerBitsRaw) +
            " HEADER_BITS_FIELD_UNIT=hundredths_of_a_bit" +
            " EXPECTED_BITS_PER_WEIGHT=" + dbl(expectedBits) +
            " DECODED_BITS_PER_WEIGHT=" + dbl(vo.headerBitsDecoded));
    }

    // caller expectations -- inputs, never sources of truth
    if (opt.haveExpectTensors)
        chk("CALLER_EXPECT_TENSORS_MATCH", vo.tensors.size() == opt.expectTensors,
            "expected=" + u64s(opt.expectTensors) + " measured=" + u64s(vo.tensors.size()));
    if (opt.haveExpectElements)
        chk("CALLER_EXPECT_ELEMENTS_MATCH", vo.chainParamCount == opt.expectElements,
            "expected=" + u64s(opt.expectElements) + " measured=" + u64s(vo.chainParamCount));
    if (opt.haveExpectFileBytes)
        chk("CALLER_EXPECT_FILE_BYTES_MATCH", vo.fileSize == opt.expectFileBytes,
            "expected=" + u64s(opt.expectFileBytes) + " measured=" + u64s(vo.fileSize));

    // ---- PHASE 1b: whole-file SHA-256, then per-tensor payload analysis ----
    //
    // Two deliberate choices here:
    //
    //  * The file digest is a plain SEQUENTIAL pass over [0, fileSize). It is
    //    not fused with the payload analysis, because fusing would make the
    //    digest depend on the region model being right -- a bug in the model
    //    would then produce a self-consistent digest of the wrong bytes.
    //
    //  * Payload floats are scanned relative to each tensor's OWN start, never
    //    relative to the file. dataStart is NOT 4-byte aligned: the vocabulary
    //    section is a whole number of bytes but not of words, so the first
    //    payload of this artifact begins at 5,984,856 (mod 4 == 0 here) and the
    //    negative-control file's begins at 481 (mod 4 == 1). Scanning on file
    //    offsets would read half-floats at the first tensor of any such file.
    if (opt.streamPayload) {
        constexpr size_t CHUNK = 8u * 1024 * 1024;
        vo.peakBufferBytes = CHUNK;
        std::vector<uint8_t> buf(CHUNK);

        // ---- (i) whole-file digest ----------------------------------------
        {
            Sha256 whole;
            f.clear();
            f.seekg(0, std::ios::beg);
            uint64_t off = 0;
            while (off < vo.fileSize) {
                const size_t want = static_cast<size_t>(
                    std::min<uint64_t>(CHUNK, vo.fileSize - off));
                f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(want));
                const size_t got = static_cast<size_t>(f.gcount());
                if (got != want) { ++vo.shortReads; break; }
                whole.update(buf.data(), got);
                off += got;
            }
            vo.targetSha256 = whole.hex();
        }

        // ---- (ii) per-tensor payload analysis, ascending by offset --------
        std::vector<size_t> asc(vo.tensors.size());
        for (size_t i = 0; i < asc.size(); ++i) asc[i] = i;
        std::sort(asc.begin(), asc.end(), [&](size_t a, size_t b) {
            return vo.tensors[a].dataBegin < vo.tensors[b].dataBegin;
        });

        for (size_t ai = 0; ai < asc.size(); ++ai) {
            TRec& t = vo.tensors[asc[ai]];
            if (t.quant != Deep2::NQBRAID_DENSE_F32) continue;

            uint64_t remaining = t.dataBytes, roff = t.dataBegin;
            while (remaining > 0) {
                const size_t want = static_cast<size_t>(std::min<uint64_t>(remaining, CHUNK));
                f.seekg(static_cast<std::streamoff>(roff), std::ios::beg);
                f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(want));
                const size_t got = static_cast<size_t>(f.gcount());
                if (got != want) { ++vo.shortReads; break; }
                vo.payloadBytesStreamed += got;

const size_t nf = got / 4;
                for (size_t i = 0; i < nf; ++i) {
                    float fv;
                    std::memcpy(&fv, buf.data() + i * 4, 4);
                    if (std::isnan(fv)) { ++t.nanCount; continue; }
                    if (std::isinf(fv)) { ++t.infCount; continue; }
                    if (t.scannedFloats == 0) { t.minVal = t.maxVal = fv; }
                    else { if (fv < t.minVal) t.minVal = fv; if (fv > t.maxVal) t.maxVal = fv; }
                }
                t.scannedFloats += nf;

                // Canonical F32 identity, hashed through the SHARED primitive the
                // source side calls, so both digests come from one function.
                // Hashing the raw stored bytes instead would quietly assume this
                // host's float layout IS the canonical little-endian image; if
                // that ever stopped being true the mismatch would arrive wearing a
                // fidelity-failure label instead of a platform-bug one.
                nqbHashCanonicalF32Chunk(reinterpret_cast<const float*>(buf.data()), nf,
                                        t.payloadHash, t.shaAcc);

                // expected reader image, via the SAME primitive the reader uses
                uint16_t* h16 = reinterpret_cast<uint16_t*>(buf.data());
                for (size_t i = 0; i < nf; ++i) {
                    float fv;
                    std::memcpy(&fv, buf.data() + i * 4, 4);
                    h16[i] = Deep2::Float32ToBF16Bits(fv);
                }
                t.bf16Hash = fnv1a(t.bf16Hash, h16, nf * 2);

                roff += got;
                remaining -= got;
            }
        }

        for (const TRec& t : vo.tensors) {
            vo.nanValues  += t.nanCount;
            vo.infValues  += t.infCount;
            vo.finiteValues += t.scannedFloats - t.nanCount - t.infCount;
        }

        chk("PAYLOAD_SHORT_READS_ZERO", vo.shortReads == 0,
            "PAYLOAD_SHORT_READS=" + u64s(vo.shortReads) +
            " PAYLOAD_BYTES_STREAMED=" + u64s(vo.payloadBytesStreamed) +
            " PAYLOAD_BYTES_EXPECTED=" + u64s(vo.payloadBytesExpected));
        chk("PAYLOAD_BYTES_MATCH_EXPECTED", vo.payloadBytesStreamed == vo.payloadBytesExpected,
            "PAYLOAD_BYTES_STREAMED=" + u64s(vo.payloadBytesStreamed) +
            " PAYLOAD_BYTES_EXPECTED=" + u64s(vo.payloadBytesExpected));
        chk("FINITE_VALUES_COVER_ELEMENTS",
            vo.finiteValues + vo.nanValues + vo.infValues == vo.chainParamCount,
            "FINITE_VALUES=" + u64s(vo.finiteValues) + " NAN_VALUES=" + u64s(vo.nanValues) +
            " INF_VALUES=" + u64s(vo.infValues) + " CHAIN_PARAM_COUNT=" + u64s(vo.chainParamCount));
        chk("NAN_VALUES_ZERO", vo.nanValues == 0, "NAN_VALUES=" + u64s(vo.nanValues));
        chk("INF_VALUES_ZERO", vo.infValues == 0, "INF_VALUES=" + u64s(vo.infValues));
    }

    // ---- manifest comparison (payload-integrity discriminator) ---------------
// Payload integrity is only claimed when a manifest was actually loaded and
    // parsed. One source of truth: a sealed manifest is compared and detection
    // is expected; without one the container stores no checksum and structural
    // authority is all that exists.
    bool manifestLoaded = false;

    if (!opt.expectManifest.empty()) {
        std::ifstream m(opt.expectManifest);
        if (!m.is_open()) { snapshotRun(mark); throw bail("IO", "cannot open expected manifest " + opt.expectManifest); }

        // RAWRXD_NQB_MANIFEST_HASH_DOMAIN_001
        //
        // This block previously parsed a manifest line as
        //     <name> \t <hash>
        // while writeManifest() emits
        //     <reverseIndex> \t <name> \t <payloadHash> \t ...
        // so column 0 (the index) was taken as the name and column 1 (the NAME)
        // was passed to strtoull, which yields 0 for "blk.1.attn_q.weight".
        // Every comparison therefore compared a real FNV digest against 0 and
        // reported a mismatch:
        //     PAYLOAD_HASHES_MATCH_EXPECTED_MANIFEST=FAIL
        //     compared=3 manifestEntries=3 mismatches=3
        // on the UNCORRUPTED baseline. Three of three on a clean file is not
        // evidence of corruption; it is evidence that the producer and the
        // verifier disagreed about the hash contract. No payload-corruption
        // conclusion may be drawn from a run that has this shape.
        //
        // The contract is now explicit and order-independent: the manifest is
        // keyed by TENSOR NAME, never by position. Reverse traversal order and
        // manifest emission order are then free to differ.
        std::unordered_map<std::string, std::pair<uint64_t, uint64_t>> exp;  // name -> (hash, bytes)
        uint64_t lines = 0, skippedLines = 0;
        std::string line;
        while (std::getline(m, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::vector<std::string> col;
            size_t p = 0;
            for (int k = 0; k < 8; ++k) {
                const size_t t = line.find('\t', p);
                if (t == std::string::npos) { col.push_back(line.substr(p)); break; }
                col.push_back(line.substr(p, t - p));
                p = t + 1;
            }
            // index name payloadHash bf16Hash rows cols bytes quant
            if (col.size() < 7) { ++skippedLines; continue; }
            const std::string& nm = col[1];
            const uint64_t h  = std::strtoull(col[2].c_str(), nullptr, 10);
            const uint64_t by = std::strtoull(col[6].c_str(), nullptr, 10);
            if (nm.empty()) { ++skippedLines; continue; }
            exp[nm] = {h, by};
            ++lines;
        }
        manifestLoaded = !exp.empty();

        uint64_t compared = 0, mismatches = 0, byteMismatches = 0, missing = 0;
        std::string diag;
        for (const TRec& t : vo.tensors) {
            auto it = exp.find(t.name);
            if (it == exp.end()) { ++missing; ++compared; continue; }
            ++compared;
            if (it->second.first != t.payloadHash) {
                ++mismatches;
                if (diag.empty()) {
                    char b[512];
                    std::snprintf(b, sizeof b,
                        "NAME=%s MANIFEST_HASH=%llu OBSERVED_RAW_HASH=%llu "
                        "HASHED_BYTES=%llu PAYLOAD_OFFSET=%llu MANIFEST_BYTES=%llu "
                        "HASH_DOMAIN=raw_stored_f32_bytes_fnv1a64",
                        t.name.c_str(),
                        (unsigned long long)it->second.first,
                        (unsigned long long)t.payloadHash,
                        (unsigned long long)t.dataBytes,
                        (unsigned long long)t.dataBegin,
                        (unsigned long long)it->second.second);
                    diag = b;
                }
            }
            if (it->second.second != t.dataBytes) ++byteMismatches;
        }
        // every manifest entry must be claimed by some tensor, or the manifest
        // describes a different file
        for (const auto& kv : exp) {
            bool found = false;
            for (const TRec& t : vo.tensors) if (t.name == kv.first) { found = true; break; }
            if (!found) ++missing;
        }

        chk("PAYLOAD_HASHES_MATCH_EXPECTED_MANIFEST",
            manifestLoaded && compared == vo.tensors.size() &&
            mismatches == 0 && missing == 0 && byteMismatches == 0,
            "compared=" + u64s(compared) + " manifestEntries=" + u64s(exp.size()) +
            " manifestLines=" + u64s(lines) + " skippedLines=" + u64s(skippedLines) +
            " mismatches=" + u64s(mismatches) + " byteCountMismatches=" + u64s(byteMismatches) +
            " namesNotInManifest=" + u64s(missing) +
            " key=BY_TENSOR_NAME orderIndependent=1" + (diag.empty() ? "" : (" " + diag)));
        vo.payloadIntegrityAuthority = manifestLoaded ? "MANIFEST_SEALED" : "STRUCTURAL_ONLY";
    } else {
        vo.payloadIntegrityAuthority = "STRUCTURAL_ONLY";
    }

    // ---- PHASE 2: canonical reader, one tensor resident ---------------------
    if (opt.useReader) {
        Deep2::Nanof32BraidStreamer reader;
        if (!reader.open(path)) { snapshotRun(mark); throw bail("FORMAT", "canonical reader refused to open the file"); }
        chk("READER_OPEN", true, "Nanof32BraidStreamer::open succeeded");

        uint64_t read = 0, metadataMatch = 0, bf16Match = 0, bf16Fail = 0, skipped = 0;
        uint64_t firstFailIdx = 0;
        std::string firstFailName;
        constexpr size_t ERRC = 4u * 1024 * 1024;
        std::vector<uint8_t> ebuf(ERRC);

        Deep2::Nanof32BraidTensorFooter ftr{};
        std::vector<Deep2::bfloat16_t> dat;
        while (reader.readNextTensor(ftr, dat)) {
            const uint64_t idx = read;
            if (idx >= vo.tensors.size()) break;
            TRec& t = vo.tensors[idx];

            size_t nl = 0;
            while (nl < sizeof(ftr.name) && ftr.name[nl] != '\0') ++nl;
            const std::string nm(ftr.name, nl);
            vo.peakReaderTensorBytes = std::max<uint64_t>(vo.peakReaderTensorBytes, ftr.dataBytes);

            t.readerFooterMatches = (ftr.rows == t.rows && ftr.cols == t.cols &&
                                     ftr.dataBytes == t.dataBytes &&
                                     ftr.quantType == t.quant && nm == t.name);
            t.readerElements = dat.size();
            if (t.readerFooterMatches) ++metadataMatch;

            if (ftr.dataBytes > opt.readerCapBytes) {
                ++skipped;
            } else {
                t.readerBf16Hash = fnv1a(fnvBegin(), dat.data(),
                                         dat.size() * sizeof(Deep2::bfloat16_t));
                t.readerBf16Matches = (t.readerBf16Hash == t.bf16Hash);
                if (t.readerBf16Matches) ++bf16Match;
                else {
                    ++bf16Fail;
                    if (bf16Fail == 1) { firstFailIdx = idx; firstFailName = t.name; }
                }

                // error of the reader's BF16 policy against the SOURCE F32 bytes
                // still on disk -- read independently of the reader's output.
                if (t.quant == Deep2::NQBRAID_DENSE_F32) {
                    double sumAbs = 0.0;
                    uint64_t n = 0, remaining = t.dataBytes;
                    uint64_t roff = t.dataBegin, base = 0;
                    while (remaining > 0) {
                        const size_t want = static_cast<size_t>(std::min<uint64_t>(remaining, ERRC));
                        f.seekg(static_cast<std::streamoff>(roff), std::ios::beg);
                        f.read(reinterpret_cast<char*>(ebuf.data()),
                               static_cast<std::streamsize>(want));
                        if (static_cast<size_t>(f.gcount()) != want) break;
                        for (size_t i = 0; i < want / 4; ++i) {
                            float src;
                            std::memcpy(&src, ebuf.data() + i * 4, 4);
                            const float got = dat[base + i].toFloat();
                            const double e = std::fabs(static_cast<double>(src) - got);
                            if (e > t.bf16MaxAbsErr) t.bf16MaxAbsErr = e;
                            sumAbs += e;
                            ++n;
                        }
                        base += want / 4;
                        roff += want;
                        remaining -= want;
                    }
                    t.bf16MeanAbsErr = n ? (sumAbs / static_cast<double>(n)) : 0.0;
                }
            }

            ++read;
            dat.clear();
            dat.shrink_to_fit();
        }

        chk("READER_TENSOR_COUNT_MATCH", read == vo.tensors.size(),
            "READER_TENSORS_READ=" + u64s(read) +
            " READER_TENSORS_EXPECTED=" + u64s(vo.tensors.size()) +
            " skippedOverCap=" + u64s(skipped));
        chk("READER_METADATA_MATCH", metadataMatch == vo.tensors.size(),
            "matched=" + u64s(metadataMatch) + " expected=" + u64s(vo.tensors.size()));
        chk("READER_BF16_SELF_CONSISTENCY", bf16Fail == 0,
            "READER_BF16_HASH_MATCH=" + u64s(bf16Match) +
            " READER_BF16_HASH_FAIL=" + u64s(bf16Fail) +
            (bf16Fail ? (" firstFailReverseIndex=" + u64s(firstFailIdx) +
                         " name=" + firstFailName) : ""));
    }

    snapshotRun(mark);
    return vo;
}

void writeManifest(const std::string& path, const VerifyOut& vo) {
    std::ofstream o(path, std::ios::trunc);
    if (!o.is_open()) return;
    o << "# RAWRXD_NQB_PRODUCTION_REOPEN_001 manifest\n";
    o << "# reverseIndex\tname\tpayloadHash\tbf16Hash\trows\tcols\tbytes\tquant\n";
    for (const TRec& t : vo.tensors) {
        o << t.reverseIndex << '\t' << t.name << '\t' << t.payloadHash << '\t'
          << t.bf16Hash << '\t' << t.rows << '\t' << t.cols << '\t'
          << t.dataBytes << '\t' << t.quant << '\n';
    }
}

// RAWRXD_NQB_SOURCE_F32_PARITY_001 -- PAYLOAD SIDE.
//
// Emits the SAME V1 manifest schema as tools/nqb_source_f32_manifest.cpp, through
// the same serialiser from Nanof32BraidManifest.hpp. Two hand-written copies of a
// schema already drifted once here and produced a confident false hash mismatch on
// a clean file, so the schema now exists once.
//
// This process opened the .nqb and nothing else. The comparator that consumes this
// file opens neither model, so no single process can see both sides.
void writeF32Manifest(const std::string& path, const VerifyOut& vo) {
    std::ofstream o(path, std::ios::trunc);
    if (!o.is_open()) return;
    o << Deep2::nqbManifestHeader() << "\n";
    std::vector<Deep2::NqbF32Record> recs;
    recs.reserve(vo.tensors.size());
    for (const TRec& t : vo.tensors) {
        Deep2::NqbF32Record r;
        r.name        = t.name;
        r.storedCodec = t.quant;
        // The footer carries ne[0] and ne[1]. rank is not stored on disk, so it is
        // reported as 2 when cols>1 and 1 otherwise -- the same reduction the
        // writer applied when it filled the footer.
        r.rank        = (t.cols > 1) ? 2u : 1u;
        r.dim0        = t.rows;
        r.dim1        = t.cols;
        r.elements    = t.elements;
        r.f32Bytes    = t.elements * 4ull;   // canonical F32 image, codec-independent
        r.fnv1a64     = t.payloadHash;
        r.sha256      = t.shaAcc.hex();
        recs.push_back(r);
    }
    // Deterministic order so two runs of this tool emit byte-identical manifests.
    std::sort(recs.begin(), recs.end(),
              [](const Deep2::NqbF32Record& a, const Deep2::NqbF32Record& b) {
                  return a.name < b.name;
              });
    for (const Deep2::NqbF32Record& r : recs) o << Deep2::nqbSerialiseRecord(r);
}

void writePhase2(const std::string& path, const VerifyOut& vo) {
    std::ofstream o(path, std::ios::trunc);
    if (!o.is_open()) return;
    o << "# RAWRXD_NQB_PRODUCTION_REOPEN_001 phase2 per-tensor reader record\n";
    o << "# reverseIndex\tname\trows\tcols\trawPayloadF32Hash\texpectedBf16Hash"
         "\treaderBf16Hash\texpectedBf16HashMatch\treaderElements\telementCountMatch"
         "\tbf16MaxAbsVsSourceF32\tbf16MeanAbsVsSourceF32\n";
    for (const TRec& t : vo.tensors) {
        char mx[64], mn[64];
        std::snprintf(mx, sizeof mx, "%.6g", t.bf16MaxAbsErr);
        std::snprintf(mn, sizeof mn, "%.6g", t.bf16MeanAbsErr);
        o << t.reverseIndex << '\t' << t.name << '\t' << t.rows << '\t' << t.cols << '\t'
          << t.payloadHash << '\t' << t.bf16Hash << '\t' << t.readerBf16Hash << '\t'
          << (t.readerBf16Matches ? 1 : 0) << '\t' << t.readerElements << '\t'
          << (t.readerElements == t.elements ? 1 : 0) << '\t' << mx << '\t' << mn << '\n';
    }
}

bool copyFile(const std::string& from, const std::string& to) {
    std::ifstream in(from, std::ios::binary);
    if (!in.is_open()) return false;
    std::ofstream out(to, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) return false;
    out << in.rdbuf();
    return out.good();
}

bool patchByte(const std::string& path, uint64_t off, const void* bytes, size_t len) {
    std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
    if (!f.is_open()) return false;
    f.seekp(static_cast<std::streamoff>(off));
    f.write(static_cast<const char*>(bytes), static_cast<std::streamsize>(len));
    f.close();
    return true;
}

// ---------------------------------------------------------------------------
// PHASE 3 -- falsification controls
// ---------------------------------------------------------------------------
void runNegativeControls(const std::string& dir) {
    const std::string base  = dir + "/nc_base.nqb";
    const std::string flip  = dir + "/nc_payload_flip.nqb";
    const std::string magic = dir + "/nc_footer_magic.nqb";
    const std::string trunc = dir + "/nc_truncated.nqb";
    const std::string hdim  = dir + "/nc_head_dim.nqb";
    const std::string man   = dir + "/nc_base.manifest";

    Deep2::Nanof32BraidArchMeta meta{};
    std::snprintf(meta.modelName, sizeof meta.modelName, "nc");
    std::snprintf(meta.archName, sizeof meta.archName, "llama");
    meta.numLayers = 2; meta.hiddenDim = 8; meta.numHeads = 2;
    meta.numKVHeads = 1; meta.headDim = 4; meta.intermediateDim = 16;
    meta.vocabSize = 6; meta.contextLength = 128; meta.ropeType = 1;
    meta.normEps = 1e-5f; meta.ropeTheta = 10000.0f;

    std::vector<float> a(8 * 6), b(4 * 8), c(2 * 2);
    for (size_t i = 0; i < a.size(); ++i) a[i] = static_cast<float>(i) * 0.5f - 3.0f;
    for (size_t i = 0; i < b.size(); ++i) b[i] = static_cast<float>(i) * -0.25f;
    for (size_t i = 0; i < c.size(); ++i) c[i] = 1.0f / static_cast<float>(i + 1);

    std::vector<Deep2::Nanof32TensorSpec> ts(3);
    ts[0].name = "token_embd.weight";  ts[0].rows = 8; ts[0].cols = 6;
    ts[0].quant = Deep2::NQBRAID_DENSE_F32; ts[0].values = a.data();
    ts[1].name = "blk.0.attn_q.weight"; ts[1].rows = 4; ts[1].cols = 8;
    ts[1].quant = Deep2::NQBRAID_DENSE_F32; ts[1].values = b.data();
    ts[2].name = "blk.1.attn_q.weight"; ts[2].rows = 2; ts[2].cols = 2;
    ts[2].quant = Deep2::NQBRAID_DENSE_F32; ts[2].values = c.data();

    Deep2::Nanof32VocabSpec vocab;
    vocab.model = "llama"; vocab.kind = 1;
    vocab.tokens = {"<unk>", "<s>", "</s>", "a", "b", "c"};
    vocab.scores.assign(6, 0.0f);
    vocab.types.assign(6, 1);
    vocab.bosId = 1; vocab.eosId = 2; vocab.unkId = 0;

    const Deep2::Nanof32WriteResult wr = Deep2::nanof32WriteBraid(base, meta, ts, &vocab);
    chk("NC_BASELINE_WRITER_SUCCEEDED", wr.ok,
        "ok=" + std::string(wr.ok ? "1" : "0") + " tensors=" + u64s(wr.tensorCount) +
        " bytes=" + u64s(wr.bytesWritten) + " err=" + wr.error);
    if (!wr.ok) return;

    VerifyOpts o0;
    o0.sourceSetSha = "phase3";
    VerifyOut v0;
    try {
        v0 = verifyFile(base, o0);
    } catch (const Bail& b) {
        chk("NC_BASELINE_PASS", false, std::string("bail: ") + b.why);
        return;
    }
writeManifest(man, v0);

    // RAWRXD_NQB_NC_ADMISSIBILITY_001
    //
    // A negative control proves something only when the CLEAN fixture passes
    // first. A verifier with a permanently failing predicate makes every
    // mutated copy "detected" for the wrong reason -- that is exactly what a
    // permanently-broken BITS_PER_WEIGHT_MATCH did in the previous run:
    //
    //     NC_FOOTER_MAGIC_ZERO_DETECTED=PASS
    //     failed checks: FOOTER_MAGIC_FAILURES_ZERO; BITS_PER_WEIGHT_MATCH;
    //                    READER_TENSOR_COUNT_MATCH; READER_METADATA_MATCH
    //
    // Two of those four failures are inherited from the clean baseline and have
    // nothing to do with the injected fault. So each control below now names
    // the ONE predicate it is supposed to flip, and is scored on that predicate
    // ALONE. Failures present in the clean baseline are excluded by
    // construction, because admissibility requires the baseline to be clean.
    chk("BASELINE_VERDICT", g_lastClean,
        g_lastFailures.empty() ? "BASELINE_VERDICT=PASS all baseline checks pass"
                               : ("BASELINE_VERDICT=FAIL baseline failures: " + g_lastFailures));

    const bool admissible = g_lastClean;
    chk("NEGATIVE_CONTROLS_ADMISSIBLE", admissible,
        admissible ? "BASELINE_VERDICT=PASS so control results are attributable"
                   : "baseline is not clean; control results would be inadmissible");

    // Runs one mutated copy and scores it on exactly one expected predicate.
    // `expectedCheck` is a check id; `expectedBailClass` is used instead when
    // the mutation is expected to abort the walk before any check can be scored.
    std::string ctlPath;   // path of the copy under test, set by each control
    struct Control {
        const char* id;
        const char* expectedCheck;     // "" when a bail class is expected
        const char* expectedBailClass; // "" when a check is expected
    };

    auto score = [&](const char* id, const VerifyOpts& o, const Control& ctl) {
        bool threw = false;
        std::string cls, why;
        try {
            (void)verifyFile(ctlPath, o);
        } catch (const Bail& b) { threw = true; cls = b.cls; why = b.why; }

        const bool byCheck = ctl.expectedCheck[0] != '\0' &&
                             g_lastFailures.find(ctl.expectedCheck) != std::string::npos;
        const bool byBail   = ctl.expectedBailClass[0] != '\0' && threw &&
                              cls == ctl.expectedBailClass;
        const bool detected = byCheck || byBail;

        char b[1024];
        std::snprintf(b, sizeof b,
            "EXPECTED_CHECK=%s EXPECTED_BAIL_CLASS=%s EXPECTED_CHECK_FAILED=%d "
            "OBSERVED_BAIL_CLASS=%s newFailures=%s",
            ctl.expectedCheck[0] ? ctl.expectedCheck : "<none>",
            ctl.expectedBailClass[0] ? ctl.expectedBailClass : "<none>",
            (byCheck || byBail) ? 1 : 0,
            threw ? cls.c_str() : "<none>",
            g_lastFailures.empty() ? "<none>" : g_lastFailures.c_str());
        chk(id, admissible && detected,
            std::string("ADMISSIBLE=") + (admissible ? "1" : "0") + " " + b +
            (threw ? (" bailDetail=" + why) : ""));
    };

// ---- NC1: payload byte flip -------------------------------------------
    // This control ALWAYS seals its own manifest, so detection is mandatory for
    // it -- and that is a different claim from the artifact under test, which
    // stores no checksum at all. The authority is selected from whether a
    // manifest was actually loaded, in one place, for the artifact:
    //     PAYLOAD_INTEGRITY_AUTHORITY=MANIFEST_SEALED   -> detection expected
    //     PAYLOAD_INTEGRITY_AUTHORITY=STRUCTURAL_ONLY   -> not expected
    if (copyFile(base, flip)) {
        ctlPath = flip;
        char orig = 0;
        {
            std::ifstream r(flip, std::ios::binary);
            r.seekg(static_cast<std::streamoff>(v0.tensors.back().dataBegin + 4));
            r.read(&orig, 1);
        }
        const char flipped = static_cast<char>(orig ^ 0x01);
        patchByte(flip, v0.tensors.back().dataBegin + 4, &flipped, 1);

        VerifyOpts o;
        o.expectManifest = man;
        score("NC_PAYLOAD_FLIP_DETECTED", o,
              Control{"", "PAYLOAD_HASHES_MATCH_EXPECTED_MANIFEST", ""});
    } else {
        chk("NC_PAYLOAD_FLIP_DETECTED", false, "could not create corrupted copy");
    }

    // ---- NC2: footer magic zeroed ------------------------------------------
    if (copyFile(base, magic)) {
        ctlPath = magic;
        const uint32_t zero = 0;
        patchByte(magic, v0.fileSize - sizeof(Deep2::Nanof32BraidTensorFooter), &zero, 4);
        VerifyOpts o;
        score("NC_FOOTER_MAGIC_ZERO_DETECTED", o,
              Control{"", "FOOTER_MAGIC_FAILURES_ZERO", ""});
    } else {
        chk("NC_FOOTER_MAGIC_ZERO_DETECTED", false, "could not create corrupted copy");
    }

    // ---- NC3: one-byte truncation ------------------------------------------
    {
        std::ifstream in(base, std::ios::binary);
        std::vector<char> all((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        std::ofstream out(trunc, std::ios::binary | std::ios::trunc);
        out.write(all.data(), static_cast<std::streamsize>(all.size() - 1));
        out.close();
        ctlPath = trunc;
        VerifyOpts o;
        o.useReader = false;
        score("NC_TRUNCATION_DETECTED", o, Control{"", "", "STRUCTURAL_BOUNDS"});
    }

    // ---- NC4: stored headDim halved ---------------------------------------
    // The defect class that survives every structural check: a container whose
    // bytes are intact and whose metadata halves the KV cache.
    if (copyFile(base, hdim)) {
        ctlPath = hdim;
        const uint32_t halved = meta.headDim / 2;
        patchByte(hdim, sizeof(Deep2::Nanof32BraidHeader) +
                           offsetof(Deep2::Nanof32BraidArchMeta, headDim),
                  &halved, sizeof halved);
        VerifyOpts o;
        o.useReader = false;
        score("NC_HEAD_DIM_CORRUPTION_DETECTED", o,
              Control{"", "ARCH_HEAD_DIM_MATCH", ""});
    } else {
        chk("NC_HEAD_DIM_CORRUPTION_DETECTED", false, "could not create corrupted copy");
    }

    // ---- tally the controls as a set ---------------------------------------
    {
        uint64_t detected = 0, total = 0;
        for (const Check& c : g_checks) {
            const std::string id(c.id);
            if (id.rfind("NC_", 0) == 0 && id.find("_DETECTED") != std::string::npos) {
                ++total;
                if (c.pass) ++detected;
            }
        }
        chk("GATE_HAS_POWER", total > 0 && detected == total,
            "NEGATIVE_CONTROLS=" + u64s(detected) + "/" + u64s(total) +
            " ADMISSIBLE=" + (admissible ? "1" : "0"));
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "Usage: %s <file.nqb> [options]\n"
            "  --expect-tensors N  --expect-elements N  --expect-file-bytes N\n"
            "  --manifest out.txt  --expect-manifest m.txt  --phase2 out.txt\n"
            "  --f32-manifest out.txt\n"
            "  --no-reader  --reader-cap-mb N\n"
            "  --negative-controls DIR  --receipt out.txt\n", argv[0]);
        return 2;
    }

    const std::string path = argv[1];
    VerifyOpts opt;
    std::string manifestOut, phase2Out, receiptOut, ncDir, f32ManifestOut;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--expect-tensors" && i + 1 < argc) {
            opt.expectTensors = std::strtoull(argv[++i], nullptr, 10); opt.haveExpectTensors = true;
        } else if (a == "--expect-elements" && i + 1 < argc) {
            opt.expectElements = std::strtoull(argv[++i], nullptr, 10); opt.haveExpectElements = true;
        } else if (a == "--expect-file-bytes" && i + 1 < argc) {
            opt.expectFileBytes = std::strtoull(argv[++i], nullptr, 10); opt.haveExpectFileBytes = true;
        } else if (a == "--manifest" && i + 1 < argc) manifestOut = argv[++i];
        else if (a == "--expect-manifest" && i + 1 < argc) opt.expectManifest = argv[++i];
        else if (a == "--phase2" && i + 1 < argc) phase2Out = argv[++i];
        else if (a == "--f32-manifest" && i + 1 < argc) f32ManifestOut = argv[++i];
        else if (a == "--no-reader") opt.useReader = false;
        else if (a == "--no-stream") opt.streamPayload = false;
        else if (a == "--reader-cap-mb" && i + 1 < argc)
            opt.readerCapBytes = std::strtoull(argv[++i], nullptr, 10) * 1024ull * 1024ull;
        else if (a == "--receipt" && i + 1 < argc) receiptOut = argv[++i];
        else if (a == "--negative-controls" && i + 1 < argc) ncDir = argv[++i];
        else {
            std::fprintf(stderr, "INVALID_INVOCATION unknown option '%s'\n", a.c_str());
            std::printf("VERDICT=INVALID_NO_RESULT\n");
            return 2;
        }
    }

    // ---- identity ----------------------------------------------------------
    const std::string toolSha = sha256SelfExe();
    // SOURCE_SET_ID: hash of the per-file digests of every source that decides
    // this gate's verdict, combined. A receipt therefore names the source it was
    // produced from, not merely the binary.
    {
        const char* srcs[] = {
            "F:\\~dev\\rawrxd\\tools\\nqb_production_reopen.cpp",
            "F:\\~dev\\rawrxd\\src\\deep2\\Nanof32BraidFormat.hpp",
            "F:\\~dev\\rawrxd\\src\\deep2\\Nanof32BraidStreamer.hpp",
            "F:\\~dev\\rawrxd\\src\\deep2\\Nanof32BraidStreamer.cpp",
            "F:\\~dev\\rawrxd\\src\\deep2\\Nanof32BraidWriter.hpp",
            "F:\\~dev\\rawrxd\\src\\deep2\\Nanof32BraidWriter.cpp",
            "F:\\~dev\\rawrxd\\src\\deep2\\BP16Streamer.hpp",
        };
        Sha256 combo;
        for (const char* s : srcs) {
            bool ok = false;
            const std::string d = sha256File(s, &ok);
            const std::string line = std::string(s) + "=" + d + "\n";
            combo.update(line.data(), line.size());
        }
        opt.sourceSetSha = combo.hex();
    }

    std::printf("GATE=RAWRXD_NQB_PRODUCTION_REOPEN_001\n");
    std::printf("ARTIFACT=%s\n", path.c_str());
    std::printf("TOOL_BINARY_SHA256=%s\n", toolSha.c_str());
    std::printf("SOURCE_SET_ID=%s\n", opt.sourceSetSha.c_str());

    VerifyOut vo;
    try {
        vo = verifyFile(path, opt);
    } catch (const Bail& b) {
        std::printf("INSTRUMENT_BAIL_CLASS=%s\n", b.cls.c_str());
        std::printf("INSTRUMENT_BAIL=%s\n", b.why.c_str());
        for (const Check& c : g_checks)
            std::printf("CHECK %s=%s %s\n", c.id.c_str(),
                        c.pass ? "PASS" : "FAIL", c.detail.c_str());
        std::printf("VERDICT=INVALID_NO_RESULT\n");
        return 2;
    }

if (!manifestOut.empty()) writeManifest(manifestOut, vo);
    if (!f32ManifestOut.empty()) writeF32Manifest(f32ManifestOut, vo);
    if (!phase2Out.empty()) writePhase2(phase2Out, vo);

    // The artifact's own checks end here. Everything appended after this point
    // belongs to deliberately corrupted fixtures, and counting those in the same
    // bucket would make a receipt read "CHECKS_FAIL=9" when three of the nine
    // are real artifact defects and six are faults this gate injected on purpose.
    // The two totals are reported separately and the verdict is computed from
    // both.
    const size_t artifactCheckEnd = g_checks.size();

    if (!ncDir.empty()) runNegativeControls(ncDir);

    // ---- receipt fields ----------------------------------------------------
    std::printf("FILE_SIZE=%llu\n", (unsigned long long)vo.fileSize);
    std::printf("TARGET_FILE_SHA256=%s\n", vo.targetSha256.c_str());
    std::printf("HEADER_NUM_TENSORS=%llu\n", (unsigned long long)vo.headerNumTensors);
    std::printf("HEADER_PARAM_COUNT=%llu\n", (unsigned long long)vo.headerParamCount);
    std::printf("HEADER_BITS_FIELD_RAW=%llu\n", (unsigned long long)vo.headerBitsRaw);
    std::printf("HEADER_BITS_FIELD_UNIT=hundredths_of_a_bit\n");
    std::printf("DECODED_BITS_PER_WEIGHT=%s\n", dbl(vo.headerBitsDecoded).c_str());
    std::printf("DATA_START=%llu\n", (unsigned long long)vo.dataStart);
    std::printf("VOCAB_OFFSET=%llu\n", (unsigned long long)vo.vocabOffset);
    std::printf("VOCAB_BYTES=%llu\n", (unsigned long long)vo.vocabBytes);
    std::printf("VOCAB_ENTRIES=%llu\n", (unsigned long long)vo.vocabEntries);
    std::printf("CHAIN_TENSOR_COUNT=%llu\n", (unsigned long long)vo.tensors.size());
    std::printf("CHAIN_PARAM_COUNT=%llu\n", (unsigned long long)vo.chainParamCount);
    std::printf("PAYLOAD_BYTES_EXPECTED=%llu\n", (unsigned long long)vo.payloadBytesExpected);
    std::printf("PAYLOAD_BYTES_STREAMED=%llu\n", (unsigned long long)vo.payloadBytesStreamed);
    std::printf("PAYLOAD_SHORT_READS=%llu\n", (unsigned long long)vo.shortReads);
    std::printf("FINITE_VALUES=%llu\n", (unsigned long long)vo.finiteValues);
    std::printf("NAN_VALUES=%llu\n", (unsigned long long)vo.nanValues);
    std::printf("INF_VALUES=%llu\n", (unsigned long long)vo.infValues);
    std::printf("FINAL_REVERSE_HEAD=%llu\n", (unsigned long long)vo.finalReverseHead);
    std::printf("GAPS=%llu\n", (unsigned long long)vo.gaps);
    std::printf("OVERLAPS=%llu\n", (unsigned long long)vo.overlaps);
    std::printf("DISTINCT_QUANT_TYPES=%llu\n", (unsigned long long)vo.distinctQuantTypes);
    std::printf("PHASE1_PEAK_BUFFER_BYTES=%llu\n", (unsigned long long)vo.peakBufferBytes);
    std::printf("PHASE2_READER_MATERIALIZATION_MODE=FULL_TENSOR\n");
    std::printf("PHASE2_PEAK_TENSOR_BYTES=%llu\n", (unsigned long long)vo.peakReaderTensorBytes);
std::printf("PAYLOAD_INTEGRITY_AUTHORITY=%s\n", vo.payloadIntegrityAuthority.c_str());
    std::printf("READER_BF16_SELF_CONSISTENCY=REPORTED_PER_TENSOR\n");
    std::printf("BF16_CONVERSION_INDEPENDENT_ORACLE=NOT_CLAIMED_HERE\n");

uint64_t pass = 0, fail = 0, aPass = 0, aFail = 0, cPass = 0, cFail = 0;
    for (size_t i = 0; i < g_checks.size(); ++i) {
        const bool ok = g_checks[i].pass;
        (ok ? pass : fail)++;
        if (i < artifactCheckEnd) (ok ? aPass : aFail)++;
        else                       (ok ? cPass : cFail)++;
    }
    std::printf("CHECKS_TOTAL=%llu\n", (unsigned long long)g_checks.size());
    std::printf("CHECKS_PASS=%llu\n", (unsigned long long)pass);
    std::printf("CHECKS_FAIL=%llu\n", (unsigned long long)fail);
    std::printf("ARTIFACT_CHECKS_TOTAL=%llu\n", (unsigned long long)artifactCheckEnd);
    std::printf("ARTIFACT_CHECKS_FAIL=%llu\n", (unsigned long long)aFail);
    std::printf("NEGATIVE_CONTROL_CHECKS_FAIL=%llu\n", (unsigned long long)cFail);
    std::printf("ARTIFACT_VERDICT=%s\n", aFail == 0 ? "PASS" : "FAIL");
    for (const Check& c : g_checks)
        std::printf("CHECK %s=%s %s\n", c.id.c_str(),
                    c.pass ? "PASS" : "FAIL", c.detail.c_str());

    // The gate itself is trustworthy only if every negative control was
    // detected on its own named predicate. An undetected control makes the
    // artifact verdict meaningless, so it fails the run even when the artifact
    // itself is clean.
    bool controlsPassed = true;
    for (const Check& c : g_checks) {
        const std::string id(c.id);
        if ((id.rfind("NC_", 0) == 0 && id.find("_DETECTED") != std::string::npos) ||
            id == "GATE_HAS_POWER" || id == "NEGATIVE_CONTROLS_ADMISSIBLE" ||
            id == "BASELINE_VERDICT") {
            if (!c.pass) controlsPassed = false;
        }
    }

    // An incomplete read means the gate never saw the whole artifact: that is
    // INVALID, not FAIL. A FAIL is reserved for an artifact that was fully read
    // and violates a predicate.
const bool invalid = vo.shortReads != 0;
    const char* verdict = invalid ? "INVALID"
                        : ((aFail == 0 && controlsPassed) ? "PASS" : "FAIL");
    std::printf("NEGATIVE_CONTROLS_HAVE_POWER=%s\n", controlsPassed ? "1" : "0");
    std::printf("VERDICT=%s\n", verdict);
    std::printf("EXIT_SEMANTICS=PASS_gate_complete_all_predicates_passed"
                "|FAIL_gate_complete_predicate_violated"
                "|INVALID_gate_could_not_establish_authority\n");

    if (!receiptOut.empty()) {
        std::ofstream r(receiptOut, std::ios::trunc);
        if (r.is_open()) {
            r << "GATE=RAWRXD_NQB_PRODUCTION_REOPEN_001\n";
            r << "ARTIFACT=" << path << "\n";
            r << "TOOL_BINARY_SHA256=" << toolSha << "\n";
            r << "SOURCE_SET_ID=" << opt.sourceSetSha << "\n";
            r << "FILE_SIZE=" << vo.fileSize << "\n";
            r << "TARGET_FILE_SHA256=" << vo.targetSha256 << "\n";
            r << "HEADER_NUM_TENSORS=" << vo.headerNumTensors << "\n";
            r << "HEADER_PARAM_COUNT=" << vo.headerParamCount << "\n";
            r << "HEADER_BITS_FIELD_RAW=" << vo.headerBitsRaw << "\n";
            r << "DECODED_BITS_PER_WEIGHT=" << dbl(vo.headerBitsDecoded) << "\n";
            r << "DATA_START=" << vo.dataStart << "\n";
            r << "VOCAB_OFFSET=" << vo.vocabOffset << "\n";
            r << "VOCAB_BYTES=" << vo.vocabBytes << "\n";
            r << "VOCAB_ENTRIES=" << vo.vocabEntries << "\n";
            r << "CHAIN_TENSOR_COUNT=" << vo.tensors.size() << "\n";
            r << "CHAIN_PARAM_COUNT=" << vo.chainParamCount << "\n";
            r << "PAYLOAD_BYTES_EXPECTED=" << vo.payloadBytesExpected << "\n";
            r << "PAYLOAD_BYTES_STREAMED=" << vo.payloadBytesStreamed << "\n";
            r << "PAYLOAD_SHORT_READS=" << vo.shortReads << "\n";
            r << "FINITE_VALUES=" << vo.finiteValues << "\n";
            r << "NAN_VALUES=" << vo.nanValues << "\n";
            r << "INF_VALUES=" << vo.infValues << "\n";
            r << "FINAL_REVERSE_HEAD=" << vo.finalReverseHead << "\n";
            r << "GAPS=" << vo.gaps << "\n";
            r << "OVERLAPS=" << vo.overlaps << "\n";
            r << "DISTINCT_QUANT_TYPES=" << vo.distinctQuantTypes << "\n";
            r << "PHASE1_PEAK_BUFFER_BYTES=" << vo.peakBufferBytes << "\n";
            r << "PHASE2_READER_MATERIALIZATION_MODE=FULL_TENSOR\n";
            r << "PHASE2_PEAK_TENSOR_BYTES=" << vo.peakReaderTensorBytes << "\n";
r << "PAYLOAD_INTEGRITY_AUTHORITY=" << vo.payloadIntegrityAuthority << "\n";
            r << "BF16_CONVERSION_INDEPENDENT_ORACLE=NOT_CLAIMED_HERE\n";
            r << "CHECKS_TOTAL=" << g_checks.size() << "\n";
            r << "CHECKS_PASS=" << pass << "\n";
            r << "CHECKS_FAIL=" << fail << "\n";
            for (const Check& c : g_checks)
                r << "CHECK " << c.id << "=" << (c.pass ? "PASS" : "FAIL")
                  << " " << c.detail << "\n";
            r << "VERDICT=" << verdict << "\n";
        }
    }

// The exit code must agree with the printed verdict. They used to disagree: the
// verdict was computed from the artifact tally plus control results, while the
// return still used the combined tally, so a run whose artifact PASSED and whose
// only failures were faults the gate had deliberately injected printed
//     VERDICT=PASS
//     EXIT=1
// An exit code that contradicts the verdict is worse than either, because a
// caller that checks the code concludes the gate failed.
if (std::string(verdict) == "INVALID") return 2;
if (std::string(verdict) == "PASS")    return 0;
return 1;
}