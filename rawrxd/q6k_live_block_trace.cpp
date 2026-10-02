// q6k_live_block_trace.cpp
// RAWRXD_Q6K_LIVE_BLOCK_TRACE_001
//
// FORENSIC, NOT NUMERICAL.
//
// The previous test (q6k_row_decisive.cpp) reported:
//
//     DETAIL col=0  direct=-0.0148701668  tofloat=-0.00743508339   (exact 2x)
//
// Two decoders cannot disagree about element 0 of block 0 by a factor of two
// while both compute `d * scales[0] * (((ql[0] & 0x0F) | (((qh[0] >> 0) & 3) << 4)) - 32)`
// from the same base pointer. Reading both sources side by side, the arithmetic
// is identical. So either the two executions are not reading the same bytes, or
// the comparison was not measuring what it claimed to measure.
//
// A disagreement you cannot explain is not evidence about the decoder. It is
// evidence that the MEASUREMENT is untrustworthy. So this test stops comparing
// results and starts recording inputs.
//
// The two paths are instrumented at their own points of consumption and never
// share helper state:
//
//   PATH=TOFLOAT32  recorded INSIDE gguf_loader's DequantQ6_K, through a
//                   runtime-null hook, from the live ql/qh/scales pointers.
//   PATH=DIRECT     recorded HERE, in this file, from bytes this file reads.
//
// FIRST_DIFFERENCE is the first field at which the two records disagree. Every
// field before it agrees, so it localizes the defect rather than restating it.
//
// The decisive fields, in the order they are consumed:
//   base/block pointer -> aliasing or view ownership
//   ql0/qh0/scales0/d  -> wrong field base within the block
//   d bits == , d_fp32 != -> fp16 conversion path
//   all inputs ==, q6_signed != -> extraction/arithmetic
//   all intermediates ==, result != -> execution/UB
//   everything == -> the two paths were never observing the same execution
#include "gguf_loader.hpp"
#include "gguf_q6k_trace.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace rawrxd;

// The layout the binary actually compiles against, not as assumed.
#pragma pack(push, 1)
struct BlockQ6KLayout {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t  scales[16];
    uint16_t d;
};
#pragma pack(pop)

static constexpr int kQKK = 256;   // weights per Q6_K super-block

// ── the sink for PATH=TOFLOAT32 ────────────────────────────────────────────
static Q6KTraceRecord g_tofloat;
static bool           g_tofloat_fired = false;

static void CaptureToFloat(const Q6KTraceRecord& r) {
    g_tofloat = r;
    g_tofloat_fired = true;
}

// ── PATH=DIRECT ────────────────────────────────────────────────────────────
// Deliberately written from the pinned upstream dequantize_row_q6_K and NOT
// sharing any helper with gguf_loader. It computes the record from pointers it
// derives itself, so an address disagreement is visible as a number.
static bool TraceDirect(const uint8_t* packed, size_t cols, size_t row, size_t col,
                        uint32_t elementInBlock, Q6KTraceRecord& out) {
    const size_t idx = row * cols + col;
    const size_t b   = idx / kQKK;
    const size_t p   = idx % kQKK;
    if (elementInBlock != p) return false;   // caller must ask about this element

    const uint8_t* blk = packed + b * sizeof(BlockQ6KLayout);

    // Upstream loop coordinates: two 128-element halves, 32 lanes, 4 runs.
    // The half matters: the decoder advances its field bases between halves
    // (ql += 64, qh += 32, scales += 8), so an element at or past 128 reads
    // DIFFERENT ADDRESSES within the same physical 210-byte block. Omitting that
    // advance produces a QL_OFFSET disagreement at exactly element 128 and
    // nowhere earlier, which is what this harness did before the advance was
    // added. The advance is applied here from the pinned upstream loop.
    const uint32_t half = (p / 128u);
    const uint32_t n    = half * 128u;
    const uint32_t w    = static_cast<uint32_t>(p % 128);
    const uint32_t run  = w / 32u;
    const uint32_t lane = w % 32u;
    const uint32_t is   = lane / 16u;
    const uint32_t ql_lane = (run == 1u || run == 3u) ? lane + 32u : lane;
    const uint32_t shift   = run * 2u;
    const bool     hi_nib  = (run == 2u || run == 3u);

    const uint8_t* ql_ptr = blk + offsetof(BlockQ6KLayout, ql)
                          + half * 64u + ql_lane;
    const uint8_t* qh_ptr = blk + offsetof(BlockQ6KLayout, qh)
                          + half * 32u + lane;
    const int8_t*  sc_ptr = reinterpret_cast<const int8_t*>(
                              blk + offsetof(BlockQ6KLayout, scales))
                          + half * 8u + is + run * 2u;
    const uint8_t* d_ptr  = blk + offsetof(BlockQ6KLayout, d);

    const uint8_t ql_byte = *ql_ptr;
    const uint8_t qh_byte = *qh_ptr;
    const int8_t  sc_byte = *sc_ptr;
    const uint16_t d_raw  = static_cast<uint16_t>(d_ptr[0] | (d_ptr[1] << 8));

    // Independent fp16 -> fp32, written as ARITHMETIC rather than as bit
    // assembly, deliberately NOT as a transcription of ggml_loader's routine.
    //
    // The first version of this harness copied the loader's bit manipulation
    // "so a defect there would show up as a differing intermediate" and
    // consequently agreed with the loader on every fp16 subnormal, including
    // exactly the ones the loader halves. A reference built from the code under
    // test cannot detect a defect in it -- that is the whole point of having two.
    // Written as arithmetic it shares no code with gguf_loader at all:
    //   subnormal : 2^-14 * mant/1024 = mant * 2^-24
    //   normal    : 2^(exp-15) * (1 + mant/1024) = (mant + 1024) * 2^(exp-25)
    float df;
    {
        const int      sign = (d_raw & 0x8000u) ? -1 : 1;
        const uint32_t exp  = (d_raw >> 10) & 0x1Fu;
        const uint32_t mant = d_raw & 0x3FFu;
        if (exp == 0x1Fu) {
            df = (mant != 0u) ? NAN : (float)sign * INFINITY;
        } else if (exp == 0u) {
            df = (mant == 0u) ? (float)sign * 0.0f
                              : (float)sign * std::ldexp((float)mant, -24);
        } else {
            df = (float)sign * std::ldexp((float)(mant + 1024u), (int)exp - 25);
        }
    }

    const uint32_t low4  = hi_nib ? (ql_byte >> 4) : (ql_byte & 0x0Fu);
    const uint32_t high2 = ((qh_byte >> shift) & 3u) << 4;
    const uint32_t uns   = low4 | high2;
    const int32_t  sq    = static_cast<int32_t>(uns) - 32;
    const float    dsc   = df * static_cast<float>(sc_byte);

    out.element       = p;
    out.src_addr      = reinterpret_cast<uintptr_t>(blk);
    out.ql_addr       = reinterpret_cast<uintptr_t>(ql_ptr);
    out.qh_addr       = reinterpret_cast<uintptr_t>(qh_ptr);
    out.scales_addr   = reinterpret_cast<uintptr_t>(sc_ptr);
    out.d_addr        = reinterpret_cast<uintptr_t>(d_ptr);
    out.ql_offset     = static_cast<uint32_t>(ql_ptr - blk);
    out.qh_offset     = static_cast<uint32_t>(qh_ptr - blk);
    out.scales_offset = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(sc_ptr) -
                                             reinterpret_cast<uintptr_t>(blk));
    out.d_offset      = static_cast<uint32_t>(d_ptr - blk);
    out.ql0_raw       = ql_byte;
    out.qh0_raw       = qh_byte;
    out.scale0_raw    = sc_byte;
    out.d_raw_u16     = d_raw;
    out.d_fp32        = df;
    out.q_low4        = static_cast<int32_t>(low4);
    out.q_high2       = static_cast<int32_t>(high2);
    out.q6_unsigned   = static_cast<int32_t>(uns);
    out.q6_signed     = sq;
    out.d_times_scale = dsc;
    out.result        = dsc * static_cast<float>(sq);
    out.n_loop        = n;
    out.l_loop        = lane;
    out.is_sub        = is;
    out.run           = run;
    return true;
}

static void Emit(const char* path, const Q6KTraceRecord& r) {
    std::printf("PATH=%s\n", path);
    std::printf("%s_BASE_ADDR=%p\n", path, reinterpret_cast<void*>(r.src_addr));
    std::printf("%s_QL_ADDR=%p\n",  path, reinterpret_cast<void*>(r.ql_addr));
    std::printf("%s_QH_ADDR=%p\n",  path, reinterpret_cast<void*>(r.qh_addr));
    std::printf("%s_SCALE_ADDR=%p\n", path, reinterpret_cast<void*>(r.scales_addr));
    std::printf("%s_D_ADDR=%p\n",   path, reinterpret_cast<void*>(r.d_addr));
    std::printf("%s_QL_OFFSET=%u\n", path, r.ql_offset);
    std::printf("%s_QH_OFFSET=%u\n", path, r.qh_offset);
    std::printf("%s_SCALE_OFFSET=%u\n", path, r.scales_offset);
    std::printf("%s_D_OFFSET=%u\n", path, r.d_offset);
    std::printf("%s_ql0_raw=%u\n", path, (unsigned)r.ql0_raw);
    std::printf("%s_qh0_raw=%u\n", path, (unsigned)r.qh0_raw);
    std::printf("%s_scale0_raw=%d\n", path, (int)r.scale0_raw);
    std::printf("%s_scale0_signed=%d\n", path, (int)r.scale0_raw);
    std::printf("%s_d_raw_u16=0x%04X\n", path, (unsigned)r.d_raw_u16);
    std::printf("%s_d_fp32=%.9g\n", path, (double)r.d_fp32);
    std::printf("%s_q_low4=%d\n", path, (int)r.q_low4);
    std::printf("%s_q_high2=%d\n", path, (int)r.q_high2);
    std::printf("%s_q6_unsigned=%d\n", path, (int)r.q6_unsigned);
    std::printf("%s_q6_signed=%d\n", path, (int)r.q6_signed);
    std::printf("%s_d_x_scale=%.9g\n", path, (double)r.d_times_scale);
    std::printf("%s_Q=%d\n", path, (int)r.q6_signed);
    std::printf("%s_result0=%.9g\n", path, (double)r.result);
    std::printf("%s_n_loop=%u %s_l_loop=%u %s_is_sub=%u %s_run=%u\n",
                path, r.n_loop, path, r.l_loop, path, r.is_sub, path, r.run);
    std::printf("\n");
}

// Field-by-field comparison, in consumption order. The first disagreement is
// the finding; everything before it is proven to agree.
static const char* FirstDifference(const Q6KTraceRecord& a, const Q6KTraceRecord& b) {
    if (a.src_addr      != b.src_addr)      return "BASE_POINTER";
    if (a.element       != b.element)       return "ELEMENT_INDEX";
    if (a.ql_offset     != b.ql_offset)     return "QL_OFFSET";
    if (a.qh_offset     != b.qh_offset)     return "QH_OFFSET";
    if (a.scales_offset != b.scales_offset) return "SCALE_OFFSET";
    if (a.d_offset      != b.d_offset)      return "D_OFFSET";
    if (a.ql0_raw       != b.ql0_raw)       return "QL_BYTE";
    if (a.qh0_raw       != b.qh0_raw)       return "QH_BYTE";
    if (a.scale0_raw    != b.scale0_raw)    return "SCALE_BYTE";
    if (a.d_raw_u16     != b.d_raw_u16)     return "D_BITS";
    if (a.d_fp32        != b.d_fp32)        return "D_FP32";
    if (a.q_low4        != b.q_low4)        return "Q_LOW4";
    if (a.q_high2       != b.q_high2)       return "Q_HIGH2";
    if (a.q6_unsigned   != b.q6_unsigned)   return "Q6_UNSIGNED";
    if (a.q6_signed     != b.q6_signed)     return "Q6_SIGNED";
    if (a.d_times_scale != b.d_times_scale) return "D_X_SCALE";
    if (a.result        != b.result)        return "RESULT";
    return nullptr;
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    const char* want        = argc > 2 ? argv[2] : nullptr;
    const size_t rowSel     = argc > 3 ? (size_t)atoll(argv[3]) : 0;

    std::printf("RAWRXD_Q6K_LIVE_BLOCK_TRACE_001\n");

    // ── layout, from the compiled type ──
    std::printf("\n; --- live compiled layout ---\n");
    std::printf("QK_K=%d\n", kQKK);
    std::printf("BLOCK_BYTES=%zu\n", sizeof(BlockQ6KLayout));
    std::printf("OFFSETOF_ql=%zu\n",     offsetof(BlockQ6KLayout, ql));
    std::printf("OFFSETOF_qh=%zu\n",     offsetof(BlockQ6KLayout, qh));
    std::printf("OFFSETOF_scales=%zu\n", offsetof(BlockQ6KLayout, scales));
    std::printf("OFFSETOF_d=%zu\n",      offsetof(BlockQ6KLayout, d));
    std::printf("LAYOUT_MATCHES_KERNEL_ASSUMPTION=%d\n",
                (offsetof(BlockQ6KLayout, ql) == 0 &&
                 offsetof(BlockQ6KLayout, qh) == 128 &&
                 offsetof(BlockQ6KLayout, scales) == 192 &&
                 offsetof(BlockQ6KLayout, d) == 208 &&
                 sizeof(BlockQ6KLayout) == 210) ? 1 : 0);

    GGUFLoader loader;
    if (!loader.LoadFromFile(path)) { std::printf("LOAD=FAIL\n"); return 2; }
    const GGUFModel* m = loader.GetModel();

    const GGUFTensorInfo* tinfo = nullptr;
    for (const auto& t : m->tensors) {
        if (t.ggml_type != GGMLType::Q6_K || t.shape.size() != 2) continue;
        const size_t cols = (size_t)t.shape[0], rows = (size_t)t.shape[1];
        if (rows == cols) continue;
        if (want && t.name != want) continue;
        tinfo = &t; break;
    }
    if (!tinfo) { std::printf("NO_NONSQUARE_Q6K_TENSOR\n"); return 3; }

    const size_t cols = (size_t)tinfo->shape[0];
    const size_t rows = (size_t)tinfo->shape[1];
    const size_t blocksPerRow = cols / kQKK;
    const size_t rowBytes = blocksPerRow * sizeof(BlockQ6KLayout);
    const size_t r = (rowSel < rows) ? rowSel : 0;

    auto view = loader.GetTensor(tinfo->name);
    if (!view) { std::printf("TENSOR_LOOKUP=FAIL\n"); return 4; }
    const uint8_t* packed = view->data<uint8_t>();

    std::printf("\n; --- target ---\n");
    std::printf("TENSOR=%s\n", tinfo->name.c_str());
    std::printf("ROWS=%zu\nCOLS=%zu\nBLOCKS_PER_ROW=%zu\nROW_BYTES=%zu\nROW_INDEX=%zu\n",
                rows, cols, blocksPerRow, rowBytes, r);
    std::printf("TENSOR_ELEMENT_COUNT=%zu\n", tinfo->element_count);
    std::printf("TENSOR_BYTE_SIZE=%zu\n", tinfo->byte_size);
    std::printf("VIEW_BLOCK_SIZE=%zu\n", view->block_size());
    std::printf("VIEW_DATA_PTR=%p\n", reinterpret_cast<const void*>(packed));

    // The expected offsets for block 0, element 0. Every one of these is a
    // *claim* about where the fields live; the two records below either confirm
    // it with measured addresses or refute it.
    std::printf("\n; --- expected offsets for block 0 element 0 ---\n");
    std::printf("QL_OFFSET=0\nQH_OFFSET=128\nSCALE_OFFSET=192\nD_OFFSET=208\nBLOCK_SIZE=%zu\n",
                sizeof(BlockQ6KLayout));

    int verdict = 0;
    const char* firstOverall = nullptr;
    uint64_t sinkRecordsLast = 0;
    bool allBlocksSameBase = true;

    // Element 0 first, on its own, exactly as the checkpoint directs. The wider
    // signature set only runs after element 0 is explained.
    const uint32_t firstPass[] = { 0u };
    const uint32_t secondPass[] = { 0u, 16u, 32u, 48u, 64u, 80u, 96u, 112u,
                                    128u, 144u, 160u, 192u, 224u };

    auto traceElement = [&](uint32_t col, bool last) -> const char* {
        Q6KTraceRecord direct{};
        if (!TraceDirect(packed, cols, r, col, static_cast<uint32_t>(col % kQKK), direct)) {
            std::printf("DIRECT_TRACE_REFUSED col=%u\n", (unsigned)col);
            return "TRACE_SETUP";
        }
        g_tofloat_fired = false;
        g_q6k_trace_records = 0;
        g_q6k_trace_element = static_cast<uint32_t>(col % kQKK);
        // Pin the block. Without this the hook observes element 0 of EVERY block
        // and reports the last one, which mimics a base-pointer disagreement
        // between two paths that each decoded every block.
        const size_t blockIndex = (r * cols + col) / kQKK;
        g_q6k_trace_src = reinterpret_cast<uintptr_t>(
            packed + blockIndex * sizeof(BlockQ6KLayout));
        g_q6k_trace_sink   = &CaptureToFloat;
        std::vector<float> dec;
        const bool ok = view->ToFloat32(dec);
        g_q6k_trace_sink = nullptr;
        g_q6k_trace_src   = 0;
        if (!ok) { std::printf("TOFLOAT32_FAILED col=%u\n", (unsigned)col); return "TOFLOAT32_FAILED"; }
        if (!g_tofloat_fired) {
            std::printf("TOFLOAT32_SINK_NEVER_FIRED col=%u\n", (unsigned)col);
            return "SINK_NEVER_FIRED";
        }

        std::printf("\n; ============ element %u (col %u) ============\n",
                    (unsigned)(col % kQKK), (unsigned)col);
        Emit("DIRECT", direct);
        Emit("TOFLOAT", g_tofloat);
        std::printf("TOFLOAT_SINK_RECORDS=%llu\n", (unsigned long long)g_q6k_trace_records);

        const char* first = FirstDifference(direct, g_tofloat);
        if (first == nullptr) {
            std::printf("ALL_FIELDS_MATCH=1\n");
            return nullptr;
        }
        std::printf("ALL_FIELDS_MATCH=0\n");
        std::printf("FIRST_DIFFERENCE=%s\n", first);
        // The two independent diagnostics that separate the remaining candidates.
        std::printf("Q_MATCH=%d\n", direct.q6_signed == g_tofloat.q6_signed ? 1 : 0);
        std::printf("D_X_SCALE_MATCH=%d\n",
                    direct.d_times_scale == g_tofloat.d_times_scale ? 1 : 0);
        if (last) {
            // Also print what the previous test reported, from the same bytes,
            // so the earlier "exact 2x" is either reproduced or shown stale.
            const float fromBuffer = dec[r * cols + col];
            std::printf("BUFFER_ELEMENT=%.9g\n", (double)fromBuffer);
            std::printf("DIRECT_RESULT=%.9g\n", (double)direct.result);
            std::printf("TOFLOAT_RESULT=%.9g\n", (double)g_tofloat.result);
            const double ratio = (direct.d_times_scale != 0.0f)
                ? (double)fromBuffer / (double)direct.d_times_scale : 0.0;
            std::printf("BUFFER_OVER_DXSCALE=%.9g\n", ratio);
        }
        return first;
    };

    std::printf("\n; ============ PASS 1: element 0 only ============\n");
    const char* f0 = traceElement(0u, true);
    if (f0) {
        firstOverall = f0;
        std::printf("\nVERDICT=%s\n", f0);
        std::printf("LOCALIZED_AT=ELEMENT_0\n");
        return 0;
    }
    std::printf("ELEMENT_0_EXPLAINED=1\n");

    std::printf("\n; ============ PASS 2: block-0 signature set ============\n");
    const char* first2 = nullptr;
    for (uint32_t c : secondPass) {
        const char* f = traceElement(c, false);
        if (f && !first2) first2 = f;
        sinkRecordsLast = g_q6k_trace_records;
        if (g_q6k_trace_records != 1) allBlocksSameBase = false;
    }
    if (first2) {
        firstOverall = first2;
        std::printf("\nVERDICT=%s\n", first2);
        std::printf("LOCALIZED_AT=SIGNATURE_SET\n");
    } else {
        std::printf("\nVERDICT=NO_DIFFERENCE_FOUND\n");
    }

    // ── terminal receipt ──
    std::printf("\nRAWRXD_Q6K_LIVE_BLOCK_TRACE_001\n");
    std::printf("ELEMENTS_TRACED=%zu\n", sizeof(secondPass) / sizeof(secondPass[0]));
    std::printf("SINK_RECORDS_PER_ELEMENT=%llu\n", (unsigned long long)sinkRecordsLast);
    // Exactly one record per requested element is what makes the hook trustworthy:
    // more means it observed some block other than the one pinned, fewer means it
    // never reached the element at all.
    std::printf("SINK_RECORD_COUNT_EXACT=%d\n", sinkRecordsLast == 1 ? 1 : 0);
    std::printf("SAME_BASE=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("SAME_QL_BYTE=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("SAME_QH_BYTE=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("SAME_SCALE_BYTE=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("SAME_D_BITS=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("SAME_D_FP32=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("SAME_Q6_VALUE=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("SAME_ELEMENT0_RESULT=%s\n", firstOverall ? "UNTESTED" : "YES");
    std::printf("FIRST_DIFFERENCE=%s\n", firstOverall ? firstOverall : "NONE");
    return verdict;
}