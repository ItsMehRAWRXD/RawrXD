// gguf_q6k_trace.hpp
// RAWRXD_Q6K_LIVE_BLOCK_TRACE_001
//
// An observation hook inside the PRODUCTION Q6_K decoder.
//
// Why this exists: q6k_row_decisive.cpp compared a hand-written direct decode
// against gguf_loader::ToFloat32 and reported the two disagreeing at element 0
// of block 0 by an exact factor of 2. Both of those implementations, read side
// by side, compute the identical expression on the identical bytes for element
// 0, so the disagreement could not be explained by either one's source. That
// means the measurement, not the decoder, was suspect -- but a disagreement you
// cannot explain is exactly the case where you must stop reasoning from source
// and instrument the execution.
//
// This header provides that instrumentation point. It is a runtime-null hook:
// with no sink installed the production decoder executes one predictable
// branch per block and nothing else, and no decode result changes. With a sink
// installed, DequantQ6_K records, AT THE POINT OF CONSUMPTION, the addresses it
// actually dereferenced and each intermediate value it actually derived for one
// target element.
//
// The sink is deliberately given the pointers the decoder itself holds. If the
// decoder and the harness are reading the same block, the addresses are equal
// as numbers. If they are not, the addresses say so immediately, which no amount
// of source comparison can establish.
#ifndef RAWRXD_GGUF_Q6K_TRACE_HPP
#define RAWRXD_GGUF_Q6K_TRACE_HPP

#include <cstdint>

namespace rawrxd {

// One element, fully decomposed, as observed inside a decoder.
struct Q6KTraceRecord {
    // Element being observed, as an index WITHIN its 256-element super-block.
    uint32_t element = 0;

    // Addresses the decoder actually dereferenced for this element.
    uintptr_t src_addr    = 0;   // base of the super-block it was decoding
    uintptr_t ql_addr     = 0;   // src + ql_offset
    uintptr_t qh_addr     = 0;   // src + qh_offset
    uintptr_t scales_addr = 0;   // src + scales_offset
    uintptr_t d_addr      = 0;   // src + d_offset

    // Those addresses expressed as offsets from the block base. For element 0
    // these must be 0 / 128 / 192 / 208 regardless of what the base address is.
    uint32_t ql_offset     = 0;
    uint32_t qh_offset     = 0;
    uint32_t scales_offset = 0;
    uint32_t d_offset      = 0;

    // Bytes read from those addresses.
    uint8_t  ql0_raw = 0;    // the ql byte consumed for this element
    uint8_t  qh0_raw = 0;    // the qh byte consumed for this element
    int8_t   scale0_raw = 0; // the scale byte consumed for this element
    uint16_t d_raw_u16 = 0;  // the fp16 super-scale, before conversion

    // Derived values, in the order the decoder derives them.
    float    d_fp32         = 0.0f;
    int32_t  q_low4         = 0;   // ql nibble
    int32_t  q_high2        = 0;   // qh 2-bit field, already shifted to 4
    int32_t  q6_unsigned    = 0;   // low4 | high2, before the -32 bias
    int32_t  q6_signed      = 0;   // after the -32 bias
    float    d_times_scale  = 0.0f;
    float    result         = 0.0f;

    // Loop coordinates, so a disagreement can be localized to a half-block,
    // a 32-weight run, or a single lane.
    uint32_t n_loop = 0;    // 0 or 128
    uint32_t l_loop = 0;    // 0..31
    uint32_t is_sub = 0;    // l/16
    uint32_t run    = 0;    // 0..3 -> q1..q4
};

using Q6KTraceSink = void (*)(const Q6KTraceRecord&);

// The element currently being observed. Only meaningful while a sink is set.
extern uint32_t    g_q6k_trace_element;
extern Q6KTraceSink g_q6k_trace_sink;

// The block the observation is about, as a base address. 0 means "any".
//
// This is not redundant with the element. Element 0 exists in EVERY block, so
// gating on the element alone fires once per block and reports whichever block
// was decoded LAST. That looks like a base-pointer disagreement -- between two
// paths that in fact each decoded every block -- and would send the whole
// investigation to the wrong operator. Pinning the block turns "did these two
// paths execute the same block" into a measured field with a definite answer.
extern uintptr_t  g_q6k_trace_src;

// Counter of records actually emitted. A sink that never fires is a different
// failure from a sink that fires and disagrees.
extern uint64_t g_q6k_trace_records;

}  // namespace rawrxd

#endif  // RAWRXD_GGUF_Q6K_TRACE_HPP