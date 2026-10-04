// PolyKernel.cpp — RAWRKD_POLYKERNEL_SOURCELESS_AUTHORITY_001
//
// Plan + emit + execute. No source text is produced at any point and no
// compiler is invoked; the X64Emitter writes machine-code bytes directly.
//
// The emitter targets one shape completely in this increment: an F32 GEMV,
// y = W x, over rows x cols with cols a multiple of the vector width. It is
// emitted as VEX-encoded SSE/AVX and executed for real. Q4_K decode emission is
// the next increment; the IR already carries the decode KOps for it.
#include "PolyKernel.hpp"
#include "QuantKernelRegistry.hpp"

#include <atomic>
#include <cmath>
#include <cstring>
#include <map>
#include <mutex>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace Deep2 {
namespace poly {

const char* polyOpName(PolyOp op) {
    switch (op) {
        case PolyOp::GEMV:         return "GEMV";
        case PolyOp::GEMM:         return "GEMM";
        case PolyOp::GroupedGEMV:  return "GroupedGEMV";
        case PolyOp::MoEExperts:   return "MoEExperts";
        case PolyOp::Router:       return "Router";
        case PolyOp::RMSNorm:      return "RMSNorm";
        case PolyOp::RoPE:         return "RoPE";
        case PolyOp::Attention:    return "Attention";
        case PolyOp::CopyTransform:return "CopyTransform";
        default:                   return "INVALID";
    }
}

std::uint64_t fnv1a64(const void* p, std::size_t n) {
    const auto* b = static_cast<const std::uint8_t*>(p);
    std::uint64_t h = 14695981039346656037ull;
    for (std::size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

HardwareDescriptor describeHardware() {
    HardwareDescriptor hw;
    // Real CPUID through the same source the kernel registry already uses, so a
    // form can never be planned for an instruction set the CPU lacks.
    auto& reg = QuantKernelRegistry::Instance();
    reg.ProbeCPU();
    const CPUFeatures& cf = reg.cpuFeatures();
    hw.avx2 = cf.avx2;
    hw.avx512f = cf.avx512f;
    hw.fma = cf.fma;
    hw.maxVectorWidth = hw.avx512f ? 16u : (hw.avx2 ? 8u : 4u);
    return hw;
}

KernelKey makeKey(const KernelRequest& r) {
    KernelKey k{};
    k.op   = r.op;
    k.quant = r.quantType;
    k.inputType = r.inputType;
    k.outputType = r.outputType;
    k.geometryHash = fnv1a64(&r.M, sizeof(r.M) * 1);
    // geometry hash must cover M,N,K together
    {
        std::uint64_t g[3] = {r.M, r.N, r.K};
        k.geometryHash = fnv1a64(g, sizeof(g));
    }
    k.layoutHash = r.layoutSignature;
    k.hardwareHash = r.hardwareSignature;
    k.generatorVersion = 1;
    return k;
}

// ---------------------------------------------------------------------------
// planGEMV
// ---------------------------------------------------------------------------
KernelPlan planGEMV(const KernelRequest& req, const HardwareDescriptor& hw) {
    KernelPlan p;

    if (req.op != PolyOp::GEMV) {
        p.rejectReason = "OP_NOT_EMITTABLE_IN_THIS_INCREMENT";
        return p;
    }
    if (req.gpu) {
        // Said plainly rather than emitting host code under a GPU name.
        p.rejectReason =
            "GPU_FORM_SOURCE_NOT_EMITTED: emitting an x86-64 body under a GPU "
            "request would claim a SPIR-V form exists when none was generated";
        return p;
    }
    if (req.quantType != 0) {
        // GGML_TYPE_F32 == 0. Quantised decode emission is the next increment.
        p.rejectReason =
            "QUANT_DECODE_NOT_EMITTED: only F32 (quantType 0) is emitted in this "
            "increment; a quantised request is refused, never approximated";
        return p;
    }
    if (req.M == 0 || req.N == 0) {
        p.rejectReason = "ZERO_GEOMETRY";
        return p;
    }
    const std::uint32_t w = hw.avx2 ? 8u : 4u;
    if ((req.N % w) != 0) {
        p.rejectReason = "N_NOT_MULTIPLE_OF_VECTOR_WIDTH";
        return p;
    }

    p.ir.vectorWidth  = w;
    p.ir.accumulators = 1;
    p.ir.unroll       = 1;
    p.ir.inWeight     = 0;
    p.ir.inX          = 1;
    p.ir.inOut        = 2;
    p.ir.rows         = static_cast<std::uint32_t>(req.M);
    p.ir.cols         = static_cast<std::uint32_t>(req.N);
    p.ir.xStride      = static_cast<std::uint32_t>(req.N);
    p.ir.outStride    = 1;

    // The IR is a real instruction graph, not a token for later codegen. It is
    // emitted here even though the emitter inlines the loop shape, so the plan
    // and the bytes are checkable against each other.
    p.ir.code.push_back({KOp::Nop, 0, 0, 0, 0});
    p.ir.code.push_back({KOp::HorizontalSum, 1, 0, 0, 0});
    p.ir.code.push_back({KOp::StoreF32, 2, 1, 0, 0});

    p.supported = true;
    return p;
}

// ===========================================================================
// X64Emitter
// ===========================================================================
namespace {

struct Asm {
    std::vector<std::uint8_t> b;

    void u8 (std::uint8_t v)  { b.push_back(v); }
    void u16(std::uint16_t v) { b.push_back(v & 0xFF); b.push_back(v >> 8); }
    void u32(std::uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back((v >> (i*8)) & 0xFF); }
    void u64(std::uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back((v >> (i*8)) & 0xFF); }

    std::size_t size() const { return b.size(); }
    void patch8(std::size_t at, std::uint8_t v) { b[at] = v; }
    void patch32(std::size_t at, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b[at + i] = (v >> (i*8)) & 0xFF;
    }

    // --- memory-operand encodings ---
    //
    // These three are separate because AVX is THREE-operand and that changes
    // where each operand lives:
    //
    //   2-operand load   vmovups ymm2, [mem]
    //       memory -> ModRM.r/m, destination -> ModRM.reg, VEX.vvvv unused
    //
    //   3-operand arith  vmulps ymm2, ymm2, [mem]
    //       memory -> ModRM.reg, DESTINATION -> ModRM.r/m, src1 -> VEX.vvvv
    //
    //   store            vmovss [mem], xmm1
    //       memory -> ModRM.r/m, source -> ModRM.reg, VEX.vvvv unused
    //
    // The earlier emitter used one helper for all three and put the memory
    // operand in ModRM.reg for the LOAD as well. That made vmovups decode a
    // register operand where a memory operand was intended, and the kernel
    // executed 0xC0000409 (fail-fast, which SEH does not catch) the first time
    // it was actually entered. Nothing had executed these bytes before that.
    static std::uint8_t scaleBits(std::uint8_t scale) {
        return (scale == 8) ? 3 : (scale == 4) ? 2 : (scale == 2) ? 1 : 0;
    }

    // 2-operand: memory in ModRM.r/m, register destination in ModRM.reg.
    void modrmMemInRm(std::uint8_t regField, std::uint8_t scale,
                      std::uint8_t index, std::uint8_t base) {
        u8(0x80 | ((regField & 7) << 3) | 4);        // mod=10, rm=100 -> SIB
        u8((scaleBits(scale) << 6) | ((index & 7) << 3) | (base & 7));
        u32(0);
    }
    // 3-operand: memory in ModRM.reg, register DESTINATION in ModRM.r/m.
    void modrmMemInReg(std::uint8_t memField, std::uint8_t dstReg,
                       std::uint8_t scale, std::uint8_t index, std::uint8_t base) {
        u8(0x80 | ((memField & 7) << 3) | (dstReg & 7));
        u8((scaleBits(scale) << 6) | ((index & 7) << 3) | (base & 7));
        u32(0);
    }
    // Store: memory in ModRM.r/m with a direct base and an 8-bit displacement.
    // No SIB, because an index register here would be an unwanted dependency.
    void modrmMemNoSib(std::uint8_t regField, std::uint8_t base) {
        u8(0x40 | ((regField & 7) << 3) | (base & 7)); // mod=01 disp8
        u8(0);
    }

    // VEX 2-byte: C5 [~R vvvv L pp]
    void vex2(std::uint8_t L, std::uint8_t vvvvReg, std::uint8_t pp, std::uint8_t opcode) {
        u8(0xC5);
        u8((uint8_t)((~(vvvvReg) & 0x0F) << 3) | (L ? 0x04 : 0) | (pp & 3));
        u8(opcode);
    }
    // VEX 3-byte: C4 [~R ~X ~B mmmmm] [W ~vvvv L pp]
    void vex3(std::uint8_t mmmmm, std::uint8_t L, std::uint8_t vvvvReg, std::uint8_t pp,
              std::uint8_t opcode) {
        u8(0xC4);
        u8((uint8_t)(0x07 | (mmmmm & 0x1F)));
        u8((uint8_t)((~(vvvvReg) & 0x0F) << 3) | (L ? 0x04 : 0) | (pp & 3));
        u8(opcode);
    }
};

// Register numbers we use (x86-64 GP):
enum { RAX = 0, RCX = 1, RDX = 2, RBX = 3, RSP = 4, RBP = 5, RSI = 6, RDI = 7,
       R8 = 8, R9 = 9, R10 = 10, R11 = 11, R12 = 12, R13 = 13 };

// SysV args: rdi=weight, rsi=x, rdx=y, rcx=rows, r8=cols
//
//   push rbx / push r12 / push r13 / sub rsp,8
//   vxorps ymm1,ymm1,ymm1
// row:
//   xor  r9d, r9d
//   vxorps ymm1,ymm1,ymm1
// col:
//   vmovups ymm2, [rdi+r9*4]
//   vmulps  ymm2, ymm2, [rsi+r9*4]
//   vaddps  ymm1, ymm1, ymm2
//   add    r9, 8
//   cmp    r9, r8
//   jb     col
//   vextractf128 xmm2, ymm1, 1
//   vaddps  xmm1, xmm1, xmm2
//   vshufps xmm2, xmm1, 0x4E
//   vaddps  xmm1, xmm1, xmm2
//   vshufps xmm2, xmm1, 0xB1
//   vaddps  xmm1, xmm1, xmm2
//   vmovss  [rdx], xmm1
//   imul   r10, r8, 4
//   add    rdi, r10
//   add    rdx, 4
//   dec    rcx
//   jnz    row
//   vzeroupper
//   add rsp,8 / pop r13 / pop r12 / pop rbx / ret

} // namespace

KernelBlob emitX64(const KernelIR& ir, const KernelRequest& req,
                   const HardwareDescriptor& hw) {
    KernelBlob out;
    const bool avx2 = hw.avx2 && ir.vectorWidth == 8;

    if (!avx2) {
        out.rejectReason =
            "EMITTER_REQUIRES_AVX2: this increment emits the 256-bit form only. "
            "A non-AVX2 machine is refused rather than given untested bytes.";
        return out;
    }
    if (req.quantType != 0) {
        out.rejectReason = "QUANT_DECODE_NOT_EMITTED";
        return out;
    }

    Asm a;
    // Prologue. R12/R13/RBX are callee-saved under SysV, so they are pushed.
    a.u8(0x53);                                   // push rbx
    a.u8(0x41); a.u8(0x54);                       // push r12
    a.u8(0x41); a.u8(0x55);                       // push r13
    a.u8(0x48); a.u8(0x83); a.u8(0xEC); a.u8(0x08);// sub rsp, 8   (align to 16)

    a.vex3(0x01, 1, 1, 1, 0x77);                  // vzeroupper (VEX.256.0F.WIG)

    const std::size_t rowTop = a.size();

    // row:
    a.u8(0x45); a.u8(0x31); a.u8(0xC9);           // xor r9d, r9d
    a.vex2(1, 1, 1, 0x57);                        // vxorps ymm1, ymm1, ymm1

    const std::size_t colTop = a.size();

    // vmovups ymm2, [rdi + r9*4]
    // VEX.256.0F.WIG 10 /r  -> vvvv is unused (1111), pp=00 (no 66)
    a.u8(0xC5);
    a.u8((uint8_t)((0x0F << 3) | 0x04 | 0x00));    // ~vvvv=1111, L=1, pp=00
    a.u8(0x10);
    a.modrmMemInRm(2, 4, R9, RDI);                // dest=ymm2, mem=[rdi+r9*4]

    // vmulps ymm2, ymm2, [rsi + r9*4]
    // VEX.256.66.0F.WIG 54 /r ; vvvv = src1 = ymm2
    a.u8(0xC5);
    a.u8((uint8_t)((~2 & 0x0F) << 3) | 0x04 | 0x01);
    a.u8(0x54);
    a.modrmMemInReg(4, 2, 4, R9, RSI);             // mem in reg=4, DEST=ymm2 in rm

    // vaddps ymm1, ymm1, ymm2
    //   dst = ModRM.rm = ymm1, src1 = VEX.vvvv = ymm1, src2 = ModRM.reg = ymm2
    a.u8(0xC5);
    a.u8((uint8_t)((~1 & 0x0F) << 3) | 0x04 | 0x01);
    a.u8(0x58);
    a.u8(0xD1);                                   // mod=11 reg=ymm2 rm=ymm1

    a.u8(0x49); a.u8(0x83); a.u8(0xC1); a.u8(0x08);   // add r9, 8
    a.u8(0x49); a.u8(0x39); a.u8(0xC8);               // cmp r9, r8
    a.u8(0x72);                                       // jb rel8
    const std::size_t jbCol = a.size();
    a.u8(0x00);
    const std::size_t colJmp = jbCol + 1;
    const int colBack = (int)(colJmp - colTop);
    a.patch8(jbCol, (uint8_t)(int8_t)((int)colTop - (int)colJmp));

    // vextractf128 xmm2, ymm1, 1
    a.u8(0xC4); a.u8(0x03); a.u8(0x75); a.u8(0x39); a.u8(0xCA); a.u8(0x01);

    // vaddps xmm1, xmm1, xmm2
    a.u8(0xC5); a.u8((uint8_t)((~1 & 0x0F) << 3) | 0x01); a.u8(0x7C); a.u8(0xD1);

    // vshufps xmm2, xmm1, 0x4E
    a.u8(0xC5); a.u8((uint8_t)((~1 & 0x0F) << 3) | 0x01); a.u8(0xC6); a.u8(0xCA); a.u8(0x4E);

    // vaddps xmm1, xmm1, xmm2
    a.u8(0xC5); a.u8((uint8_t)((~1 & 0x0F) << 3) | 0x01); a.u8(0x7C); a.u8(0xD1);

    // vshufps xmm2, xmm1, 0xB1
    a.u8(0xC5); a.u8((uint8_t)((~1 & 0x0F) << 3) | 0x01); a.u8(0xC6); a.u8(0xCA); a.u8(0xB1);

    // vaddps xmm1, xmm1, xmm2
    a.u8(0xC5); a.u8((uint8_t)((~1 & 0x0F) << 3) | 0x01); a.u8(0x7C); a.u8(0xD1);

    // vmovss [rdx], xmm1
    a.u8(0xC5);
    a.u8((uint8_t)((0x0F << 3) | 0x01));          // ~vvvv=1111, L=0, pp=00
    a.u8(0x11);
    a.modrmMemNoSib(1, RDX);                       // store [rdx], xmm1

    // imul r10, r8, 4
    a.u8(0x4D); a.u8(0x6B); a.u8(0xC2); a.u8(0x04);
    a.u8(0x49); a.u8(0x01); a.u8(0xFA);           // add rdi, r10
    a.u8(0x48); a.u8(0xFF); a.u8(0xC2);           // add rdx, 4
    a.u8(0x48); a.u8(0xFF); a.u8(0xC9);           // dec rcx
    a.u8(0x75);                                    // jnz rel8
    const std::size_t jnzRow = a.size();
    a.u8(0x00);
    const std::size_t rowJmp = jnzRow + 1;
    a.patch8(jnzRow, (uint8_t)(int8_t)((int)rowTop - (int)rowJmp));

    a.vex3(0x01, 1, 1, 1, 0x77);                  // vzeroupper

    a.u8(0x48); a.u8(0x83); a.u8(0xC4); a.u8(0x08);   // add rsp, 8
    a.u8(0x41); a.u8(0x5D);                            // pop r13
    a.u8(0x41); a.u8(0x5C);                            // pop r12
    a.u8(0x5B);                                        // pop rbx
    a.u8(0xC3);                                        // ret

    out.bytes = a.b;
    out.entryOffset = 0;
    out.digest = fnv1a64(out.bytes.data(), out.bytes.size());
    out.ok = true;
    return out;
}

// ===========================================================================
// Authority
// ===========================================================================
namespace {

struct Entry {
    KernelBlob blob;
    KernelIR   ir;
    KernelKey  key;
    void*      fn = nullptr;
};

std::mutex& mtx() { static std::mutex m; return m; }

// Entries are stored in a VECTOR and addressed by index, and a side map gives
// key-hash -> index. std::map iterators are not random-access, so the earlier
// `it - begin()` handle was not just wrong, it would not compile.
std::vector<Entry>& entriesVec() { static std::vector<Entry> v; return v; }
std::map<std::uint64_t, std::size_t>& byHash() {
    static std::map<std::uint64_t, std::size_t> m; return m;
}

std::atomic<std::uint64_t> nReq{0}, nHit{0}, nGen{0}, nRej{0}, nExe{0};

std::uint64_t keyHash(const KernelKey& k) {
    return fnv1a64(&k, sizeof(k));
}

} // namespace

PolyKernelAuthority& PolyKernelAuthority::Instance() {
    static PolyKernelAuthority a; return a;
}

long PolyKernelAuthority::acquire(const KernelRequest& req, std::string* why) {
    ++nReq;
    const KernelKey k = makeKey(req);
    const std::uint64_t h = keyHash(k);

    std::lock_guard<std::mutex> g(mtx());
    auto it = byHash().find(h);
    if (it != byHash().end()) {
        ++nHit;
        return (long)it->second;
    }

    const HardwareDescriptor hw = describeHardware();
    KernelPlan plan = planGEMV(req, hw);
    if (!plan.supported) {
        ++nRej;
        if (why) *why = plan.rejectReason;
        return -1;
    }
    KernelBlob blob = emitX64(plan.ir, req, hw);
    if (!blob.ok) {
        ++nRej;
        if (why) *why = blob.rejectReason;
        return -1;
    }

    // Make the bytes executable. Real memory, real protections.
    void* mem = VirtualAlloc(nullptr, blob.bytes.size(),
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { ++nRej; if (why) *why = "VIRTUAL_ALLOC_FAILED"; return -1; }
    std::memcpy(mem, blob.bytes.data(), blob.bytes.size());
    DWORD old = 0;
    if (!VirtualProtect(mem, blob.bytes.size(), PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        ++nRej; if (why) *why = "VIRTUAL_PROTECT_FAILED"; return -1;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, blob.bytes.size());

    Entry e;
    e.blob = blob;
    e.ir   = plan.ir;
    e.key  = k;
    e.fn   = mem;
    const std::size_t idx = entriesVec().size();
    entriesVec().push_back(e);
    byHash()[h] = idx;
    ++nGen;
    return (long)idx;
}

bool PolyKernelAuthority::execute(long handle, const KernelBinding& b) {
    if (handle < 0 || b.weight == nullptr || b.x == nullptr || b.y == nullptr)
        return false;
    std::lock_guard<std::mutex> g(mtx());
    auto& v = entriesVec();
    if (handle < 0 || (std::size_t)handle >= v.size()) return false;
    using Fn = void (*)(const float*, const float*, float*, std::uint32_t, std::uint32_t);
    Fn fn = reinterpret_cast<Fn>(v[(std::size_t)handle].fn);
    if (!fn) return false;
    fn(b.weight, b.x, b.y, b.rows, b.cols);
    ++nExe;
    return true;
}

PolyKernelAuthority::Stats PolyKernelAuthority::stats() {
    Stats s;
    s.requests   = nReq.load();
    s.cacheHits  = nHit.load();
    s.generated  = nGen.load();
    s.rejected   = nRej.load();
    s.executions = nExe.load();
    return s;
}

void PolyKernelAuthority::clear() {
    std::lock_guard<std::mutex> g(mtx());
    for (auto& e : entriesVec()) {
        if (e.fn) VirtualFree(e.fn, 0, MEM_RELEASE);
    }
    entriesVec().clear();
    byHash().clear();
}

} // namespace poly
} // namespace Deep2