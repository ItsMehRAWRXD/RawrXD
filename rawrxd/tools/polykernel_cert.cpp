// polykernel_cert.cpp — RAWRXD_POLYKERNEL_001 / RAWRXD_REVERSE_001
//
// A gate that CAN FAIL. Every check is computed, none is asserted.
//
// The checks are deliberately adversarial:
//   C1  an unknown identity must NOT resolve
//   C2  a real identity resolves to the provenance the loader bound
//   C3  requiring DUAL GPU on a machine with no published device must FAIL CLOSED
//   C4  two different forms of one identity produce two different source digests
//       (semantics stable, source form mutable)
//   C5  the same form regenerates BYTE-IDENTICALLY (generation is deterministic;
//       a non-deterministic generator would make digests meaningless)
//   C6  the generated source COMPILES with a real compiler and its entry point
//       runs, producing finite output on real quantized bytes
//   C7  the generated kernel agrees with the PRODUCTION QuantKernelRegistry
//       kernel on real inputs
//   C8  a form bound to an older heartbeat generation reports STALE
//   C9  NanoAddress carries no pointer member (static check on the type)
//   C10 FALSIFICATION: corrupting the generated source must make the compile
//       step FAIL. If a deliberately broken source still compiles, the compile
//       step is not actually gating anything.
//   C11 FALSIFICATION: forcing a wrong dequant into the generator must make the
//       parity check FAIL. If a numerically wrong kernel still passes, parity is
//       not actually comparing.
//
// C11 is the one that matters most: a parity check that cannot disagree with
// the thing it measures is not a check.

#include "ReverseLayer.hpp"
#include "PolyKernelGenerator.hpp"
#include "QuantKernelRegistry.hpp"
#include "LoomPromotion.hpp"
#include "GGUFLoader.hpp"
#include "ReverseIntegration.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace Deep2;

namespace {

int g_pass = 0, g_fail = 0;
void check(bool ok, const char* name, const char* detail = "") {
    if (ok) { ++g_pass; std::printf("CHECK PASS  %s\n", name); }
    else    { ++g_fail; std::printf("CHECK FAIL  %s  %s\n", name, detail); }
    std::fflush(stdout);
}

void kv(const char* k, const std::string& v) { std::printf("%s=%s\n", k, v.c_str()); }
void kv(const char* k, uint64_t v)           { std::printf("%s=%llu\n", k, (unsigned long long)v); }
void kv(const char* k, double v)             { std::printf("%s=%.9g\n", k, v); }
void kv(const char* k, bool v)               { std::printf("%s=%d\n", k, v ? 1 : 0); }

} // namespace

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    std::printf("RAWRXD_POLYKERNEL_CERT\n");
    std::printf("========================\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();

    // ---------------------------------------------------------------------
    // Real hardware truth. No device is published by this probe, so the
    // heartbeat reports zero devices and every GPU form is unreachable.
    // That is the fail-closed direction and it is asserted, not assumed.
    // ---------------------------------------------------------------------
    Heartbeat hb = publishHeartbeat();
    std::printf("HEARTBEAT CPU avx2=%d avx512f=%d fma=%d devices=%zu generation=%llu\n",
                hb.cpu.avx2 ? 1 : 0, hb.cpu.avx512f ? 1 : 0, hb.cpu.fma ? 1 : 0,
                hb.devices.size(), (unsigned long long)hb.generation);

    // ---------------------------------------------------------------------
    // C1: unknown identity must not resolve.
    // ---------------------------------------------------------------------
    KernelIdentity unknown;
    unknown.operation = Operation::MatrixVector;
    unknown.contract.contractName = "Deep2_Q4_K_GEMV";
    unknown.representation.kind = RepresentationKind::Quantized;
    unknown.representation.quantType = 12;
    unknown.weight = TensorIdentity{0xDEADBEEF, 0xFEEDFACE, 999, 7, 1};

    auto miss = ReverseLayer::resolve(unknown, ExecutionConstraints{}, hb);
    check(!miss.has_value(), "C1_UNKNOWN_IDENTITY_REFUSED",
          "resolve() returned a NanoAddress for an identity that was never bound");

    // ---------------------------------------------------------------------
    // C2: a real binding resolves to the provenance that was registered.
    // Values below are the ones the binder site would have copied out of a
    // GGUFTensor: shardId, fileOffset, byteLength, quantType, rows, cols.
    // ---------------------------------------------------------------------
    TensorIdentity qproj;
    qproj.model = 0xA5A5A5A5ull;
    qproj.tensor = 0x1234;
    qproj.layer = 17;
    qproj.role = 1;      // Q projection
    qproj.variant = 0;

    BackingRef ref;
    ref.source     = BackingSource::GGUF_MMAP;
    ref.shardId    = 3;
    ref.fileOffset = 0x0012ABCDull;
    ref.byteLength = 1024ull * 1024ull;
    ref.quantType  = 12;                       // Q4_K
    ref.rows       = 4096;
    ref.cols       = 4096;
    ref.tensorName = "blk.17.attn_q.weight";
    BackingDirectory::Instance().registerBinding(qproj, ref);

    kv("DIRECTORY_BINDINGS", (uint64_t)BackingDirectory::Instance().size());

    KernelIdentity intent;
    intent.operation = Operation::MatrixVector;
    intent.contract.contractName = "Deep2_Q4_K_GEMV";
    intent.contract.contractHash = fnv1a64("Deep2_Q4_K_GEMV", 14);
    intent.representation.kind = RepresentationKind::Quantized;
    intent.representation.quantType = 12;
    intent.weight = qproj;

    auto na = ReverseLayer::resolve(intent, ExecutionConstraints{}, hb);
    check(na.has_value(), "C2_BOUND_IDENTITY_RESOLVES",
          "resolve() refused a binding that the directory holds");

    if (na) {
        const BackingRef& b = na->backing;
        const bool same =
            b.shardId == ref.shardId &&
            b.fileOffset == ref.fileOffset &&
            b.byteLength == ref.byteLength &&
            b.quantType == ref.quantType &&
            b.rows == ref.rows &&
            b.cols == ref.cols &&
            b.tensorName == ref.tensorName;
        check(same, "C2B_BACKING_MATCHES_BINDER_PROVENANCE",
              "resolved provenance differs from what was registered");
        kv("NANOADDR_SHARD", (uint64_t)b.shardId);
        kv("NANOADDR_FILE_OFFSET", b.fileOffset);
        kv("NANOADDR_BYTE_LENGTH", b.byteLength);
        kv("NANOADDR_QUANT_TYPE", (uint64_t)b.quantType);
        const BackendForm chosen = ReverseLayer::selectForm(intent, b, hb,
                                                             ExecutionConstraints{});
        kv("NANOADDR_SELECTED_FORM", backendFormName(chosen));
        kv("NANOADDR_BYTES_ADDRESSABLE_NOW", b.immediatelyAddressable());
        kv("NANOADDR_FORM_GENERATION", na->formGeneration);
    }

    // ---------------------------------------------------------------------
    // C3: requireDualGPU with no published device must fail CLOSED.
    // ---------------------------------------------------------------------
    ExecutionConstraints needDual;
    needDual.requireDualGPU = true;
    auto dual = ReverseLayer::resolve(intent, needDual, hb);
    check(!dual.has_value(), "C3_DUAL_GPU_REQUIRED_REFUSED_WITHOUT_DEVICE",
          "a dual-GPU constraint resolved on a machine reporting zero devices");

    // A second device being published must CHANGE the answer, which proves the
    // refusal above was caused by reality and not by a hard-coded refusal.
    DeviceBeacon d0;
    d0.deviceId = 0; d0.name = "PROBE-DEVICE-0";
    d0.totalBytes = 8ull << 30; d0.freeBytes = 4ull << 30;
    d0.peerReachable = false;
    publishDevice(d0);
    Heartbeat hb1 = publishHeartbeat();
    std::printf("HEARTBEAT_AFTER_PUBLISH devices=%zu generation=%llu\n",
                hb1.devices.size(), (unsigned long long)hb1.generation);
    auto dual1 = ReverseLayer::resolve(intent, needDual, hb1);
    check(!dual1.has_value(), "C3B_SINGLE_DEVICE_STILL_REFUSES_DUAL",
          "one device satisfied a requireDualGPU constraint");

    DeviceBeacon d1 = d0;
    d1.deviceId = 1; d1.name = "PROBE-DEVICE-1"; d1.peerReachable = true;
    publishDevice(d1);
    Heartbeat hb2 = publishHeartbeat();
    std::printf("HEARTBEAT_AFTER_SECOND devices=%zu generation=%llu\n",
                hb2.devices.size(), (unsigned long long)hb2.generation);
    auto dual2 = ReverseLayer::resolve(intent, needDual, hb2);
    check(dual2.has_value(), "C3C_DUAL_DEVICE_SATISFIES_DUAL",
          "two published devices did not satisfy requireDualGPU");

    // Restore reality: these were probe-registered, not engine-registered.
    withdrawAllDevices();
    Heartbeat hbClean = publishHeartbeat();

    // ---------------------------------------------------------------------
    // C8: a form bound to an older generation is STALE.
    // ---------------------------------------------------------------------
    check(!formIsCurrent(intent, hb2, 1),
          "C8_FORM_FROM_OLDER_GENERATION_IS_STALE",
          "a form bound to generation 1 reported current at generation >1");
    check(formIsCurrent(intent, hb2, hb2.generation),
          "C8B_FORM_AT_CURRENT_GENERATION_IS_CURRENT",
          "a form bound to the live generation reported stale");

    // ---------------------------------------------------------------------
    // C4/C5: source generation. Identity fixed, form varied.
    // ---------------------------------------------------------------------
    PrimitiveGraph graph = ReverseLayer::decompose(intent);
    std::printf("GRAPH nodes=%zu entry=%u exit=%u q0_blockBytes=%u q0_blockElements=%u\n",
                graph.nodes.size(), graph.entry, graph.exit,
                graph.nodes[0].blockBytes, graph.nodes[0].blockElements);
    check(graph.nodes.size() == 5 &&
          graph.nodes[0].op == PrimitiveOp::LOAD_BLOCK &&
          graph.nodes[1].op == PrimitiveOp::DEQUANT &&
          graph.nodes[2].op == PrimitiveOp::DOT &&
          graph.nodes[3].op == PrimitiveOp::ACCUMULATE &&
          graph.nodes[4].op == PrimitiveOp::STORE,
          "C4B_MATRIX_VECTOR_GRAPH_SHAPE",
          "decompose() did not produce LOAD_BLOCK/DEQUANT/DOT/ACCUMULATE/STORE");

    GeneratedSource gScalar = generatePolyKernelSource(intent, graph, BackendForm::CPU_SCALAR);
    GeneratedSource gAvx2   = generatePolyKernelSource(intent, graph, BackendForm::CPU_AVX2);
    GeneratedSource gAvx512 = generatePolyKernelSource(intent, graph, BackendForm::CPU_AVX512);

    check(gScalar.produced, "C4_SOURCE_GENERATED_SCALAR", gScalar.rejectReason.c_str());
    check(gAvx2.produced,   "C4_SOURCE_GENERATED_AVX2",   gAvx2.rejectReason.c_str());
    check(gAvx512.produced, "C4_SOURCE_GENERATED_AVX512", gAvx512.rejectReason.c_str());

    kv("SRC_SCALAR_BYTES", (uint64_t)gScalar.bytes);
    kv("SRC_SCALAR_DIGEST", gScalar.digest);
    kv("SRC_AVX2_DIGEST", gAvx2.digest);
    kv("SRC_AVX512_DIGEST", gAvx512.digest);

    check(gScalar.digest != gAvx2.digest && gScalar.digest != gAvx512.digest &&
          gAvx2.digest != gAvx512.digest,
          "C4C_FORMS_PRODUCE_DISTINCT_SOURCE",
          "two forms produced the same source digest, so 'form' is not a real axis");

    GeneratedSource gScalarAgain = generatePolyKernelSource(intent, graph, BackendForm::CPU_SCALAR);
    check(gScalarAgain.digest == gScalar.digest && gScalarAgain.bytes == gScalar.bytes,
          "C5_GENERATION_IS_DETERMINISTIC",
          "regenerating the same identity+form produced different bytes");

    // A GPU form must REFUSE to emit host text under a GPU name.
    GeneratedSource gVk = generatePolyKernelSource(intent, graph, BackendForm::VULKAN_SINGLE);
    check(!gVk.produced && !gVk.rejectReason.empty(),
          "C5B_GPU_FORM_REFUSES_HOST_SOURCE",
          "a Vulkan form emitted text, which would claim a shader exists when none was generated");
    std::printf("GPU_FORM_REJECT_REASON=%s\n", gVk.rejectReason.c_str());

    // ---------------------------------------------------------------------
    // C6/C7: real compile, real execution, real parity vs the PRODUCTION kernel.
    // ---------------------------------------------------------------------
    const BackendForm cpuForm = hb.cpu.avx512f ? BackendForm::CPU_AVX512
                           : hb.cpu.avx2    ? BackendForm::CPU_AVX2
                                             : BackendForm::CPU_SCALAR;
    std::printf("CERTIFYING form=%s quantType=%d\n",
                backendFormName(cpuForm), intent.representation.quantType);

    PolyKernelReceipt R = certifyPolyKernel(intent, graph, cpuForm,
                                            hbClean.generation,
                                            /*rows=*/64, /*cols=*/256,
                                            /*trials=*/8, /*tol=*/1e-3);

    kv("RECEIPT_SOURCE_GENERATED", R.sourceGenerated);
    kv("RECEIPT_SOURCE_DIGEST", R.sourceDigest);
    kv("RECEIPT_SOURCE_BYTES", (uint64_t)R.sourceBytes);
    kv("RECEIPT_BEACON_GENERATION", R.beaconGeneration);
    kv("RECEIPT_HARDWARE_FINGERPRINT", R.hardwareFingerprint);
    kv("RECEIPT_COMPILE_EXIT", (uint64_t)(int64_t)R.compileExit);
    kv("RECEIPT_BINARY_BYTES", (uint64_t)R.binaryBytes);
    kv("RECEIPT_BINARY_DIGEST", R.binaryDigest);
    kv("RECEIPT_EXECUTION_COUNT", R.executionCount);
    kv("RECEIPT_KERNEL_ENTERED", R.kernelEntered);
    kv("RECEIPT_FINITE_OUTPUT", R.finiteOutput);
    kv("RECEIPT_MAX_ABS_DIFF", R.maxAbsDiff);
    kv("RECEIPT_RMS_DIFF", R.rmsDiff);
    kv("RECEIPT_COMPARISON_COUNT", R.comparisonCount);
    kv("RECEIPT_NONFINITE_REFERENCE", R.nonFiniteRef);
    std::printf("RECEIPT_STAGE=%s\n", R.stage.c_str());
    std::printf("RECEIPT_DETAIL=%s\n", R.detail.c_str());

    check(R.sourceGenerated, "C6_SOURCE_GENERATED", R.detail.c_str());
    check(R.compileExit == 0, "C6B_COMPILED_BY_REAL_COMPILER",
          ("compiler exit " + std::to_string(R.compileExit) + " " + R.detail).c_str());
    check(R.kernelEntered, "C6C_GENERATED_KERNEL_ENTERED", R.stage.c_str());
    check(R.executionCount > 0, "C6D_KERNEL_EXECUTED", R.stage.c_str());
    check(R.finiteOutput, "C6E_OUTPUT_FINITE", R.stage.c_str());
    check(R.nonFiniteRef == 0, "C6F_REFERENCE_WAS_FINITE",
          "the production reference produced non-finite values, so parity is meaningless");
    check(R.comparisonCount > 0, "C6G_COMPARISONS_PERFORMED", R.stage.c_str());

    const bool parityOk = R.maxAbsDiff <= 1e-3 && R.comparisonCount > 0;
    check(parityOk, "C7_PARITY_WITH_PRODUCTION_KERNEL",
          ("maxAbsDiff=" + std::to_string(R.maxAbsDiff)).c_str());

    // Vector bodies are emitted for the AVX forms. Whether they were actually
    // COMPILED is settled by BG8-AV, which requires the vector binary digest to
    // differ from the scalar one -- that is the check that distinguishes real
    // vectorisation from intrinsics present in text but compiled out by a
    // missing /arch switch. Asserting their absence here would only restate a
    // limitation that no longer holds.
    check(gAvx512.text.find("_mm512_") != std::string::npos &&
          gAvx2.text.find("_mm256_") != std::string::npos,
          "C7B_VECTOR_BODIES_EMITTED_FOR_VECTOR_FORMS",
          "the AVX forms did not contain the intrinsics they should emit");
    check(gScalar.text.find("_mm256_") == std::string::npos &&
          gScalar.text.find("_mm512_") == std::string::npos,
          "C7C_SCALAR_FORM_STAYS_SCALAR",
          "the scalar form emitted vector intrinsics");

    // ---------------------------------------------------------------------
    // C10: a type with no independent dequantizer must be REFUSED, not faked.
    // ---------------------------------------------------------------------
    KernelIdentity unsupported = intent;
    unsupported.representation.quantType = 13;   // Q5_K: no emitter here
    GeneratedSource gu = generatePolyKernelSource(unsupported, graph,
                                                 BackendForm::CPU_SCALAR);
    check(!gu.produced && !gu.rejectReason.empty(),
          "C10_UNSUPPORTED_QUANT_REFUSED_NOT_FAKED",
          "a type with no independent dequantizer still produced source");
    std::printf("UNSUPPORTED_QUANT_REJECT_REASON=%s\n", gu.rejectReason.c_str());

    // A source that does not compile must be reported as a compile failure.
    {
        std::string broken = gScalar.text;
        const size_t at = broken.find("extern \"C\"");
        if (at != std::string::npos) broken.insert(at, "@@@ not valid c++ @@@ ");
        PolyKernelReceipt RB = certifySourceText(intent, graph, broken,
                                                 hbClean.generation,
                                                 64, 256, 1, 1e-3);
        kv("FALSIFY_COMPILE_EXIT", (uint64_t)(int64_t)RB.compileExit);
        kv("FALSIFY_KERNEL_ENTERED", RB.kernelEntered);
        std::printf("FALSIFY_COMPILE_DETAIL=%s\n", RB.detail.c_str());
        check(RB.compileExit != 0,
              "C10B_BROKEN_SOURCE_FAILS_TO_COMPILE",
              "text that is not valid C++ passed the compile stage, so the "
              "compile stage is not gating anything");
    }

    // ---------------------------------------------------------------------
    // C11 FALSIFICATION, and it is the one that matters most:
    // take the EXACT source that just passed parity, corrupt its arithmetic,
    // push it through the IDENTICAL pipeline, and require the gate to FAIL.
    //
    // If a numerically wrong kernel also produces PASS here, then the PASS in
    // C6/C7 is not evidence of anything, and the instrument — not the system
    // under test — is the defect. This is the same class as the retracted
    // false-PASS receipts in this repo, so it is checked rather than assumed.
    // ---------------------------------------------------------------------
    {
        // Q4_K dequant low-nibble term: ... - m1;  Flip the subtraction.
        // Small, local, definitely wrong, and it still compiles -- so the
        // compile stage cannot be what catches it. Only parity can.
        // The needle is the single token `- m1;`, which appears exactly once
        // (the high-nibble line uses m2).
        const std::string good = gScalar.text;
        const std::string needle = "- m1;";
        const size_t at = good.find(needle);
        if (at == std::string::npos) {
            check(false, "C11_FALSIFIER_FOUND_THE_ARITHMETIC_TO_CORRUPT",
                  "the generated text no longer contains '- m1;', so the "
                  "falsifier cannot be built");
        } else {
            std::string sabotaged = good;
            sabotaged.replace(at, needle.size(), "+ m1;");
            kv("SABOTAGE_SOURCE_DIGEST", fnv1a64(sabotaged.data(), sabotaged.size()));
            kv("SABOTAGE_DIFFERS_FROM_GOOD", sabotaged != good);

            PolyKernelReceipt RF = certifySourceText(intent, graph, sabotaged,
                                                     hbClean.generation,
                                                     64, 256, 8, 1e-3);
            kv("FALSIFY2_COMPILE_EXIT", (uint64_t)(int64_t)RF.compileExit);
            kv("FALSIFY2_KERNEL_ENTERED", RF.kernelEntered);
            kv("FALSIFY2_FINITE_OUTPUT", RF.finiteOutput);
            kv("FALSIFY2_MAX_ABS_DIFF", RF.maxAbsDiff);
            kv("FALSIFY2_COMPARISON_COUNT", RF.comparisonCount);

            check(RF.compileExit == 0,
                  "C11A_SABOTAGED_SOURCE_STILL_COMPILES",
                  "the sabotaged source failed to compile, which means this probe "
                  "proves nothing about parity (it would have failed for the "
                  "compile reason, not the numeric one)");
            check(RF.kernelEntered && RF.finiteOutput,
                  "C11B_SABOTAGED_KERNEL_RAN_AND_WAS_FINITE",
                  "the sabotaged kernel did not run, so parity had nothing to compare");
            check(RF.maxAbsDiff > 1e-3,
                  "C11C_PARITY_DETECTS_WRONG_ARITHMETIC",
                  "a kernel with a flipped sign in its dequant still passed the "
                  "parity bound — the parity measurement cannot disagree with the "
                  "thing it measures, so it is not a measurement");
            check(!RF.passed(),
                  "C11D_SABOTAGED_KERNEL_RECEIPT_IS_NOT_PASS",
                  "certifySourceText returned passed()==true for a wrong kernel");
        }
    }

    // ---------------------------------------------------------------------
    // C12: EVERY emitted quant type must survive the same differential.
    // Q4_K passing does not license Q6_K / Q4_0 / Q8_0 -- those emitters are
    // separate transcriptions of separate layouts, and shipping an unverified
    // one is exactly how a generator ends up with kernels nobody has ever run.
    // A type that does not reach bit-exactness is reported as UNVERIFIED here
    // rather than being quietly counted as covered.
    // ---------------------------------------------------------------------
    std::printf("---- C12 per-type differential ----\n");
    {
        const int kTypes[] = {2, 8, 12, 14};   // Q4_0, Q8_0, Q4_K, Q6_K
        const char* kNames[] = {"Q4_0", "Q8_0", "Q4_K", "Q6_K"};
        int verified = 0, refused = 0, wrong = 0;
        for (int i = 0; i < 4; ++i) {
            KernelIdentity ti = intent;
            ti.representation.quantType = static_cast<uint32_t>(kTypes[i]);
            PrimitiveGraph tg = ReverseLayer::decompose(ti);
            GeneratedSource tgs = generatePolyKernelSource(ti, tg,
                                                           BackendForm::CPU_SCALAR);
            if (!tgs.produced) {
                // A removed emitter must refuse WITH A REASON. Silent absence
                // would be indistinguishable from a type that was forgotten.
                std::printf("TYPE=%-5s GENERATED=0 REFUSED_REASON=%s\n",
                            kNames[i], tgs.rejectReason.c_str());
                check(!tgs.rejectReason.empty(),
                      "C12R_REFUSAL_CARRIES_A_REASON",
                      "a type was refused with no reason given");
                ++refused;
                continue;
            }
            const size_t blkE = tg.nodes[0].blockElements;
            PolyKernelReceipt rt = certifySourceText(ti, tg, tgs.text,
                                                    hbClean.generation,
                                                    /*rows=*/32,
                                                    /*cols=*/static_cast<uint32_t>(blkE),
                                                    /*trials=*/4, 0.0);
            const bool exact = (rt.compileExit == 0 && rt.kernelEntered &&
                                rt.finiteOutput && rt.nonFiniteRef == 0 &&
                                rt.maxAbsDiff == 0.0 && rt.comparisonCount > 0);
            std::printf("TYPE=%-5s GENERATED=1 BYTES=%u SRC_DIGEST=%llu "
                        "COMPILE_EXIT=%d ENTERED=%d FINITE=%d NONFINITE_REF=%llu "
                        "MAX_ABS_DIFF=%.9g CMP=%llu EXACT=%d STAGE=%s\n",
                        kNames[i], tgs.bytes,
                        (unsigned long long)tgs.digest, rt.compileExit,
                        rt.kernelEntered ? 1 : 0, rt.finiteOutput ? 1 : 0,
                        (unsigned long long)rt.nonFiniteRef, rt.maxAbsDiff,
                        (unsigned long long)rt.comparisonCount,
                        exact ? 1 : 0, rt.stage.c_str());
            if (exact) ++verified; else ++wrong;
        }
        kv("C12_TYPES_EMITTED_AND_BIT_EXACT", (uint64_t)verified);
        kv("C12_TYPES_REFUSED_WITH_REASON", (uint64_t)refused);
        kv("C12_TYPES_EMITTED_BUT_WRONG", (uint64_t)wrong);

        // The strict form of this gate. An earlier version only required
        // verified >= 1, which reported 48/48 PASS while three emitted kernels
        // were numerically wrong -- the aggregate verdict hid them. Now every
        // kernel the generator is capable of emitting must be bit-exact.
        check(verified >= 1,
              "C12_AT_LEAST_ONE_TYPE_BIT_EXACT",
              "no emitted quant type reached bit-exactness with production");
        check(wrong == 0,
              "C12_NO_EMITTED_TYPE_IS_NUMERICALLY_WRONG",
              "the generator emitted a kernel that disagrees with production; "
              "an emitter that exists but is wrong reads as coverage");
        check(refused + verified == 4,
              "C12_EVERY_TYPE_ACCOUNTED_FOR",
              "a quant type was neither emitted-and-verified nor refused-with-a-reason");
    }

    // ---------------------------------------------------------------------
    // C13: the promotion gate. A residual that was never measured must not be
    // able to widen anything, and Unknown ownership must not admit promotion.
    // ---------------------------------------------------------------------
    std::printf("---- C13 promotion gate ----\n");
    {
        using namespace rawrxd::deep2::loom;

        MeasuredResidual measured;
        measured.maxAbsError = 0.0;
        measured.rmsError    = 0.0;
        measured.relativeL2  = 0.0;
        measured.elementCount = 512;
        measured.finite      = true;

        MeasuredResidual unmeasured;   // every field default: nothing observed

        MeasuredResidual worse;
        worse.maxAbsError = 5.35;
        worse.rmsError    = 2.0;
        worse.relativeL2  = 5.35;
        worse.elementCount = 512;
        worse.finite      = true;

        check(measured.measured(), "C13A_MEASURED_RESIDUAL_RECOGNISED",
              "a residual with 512 finite comparisons reported itself unmeasured");
        check(!unmeasured.measured(), "C13B_UNMEASURED_RESIDUAL_RECOGNISED",
              "an empty residual claimed to be measured -- promotion would accept it");
        check(!mayWiden(measured, unmeasured),
              "C13C_UNMEASURED_CANNOT_WIDEN",
              "mayWiden accepted a candidate that was never executed");
        check(!mayWiden(measured, worse),
              "C13D_WORSE_RESIDUAL_CANNOT_WIDEN",
              "mayWiden accepted a candidate with higher relative L2");
        mayWiden(measured, measured);   // equal is not strictly better

        MeasuredResidual incumbent;
        incumbent.relativeL2 = 9.0; incumbent.elementCount = 10; incumbent.finite = true;
        check(mayWiden(incumbent, measured),
              "C13E_BETTER_RESIDUAL_WIDENS",
              "mayWiden refused a strictly better measured candidate");

        check(!ownershipAdmitsPromotion(Ownership::Unknown),
              "C13F_UNKNOWN_OWNERSHIP_FORBIDS_PROMOTION",
              "Unknown ownership was admissible for promotion");
        check(ownershipAdmitsPromotion(Ownership::Owned) &&
              ownershipAdmitsPromotion(Ownership::Bypass) &&
              ownershipAdmitsPromotion(Ownership::Delegated) &&
              ownershipAdmitsPromotion(Ownership::Conditional),
              "C13G_KNOWN_OWNERSHIPS_ADMIT_PROMOTION",
              "a known ownership was refused");

        // Spaceless resource law.
        ResourceCost withReconstruction;
        withReconstruction.reconstructedWeightBytes = 4096;
        check(!isSpaceless(withReconstruction),
              "C13H_RECONSTRUCTED_WEIGHT_BREAKS_SPACELESS",
              "a candidate that reconstructed W was accepted as spaceless");
        ResourceCost clean;
        check(isSpaceless(clean),
              "C13I_ZERO_RECONSTRUCTION_IS_SPACELESS",
              "a candidate with no reconstruction was refused");

        // Executable identity must move when the compiled artifact moves,
        // even though the genome did not.
        ExecutableIdentity e1;
        e1.genomeHash          = 0xAAAAull;
        e1.materializerHash    = 0xBBBBull;
        e1.compilerId          = "msvc-14.44";
        e1.compilerFlags       = "/O2";
        e1.targetIsa           = "x86-64";
        e1.generatedSourceHash = 0xCCCCull;
        e1.binaryHash          = 0xDDDDull;
        ExecutableIdentity e2 = e1;
        e2.compilerFlags = "/O2 /arch:AVX512";
        check(e1.hash() != e2.hash(),
              "C13J_EXECUTABLE_HASH_TRACKS_COMPILER_FLAGS",
              "changing only the compiler flags left the executable hash unchanged, "
              "so two different binaries would be treated as one kernel");
        check(e1.genomeHash == e2.genomeHash && e1.hash() != e2.hash(),
              "C13K_GENOME_FINGERPRINT_DISTINCT_FROM_EXECUTABLE_HASH",
              "genome and executable identity collapsed into one another");

        // ---- traffic contract, computed ----
        TrafficContract tc;
        tc.logicalWeightBytes           = 400ull * 1000 * 1000 * 1000;  // 400 GB
        tc.logicalWeightBytesUnbounded  = 1;
        tc.physicalFreshBytesPerToken   = 8ull * 1000 * 1000 * 1000;    // 8 GB
        tc.physicalBudgetBytesPerToken  = 8ull * 1000 * 1000 * 1000;
        tc.sustainedBandwidthBytesPerSec = 1200ull * 1000 * 1000 * 1000; // 1.2 TB/s
        tc.targetTokensPerSecond        = 150;

        std::printf("TRAFFIC logical=%llu fresh_per_token=%llu budget=%llu "
                    "ceiling_tps=%llu target_tps=%u collapse=%llux logical_gt_physical=%d "
                    "within_budget=%d verdict=%d\n",
                    (unsigned long long)tc.logicalWeightBytes,
                    (unsigned long long)tc.physicalFreshBytesPerToken,
                    (unsigned long long)tc.physicalBudgetBytesPerToken,
                    (unsigned long long)tc.bandwidthCeilingTps(),
                    tc.targetTokensPerSecond,
                    (unsigned long long)tc.minTrafficCollapse(),
                    tc.logicalExceedsPhysical() ? 1 : 0,
                    tc.physicalWithinBudget() ? 1 : 0,
                    tc.verdict() ? 1 : 0);

        check(tc.logicalExceedsPhysical(),
              "C13L_LOGICAL_EXCEEDS_PHYSICAL",
              "400 GB logical was not distinguishable from 8 GB realized");
        check(tc.minTrafficCollapse() >= 50ull,
              "C13M_TRAFFIC_COLLAPSE_AT_LEAST_50X",
              "400 GB -> 8 GB is 50x; a smaller ratio was reported");
        check(tc.bandwidthCeilingTps() >= 150ull,
              "C13N_BANDWIDTH_CEILING_MEETS_TARGET",
              "1.2 TB/s over 8 GB/token cannot reach 150 TPS");
        check(tc.verdict(), "C13O_TRAFFIC_CONTRACT_SATISFIED",
              "the stated contract did not evaluate to satisfied");

        // Half the traffic must double the ceiling. If it does not, the
        // contract is not actually the binding constraint it claims to be.
        TrafficContract half = tc;
        half.physicalFreshBytesPerToken = 4ull * 1000 * 1000 * 1000;
        kv("TRAFFIC_HALF_CEILING_TPS", half.bandwidthCeilingTps());
        check(half.bandwidthCeilingTps() >= 300ull,
              "C13P_HALVING_TRAFFIC_DOUBLES_CEILING",
              "4 GB/token did not reach ~300 TPS, so the ceiling is not traffic-bound");

        // And a full re-read must NOT be admissible.
        TrafficContract fullReread = tc;
        fullReread.physicalFreshBytesPerToken = tc.logicalWeightBytes;
        check(!fullReread.verdict(),
              "C13Q_FULL_REREAD_REJECTED_AT_TARGET_TPS",
              "re-reading the entire 400 GB per token was accepted at 150 TPS");
    }

    // ---------------------------------------------------------------------
    // BG8-B: a REAL quantized weight block, read from a REAL GGUF on disk.
    //
    // Everything above uses valid-by-construction tensors, which proves the
    // machinery but not a model weight. This block closes that gap: it opens a
    // real GGUF, takes a real Q4_K block out of a real 2-D weight, and
    // certifies the generated kernel against the production reference on those
    // exact bytes.
    //
    // The rows are taken from ONE real block's first ROWS output channels, so
    // every byte fed to both kernels came out of the model file.
    // ---------------------------------------------------------------------
    std::printf("---- BG8-B real GGUF weight capture ----\n");
    {
        const char* kModels[] = {
            "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
            "G:\\~dev\\rawrxd\\models\\tinyllama.gguf",
            "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf",
        };

        GGUFLoader loader;
        const char* chosen = nullptr;
        for (const char* p : kModels) {
            if (loader.load(p)) { chosen = p; break; }
            std::printf("BG8B_MODEL_UNAVAILABLE=%s\n", p);
        }

        check(chosen != nullptr, "BG8B_REAL_GGUF_LOADED",
              "no real GGUF could be opened, so no real weight was captured");
        kv("BG8B_MODEL_LOADED", chosen ? std::string(chosen) : std::string("NONE"));

        if (chosen) {
            const std::vector<std::string> names = loader.listTensors();
            kv("BG8B_TENSOR_COUNT", (uint64_t)names.size());
            kv("BG8B_LOADER_LOADED", loader.loaded());

            // Find a real 2-D Q4_K weight.
            const GGUFTensor* real = nullptr;
            std::string realName;
            for (const auto& n : names) {
                const GGUFTensor* t = loader.getTensor(n);
                if (!t || !t->data) continue;
                if (t->type != GGMLType::GGML_TYPE_Q4_K) continue;
                if (t->shape.size() < 2) continue;
                const int64_t cols = t->shape[0];
                const int64_t rows = t->shape[1];
                if (cols <= 0 || rows <= 0) continue;
                if (cols % 256 != 0) continue;      // production fast path
                if (t->sizeBytes == 0 || !t->mapped) continue;
                real = t; realName = n;
                break;
            }

            check(real != nullptr, "BG8B_REAL_Q4K_WEIGHT_FOUND",
                  "no mapped 2-D Q4_K tensor with cols%256==0 was present");

            if (real) {
                const uint32_t cols = static_cast<uint32_t>(real->shape[0]);
                const uint32_t totalRows = static_cast<uint32_t>(real->shape[1]);
                const uint32_t rows = 32;   // small on purpose: one real block

                kv("BG8B_TENSOR_NAME", realName);
                kv("BG8B_SHARD_ID", (uint64_t)real->shardId);
                kv("BG8B_FILE_OFFSET", real->fileOffset);
                kv("BG8B_TOTAL_BYTES", (uint64_t)real->sizeBytes);
                kv("BG8B_TENSOR_ROWS", (uint64_t)totalRows);
                kv("BG8B_TENSOR_COLS", (uint64_t)cols);
                kv("BG8B_SLICE_ROWS", (uint64_t)rows);

                const size_t rowBytes =
                    (static_cast<size_t>(cols) / 256) * 144;
                const size_t sliceBytes = rowBytes * rows;
                check(sliceBytes <= real->sizeBytes,
                      "BG8B_SLICE_WITHIN_TENSOR",
                      "the slice is larger than the tensor it claims to come from");

                // The REAL bytes. Copied once so both kernels read the same
                // buffer and the reference cannot be reading something else.
                std::vector<uint8_t> realBytes(
                    reinterpret_cast<const uint8_t*>(real->data),
                    reinterpret_cast<const uint8_t*>(real->data) + sliceBytes);

                kv("BG8B_SLICE_BYTES", (uint64_t)realBytes.size());
                kv("BG8B_SLICE_SHA_LIKE_FNV",
                   fnv1a64(realBytes.data(), realBytes.size()));

                // A REAL activation: deterministic, but not drawn from the same
                // distribution as the weight. The point is that neither side
                // gets an easier input than the other.
                std::vector<float> x(cols);
                std::mt19937 rng(0xB68u);
                std::uniform_real_distribution<float> d(-1.0f, 1.0f);
                for (auto& v : x) v = d(rng);

                PrimitiveGraph bg = ReverseLayer::decompose(intent);
                GeneratedSource bgs = generatePolyKernelSource(intent, bg,
                                                              BackendForm::CPU_SCALAR);
                check(bgs.produced, "BG8B_SOURCE_GENERATED", bgs.rejectReason.c_str());

                if (bgs.produced) {
                    // THE REAL CASE. These bytes came out of the model file via
                    // the mmap the loader owns, and they go through certifyCases
                    // -- the same function the synthetic path uses -- so this is
                    // not a parallel, more forgiving measurement.
                    ExternalCase rc;
                    rc.weightBytes = realBytes.data();
                    rc.x           = x.data();
                    rc.rows        = rows;
                    rc.cols        = cols;
                    rc.label       = realName;
                    const std::vector<ExternalCase> realCases{rc};

                    PolyKernelReceipt rb = certifySourceTextOn(
                        intent, bg, bgs.text, hbClean.generation, realCases, 0.0);

                    kv("BG8B_CASE_COUNT", rb.caseCount);
                    kv("BG8B_CASE_LABEL", rc.label);
                    kv("BG8B_COMPILE_EXIT", (uint64_t)(int64_t)rb.compileExit);
                    kv("BG8B_BINARY_DIGEST", rb.binaryDigest);
                    kv("BG8B_SOURCE_DIGEST", rb.sourceDigest);
                    kv("BG8B_KERNEL_ENTERED", rb.kernelEntered);
                    kv("BG8B_EXECUTION_COUNT", rb.executionCount);
                    kv("BG8B_FINITE_OUTPUT", rb.finiteOutput);
                    kv("BG8B_NONFINITE_REFERENCE", rb.nonFiniteRef);
                    kv("BG8B_COMPARISON_COUNT", rb.comparisonCount);
                    kv("BG8B_MAX_ABS_DIFF", rb.maxAbsDiff);
                    kv("BG8B_RMS_DIFF", rb.rmsDiff);
                    std::printf("BG8B_STAGE=%s\n", rb.stage.c_str());
                    if (!rb.detail.empty())
                        std::printf("BG8B_DETAIL=%s\n", rb.detail.c_str());

                    check(rb.compileExit == 0,
                          "BG8B_REAL_WEIGHT_COMPILED",
                          ("compiler exit " + std::to_string(rb.compileExit)).c_str());
                    check(rb.kernelEntered && rb.executionCount > 0,
                          "BG8B_REAL_WEIGHT_KERNEL_ENTERED",
                          "the generated kernel never ran on the real weight");
                    check(rb.nonFiniteRef == 0,
                          "BG8B_REAL_WEIGHT_REFERENCE_FINITE",
                          "the production reference produced non-finite output on a "
                          "real model weight, so parity cannot be interpreted");
                    check(rb.finiteOutput,
                          "BG8B_REAL_WEIGHT_OUTPUT_FINITE",
                          "the generated kernel produced non-finite output");

                    // The decisive one. The transcription is bit-exact on
                    // synthetic tensors; if it were only right for the
                    // synthetic value range, a real model weight is where that
                    // would finally show.
                    check(rb.maxAbsDiff == 0.0,
                          "BG8B_REAL_WEIGHT_PARITY_BIT_EXACT",
                          ("maxAbsDiff=" + std::to_string(rb.maxAbsDiff) +
                           " on a real model weight").c_str());

                    // Falsify on the REAL bytes too, not only on synthetic ones.
                    // A parity check proven only on synthetic input has not been
                    // shown to work on the input that actually matters.
                    {
                        const std::string needle = "- m1;";
                        const size_t at = bgs.text.find(needle);
                        if (at != std::string::npos) {
                            std::string bad = bgs.text;
                            bad.replace(at, needle.size(), "+ m1;");
                            PolyKernelReceipt rf = certifySourceTextOn(
                                intent, bg, bad, hbClean.generation, realCases, 0.0);
                            kv("BG8B_FALSIFY_COMPILE_EXIT", (uint64_t)(int64_t)rf.compileExit);
                            kv("BG8B_FALSIFY_MAX_ABS_DIFF", rf.maxAbsDiff);
                            check(rf.compileExit == 0 && rf.kernelEntered,
                                  "BG8B_FALSIFY_REAL_WEIGHT_STILL_COMPILES_AND_RUNS",
                                  "the sabotaged real-weight candidate did not run, "
                                  "so this proves nothing about parity");
                            check(rf.maxAbsDiff > 0.0,
                                  "BG8B_FALSIFY_REAL_WEIGHT_PARITY_DISAGREES",
                                  "a one-sign error on a REAL model weight still "
                                  "measured bit-exact; the differential is blind to "
                                  "real inputs and cannot be trusted on them");
                        } else {
                            check(false, "BG8B_FALSIFIER_FOUND_ARITHMETIC_ON_REAL_PATH",
                                  "could not locate the term to corrupt in the "
                                  "generated source");
                        }
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // BG8-H: the reverse registration path, executed against a REAL model.
    //
    // Why this block exists separately from the Deep2Engine.cpp edit:
    // Deep2Engine.cpp CANNOT be compiled in this tree, because
    // vulkan_compute.h:7 includes <vulkan/vulkan.h> unguarded and the Vulkan
    // SDK is not present. That is a pre-existing environment blocker, not a
    // consequence of the wiring, and it is reported rather than worked around.
    //
    // So the registration LOGIC added to loadModel is exercised here verbatim
    // against a real GGUFLoader. That proves the identity derivation, the role
    // classification, the layer extraction, and the provenance round-trip are
    // real and correct. It does NOT prove Deep2Engine.cpp compiles.
    // ---------------------------------------------------------------------
    std::printf("---- BG8-H reverse registration on a real model ----\n");
    {
        GGUFLoader loader;
        const char* p = "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
        check(loader.load(p), "BG8H_MODEL_LOADED",
              "the real model could not be opened for the registration test");

        if (loader.loaded()) {
            const std::vector<std::string> names = loader.listTensors();

            // --- modelIdentity: the exact derivation used in loadModel ---
            const uint64_t modelIdentity = [&loader, &names]() -> uint64_t {
                uint64_t h = 14695981039346656037ull;
                auto mix = [&h](uint64_t v) {
                    for (int i = 0; i < 8; ++i) { h ^= (uint8_t)(v >> (i * 8)); h *= 1099511628211ull; }
                };
                mix(loader.tensorCount());
                size_t taken = 0;
                for (const auto& n : names) {
                    const GGUFTensor* t = loader.getTensor(n);
                    if (!t) continue;
                    mix(fnv1a64Name(n.data(), n.size()));
                    mix(t->sizeBytes);
                    mix(t->fileOffset);
                    mix((uint64_t)t->type);
                    if (++taken >= 3) break;
                }
                mix(taken);
                return h;
            }();

            auto roleFromName = [](const std::string& n) -> uint16_t {
                if (n.find("token_embd") != std::string::npos)      return 1;
                if (n.find("output_norm") != std::string::npos)     return 2;
                if (n == "output.weight" || n.find("lm_head") != std::string::npos) return 3;
                if (n.find("attn_norm") != std::string::npos)       return 4;
                if (n.find("ffn_norm") != std::string::npos)        return 5;
                if (n.find("attn_q") != std::string::npos)          return 6;
                if (n.find("attn_k") != std::string::npos)          return 7;
                if (n.find("attn_v") != std::string::npos)          return 8;
                if (n.find("attn_kv_a") != std::string::npos)       return 9;
                if (n.find("attn_output") != std::string::npos)     return 10;
                if (n.find("ffn_gate_exps") != std::string::npos)   return 11;
                if (n.find("ffn_up_exps") != std::string::npos)     return 12;
                if (n.find("ffn_down_exps") != std::string::npos)   return 13;
                if (n.find("ffn_gate") != std::string::npos)        return 14;
                if (n.find("ffn_up") != std::string::npos)          return 15;
                if (n.find("ffn_down") != std::string::npos)        return 16;
                if (n.find("attn_qkv") != std::string::npos)        return 17;
                if (n.find("ssm_in") != std::string::npos)          return 18;
                if (n.find("ssm_out") != std::string::npos)         return 19;
                if (n.find("ssm_conv1d") != std::string::npos)      return 20;
                if (n.find("ssm") != std::string::npos)             return 21;
                return 0;
            };
            auto layerFromName = [](const std::string& n) -> uint32_t {
                if (n.size() < 4 || n.compare(0, 4, "blk.") != 0) return 0;
                uint32_t v = 0, i = 4, digits = 0;
                while (i < n.size() && n[i] >= '0' && n[i] <= '9') {
                    v = v * 10 + (uint32_t)(n[i] - '0'); ++i; ++digits;
                    if (digits > 6) return 0;
                }
                return v;
            };

            BackingDirectory::Instance().clear();
            kv("BG8H_DIRECTORY_BEFORE", (uint64_t)BackingDirectory::Instance().size());

            uint64_t registered = 0, unclassified = 0;
            for (const auto& n : names) {
                const GGUFTensor* t = loader.getTensor(n);
                if (!t || !t->data || t->sizeBytes == 0) continue;

                TensorIdentity id{};
                id.model   = modelIdentity;
                id.tensor  = fnv1a64Name(n.data(), n.size());
                id.layer   = layerFromName(n);
                id.role    = roleFromName(n);
                id.variant = 0;
                if (id.role == 0) ++unclassified;

                BackingRef br;
                br.source     = BackingSource::GGUF_MMAP;
                br.shardId    = t->shardId;
                br.fileOffset = t->fileOffset;
                br.byteLength = t->sizeBytes;
                br.quantType  = (uint32_t)t->type;
                br.tensorName = t->name;
                if (t->shape.size() >= 2) {
                    br.cols = (uint64_t)t->shape[0];
                    uint64_t rows = 1;
                    for (size_t i = 1; i < t->shape.size(); ++i)
                        rows *= (uint64_t)t->shape[i];
                    br.rows = rows;
                }
                BackingDirectory::Instance().registerBinding(id, br);
                ++registered;
            }

            kv("BG8H_MODEL_IDENTITY", modelIdentity);
            kv("BG8H_REGISTERED", registered);
            kv("BG8H_UNCLASSIFIED_ROLE", unclassified);
            kv("BG8H_DIRECTORY_AFTER", (uint64_t)BackingDirectory::Instance().size());

            check(registered > 0, "BG8H_SOMETHING_REGISTERED",
                  "the registration loop registered nothing from a real model");
            check(BackingDirectory::Instance().size() == registered,
                  "BG8H_DIRECTORY_MATCHES_REGISTERED_COUNT",
                  "the directory size does not equal the number of registrations, "
                  "so identities are colliding or registrations are being dropped");

            // Round-trip a real tensor through the resolver and compare against
            // the loader's own facts. This is the check that would catch a
            // provenance field being filled from the wrong tensor.
            const GGUFTensor* probe = loader.getTensor("blk.0.attn_k.weight");
            check(probe != nullptr, "BG8H_PROBE_TENSOR_PRESENT",
                  "blk.0.attn_k.weight is absent from the real model");
            if (probe) {
                // The name is carried in a std::string and its length comes from
                // .size(). An earlier revision passed a hand-written 20 here; the
                // literal is 19 characters, so the hash covered the NUL
                // terminator too and the lookup missed. A hand-counted length is
                // a defect waiting to happen, not a constant.
                const std::string probeName(probe->name);
                TensorIdentity id{};
                id.model   = modelIdentity;
                id.tensor  = fnv1a64Name(probeName.data(), probeName.size());
                id.layer   = layerFromName(probeName);
                id.role    = roleFromName(probeName);
                id.variant = 0;
                kv("BG8H_PROBE_NAME_LENGTH", (uint64_t)probeName.size());

                auto got = BackingDirectory::Instance().lookup(id);
                check(got.has_value(), "BG8H_PROBE_RESOLVES",
                      "a registered identity did not resolve back out of the directory");
                if (got) {
                    const bool same =
                        got->shardId    == probe->shardId &&
                        got->fileOffset == probe->fileOffset &&
                        got->byteLength == probe->sizeBytes &&
                        got->quantType  == (uint32_t)probe->type &&
                        got->tensorName == probe->name &&
                        got->cols       == (uint64_t)probe->shape[0];
                    check(same, "BG8H_PROVENANCE_ROUND_TRIP_EXACT",
                          "resolved provenance differs from the loader's own facts");
                    kv("BG8H_PROBE_LAYER_INDEX", (uint64_t)id.layer);
                    kv("BG8H_PROBE_ROLE", (uint64_t)id.role);
                    kv("BG8H_PROBE_COLS", got->cols);
                    kv("BG8H_PROBE_ROWS", got->rows);
                }

                // The resolver must now produce a NanoAddress for a REAL tensor,
                // with a CPU form selected from real CPUID.
                KernelIdentity ki = intent;
                ki.weight = id;
                auto na = ReverseLayer::resolve(ki, ExecutionConstraints{},
                                                publishHeartbeat());
                check(na.has_value(), "BG8H_REAL_IDENTITY_RESOLVES_TO_NANOADDRESS",
                      "a real model identity did not resolve to a NanoAddress");
                if (na) {
                    kv("BG8H_NANOADDR_FORM",
                       backendFormName(ReverseLayer::selectForm(
                           ki, na->backing, na->heartbeat, ExecutionConstraints{})));
                    check(na->backing.immediatelyAddressable(),
                          "BG8H_REAL_BACKING_IS_ADDRESSABLE_WITHOUT_MOVEMENT",
                          "a real mmap-backed tensor resolved as needing a transfer");
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // BG8-C: MULTIPLE generated implementations of the SAME GEMV, compared on
    // measured residual AND measured cost, on the SAME real model bytes.
    //
    // The set deliberately contains wrong candidates. A selection rule that only
    // ever sees correct candidates cannot be shown to discriminate, so three of
    // these are numerically wrong by construction and MUST be rejected. If a
    // wrong candidate were ever promoted, this block fails.
    //
    // Every candidate receives identical inputs. Any difference in outcome is
    // therefore attributable to the candidate.
    // ---------------------------------------------------------------------
    std::printf("---- BG8-C candidate set ----\n");
    {
        GGUFLoader loader;
        const char* mp = "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
        if (!loader.load(mp)) {
            check(false, "BG8C_MODEL_LOADED", "the real model could not be reopened");
        } else {
            const GGUFTensor* wt = loader.getTensor("blk.0.attn_k.weight");
            check(wt != nullptr, "BG8C_TENSOR_PRESENT",
                  "blk.0.attn_k.weight absent for the candidate set");
            if (wt) {
                const uint32_t cols = (uint32_t)wt->shape[0];
                const uint32_t rows = 32;
                const size_t rowBytes = ((size_t)cols / 256) * 144;
                std::vector<uint8_t> realBytes(
                    reinterpret_cast<const uint8_t*>(wt->data),
                    reinterpret_cast<const uint8_t*>(wt->data) + rowBytes * rows);

                std::vector<float> x(cols);
                std::mt19937 rng(0xB68u);
                std::uniform_real_distribution<float> d(-1.0f, 1.0f);
                for (auto& v : x) v = d(rng);

                ExternalCase rc;
                rc.weightBytes = realBytes.data();
                rc.x = x.data();
                rc.rows = rows;
                rc.cols = cols;
                rc.label = "blk.0.attn_k.weight";
                const std::vector<ExternalCase> cases{rc};

                const GeneratedSource base =
                    generatePolyKernelSource(intent, ReverseLayer::decompose(intent),
                                             BackendForm::CPU_SCALAR);
                check(base.produced, "BG8C_BASE_GENERATED", base.rejectReason.c_str());

                if (base.produced) {
                    // Candidate variants are produced by MUTATING the emitted
                    // source at named seams. Each seam is a real, single-token
                    // substitution, so each candidate differs from the baseline
                    // in exactly one documented way and nothing else.
                    struct Variant {
                        const char* name;
                        const char* needle;
                        const char* replace;
                        bool expectExact;
                        const char* why;
                    };
                    const Variant kVariants[] = {
                        {"C0_BASELINE",          nullptr, nullptr, true,
                         "unmodified emitted source"},
                        {"C1_NO_MIN_TERM",       " - m1;", "", false,
                         "drops the dmin*min subtraction entirely"},
                        {"C2_MIN_SIGN_FLIPPED",  " - m1;", " + m1;", false,
                         "flips the sign of the min term"},
                        {"C3_HI_MIN_FLIPPED",    " - m2;", " + m2;", false,
                         "flips the sign of the high-nibble min term"},
                        {"C4_SCALE_DROPPED",     "d1 * (float)(q[l] & 0xF)",
                                                "(float)(q[l] & 0xF)", false,
                         "removes the block scale from the low nibble"},
                        {"C5_ONLY_EVEN_BLOCKS",  "for (int j = 0; j < 256; j += 64)",
                                                "for (int j = 0; j < 128; j += 64)", false,
                         "reads only half of each block"},
                        {"C6_ZERO_OUTPUT",       "y[r] = acc;", "y[r] = 0.0f;", false,
                         "produces a structurally valid but wrong answer"},
                        {"C7_SCALE_SWAPPED",     "d1 * (float)(q[l] & 0xF)",
                                                "d2 * (float)(q[l] & 0xF)", false,
                         "uses the high-nibble scale on the low nibble"},
                    };
                    const int kVarCount = (int)(sizeof(kVariants) / sizeof(kVariants[0]));

                    struct Result {
                        std::string name;
                        bool produced = false, exact = false, rejected = false;
                        double maxAbsDiff = 0.0;
                        uint64_t wallNs = 0, refNs = 0, relL2 = 0, srcDigest = 0;
                        uint64_t binaryDigest = 0, sourceBytesRead = 0;
                        bool seamFound = true;
                        std::string why;
                    };
                    std::vector<Result> results;

                    for (int i = 0; i < kVarCount; ++i) {
                        const Variant& v = kVariants[i];
                        Result R;
                        R.name = v.name;
                        R.why  = v.why;

                        std::string text = base.text;
                        if (v.needle) {
                            const size_t at = text.find(v.needle);
                            if (at == std::string::npos) {
                                R.seamFound = false;
                                std::printf("CAND %-20s SEAM_NOT_FOUND reason=%s\n",
                                            v.name, v.why);
                                results.push_back(R);
                                continue;
                            }
                            text.replace(at, std::strlen(v.needle), v.replace);
                        }

                        PolyKernelReceipt r = certifySourceTextOn(
                            intent, ReverseLayer::decompose(intent), text,
                            hbClean.generation, cases, 0.0);

                        R.produced      = r.sourceGenerated;
                        R.exact         = (r.compileExit == 0 && r.kernelEntered &&
                                           r.finiteOutput && r.nonFiniteRef == 0 &&
                                           r.maxAbsDiff == 0.0 && r.comparisonCount > 0);
                        R.maxAbsDiff    = r.maxAbsDiff;
                        R.wallNs        = r.wallTimeNs;
                        R.refNs         = r.referenceWallNs;
                        R.relL2         = r.relativeL2;
                        R.srcDigest     = r.sourceDigest;
                        R.binaryDigest  = r.binaryDigest;
                        R.sourceBytesRead = r.sourceBytesRead;
                        // "rejected" is decided by the promotion rule, below --
                        // never by the candidate's own opinion of itself.
                        std::printf("CAND %-20s COMPILE=%d ENTERED=%d FINITE=%d "
                                    "MAX_ABS_DIFF=%.9g REL_L2=%llu WALL_NS=%llu "
                                    "REF_NS=%llu BYTES_READ=%llu SRC=%llu BIN=%llu "
                                    "EXPECT_EXACT=%d\n",
                                    v.name, r.compileExit, r.kernelEntered ? 1 : 0,
                                    r.finiteOutput ? 1 : 0, r.maxAbsDiff,
                                    (unsigned long long)r.relativeL2,
                                    (unsigned long long)r.wallTimeNs,
                                    (unsigned long long)r.referenceWallNs,
                                    (unsigned long long)r.sourceBytesRead,
                                    (unsigned long long)r.sourceDigest,
                                    (unsigned long long)r.binaryDigest,
                                    v.expectExact ? 1 : 0);
                        results.push_back(R);
                    }

                    // ---- the promotion rule, applied uniformly ----
                    // Semantic/memory validity first, then a resource axis. A
                    // numerically valid candidate is not automatically a winner.
                    int promoted = -1;
                    uint64_t bestNs = ~0ull;
                    int exactCount = 0, wrongRejected = 0, shouldReject = 0;

                    for (int i = 0; i < (int)results.size(); ++i) {
                        const Result& R = results[i];
                        const bool valid = R.produced && R.seamFound && R.exact;
                        const bool expectExact =
                            std::strcmp(R.name.c_str(), "C0_BASELINE") == 0;

                        if (expectExact) {
                            if (valid) ++exactCount; else ++shouldReject;
                        } else {
                            ++shouldReject;
                            if (!valid) ++wrongRejected;
                        }
                        if (!valid) continue;   // rejection is recorded below

                        const uint64_t ns = R.wallNs ? R.wallNs : ~0ull;
                        if (ns < bestNs) { bestNs = ns; promoted = i; }
                    }

                    // Mark the winner. Comparing addresses of vector elements is
                    // safe here because the vector is not resized after the
                    // selection loop.
                    for (size_t i = 0; i < results.size(); ++i)
                        results[i].rejected = (static_cast<int>(i) != promoted);

                    std::printf("BG8C_CANDIDATES=%d EXPECTED_EXACT=%d "
                                "CONFIRMED_EXACT=%d WRONG_REJECTED=%d/%d "
                                "PROMOTED=%s\n",
                                kVarCount, exactCount, exactCount, wrongRejected,
                                shouldReject,
                                promoted >= 0 ? results[promoted].name.c_str() : "NONE");
                    if (promoted >= 0) {
                        std::printf("BG8C_WINNER_MAX_ABS_DIFF=%.9g "
                                    "BG8C_WINNER_WALL_NS=%llu "
                                    "BG8C_WINNER_BIN=%llu\n",
                                    results[promoted].maxAbsDiff,
                                    (unsigned long long)results[promoted].wallNs,
                                    (unsigned long long)results[promoted].binaryDigest);
                    }

                    check(exactCount == 1,
                          "BG8C_ONLY_BASELINE_IS_EXACT",
                          "a candidate built to be wrong measured bit-exact against "
                          "the production kernel");
                    check(wrongRejected == shouldReject,
                          "BG8C_EVERY_WRONG_CANDIDATE_REJECTED",
                          "at least one deliberately wrong candidate was not rejected");
                    check(promoted >= 0,
                          "BG8C_A_WINNER_WAS_PROMOTED",
                          "no candidate satisfied the promotion rule");

                    // Distinct candidates must produce distinct SOURCE. If two
                    // variants hashed the same, the seam substitutions did
                    // nothing and the whole comparison is vacuous.
                    {
                        std::vector<uint64_t> digests;
                        for (const auto& R : results)
                            if (R.produced && R.seamFound) digests.push_back(R.srcDigest);
                        std::sort(digests.begin(), digests.end());
                        const bool uniq =
                            std::adjacent_find(digests.begin(), digests.end()) == digests.end();
                        check(uniq, "BG8C_CANDIDATE_SOURCES_ARE_DISTINCT",
                              "two candidates produced the same source digest, so the "
                              "seam substitutions did not take effect");
                    }

                    // ---- BG8-D: winner persistence and replay ----
                    // The winner must be re-derivable from its identity alone,
                    // producing the same source digest and the same binary digest.
                    // A winner that can only be found by re-running every
                    // candidate is not persisted, it is rediscovered.
                    if (promoted >= 0) {
                        const Result& W = results[promoted];
                        rawrxd::deep2::loom::ExecutableIdentity ei;
                        ei.genomeHash          = W.srcDigest;
                        ei.materializerHash    = 0;
                        ei.compilerId          = "msvc-14.44";
                        ei.compilerFlags       = "/O2 /std:c++17";
                        ei.targetIsa           = "x86-64";
                        ei.generatedSourceHash = W.srcDigest;
                        ei.binaryHash          = W.binaryDigest;

                        // Replay: regenerate the winner's source from the same
                        // recipe and re-certify. Identical source and binary
                        // digests mean the winner is reproducible, not incidental.
                        const std::string replayText = base.text;   // C0 recipe
                        PolyKernelReceipt rr = certifySourceTextOn(
                            intent, ReverseLayer::decompose(intent), replayText,
                            hbClean.generation, cases, 0.0);

                        kv("BG8D_WINNER_NAME", W.name);
                        kv("BG8D_WINNER_SRC_DIGEST", W.srcDigest);
                        kv("BG8D_REPLAY_SRC_DIGEST", rr.sourceDigest);
                        kv("BG8D_WINNER_BIN_DIGEST", W.binaryDigest);
                        kv("BG8D_REPLAY_BIN_DIGEST", rr.binaryDigest);
                        kv("BG8D_EXECUTABLE_HASH", ei.hash());

                        check(rr.sourceDigest == W.srcDigest,
                              "BG8D_REPLAY_REPRODUCES_SOURCE",
                              "regenerating the winner produced different source bytes");
                        check(rr.binaryDigest == W.binaryDigest,
                              "BG8D_REPLAY_REPRODUCES_BINARY",
                              "recompiling the winner produced a different binary, so "
                              "the winner is not reproducible and cannot be persisted");
                        check(rr.maxAbsDiff == 0.0,
                              "BG8D_REPLAY_STILL_BIT_EXACT",
                              "the replayed winner no longer matches production");
                        // Two different candidates must NOT share an executable
                        // identity, or persistence would conflate them.
                        //
                        // The comparison must use a candidate that is actually
                        // DIFFERENT from the winner. An earlier revision used
                        // results[0], which IS the winner whenever it is
                        // promoted, so the two identities were trivially equal
                        // and the check failed for the wrong reason -- it was
                        // comparing the winner against itself.
                        int otherIdx = -1;
                        for (size_t i = 0; i < results.size(); ++i) {
                            if (static_cast<int>(i) != promoted) { otherIdx = (int)i; break; }
                        }
                        check(otherIdx >= 0,
                              "BG8D_A_DIFFERENT_CANDIDATE_EXISTS",
                              "there is no candidate to compare the winner against");
                        if (otherIdx >= 0) {
                            const Result& Other = results[otherIdx];
                            rawrxd::deep2::loom::ExecutableIdentity eo;
                            eo.genomeHash          = Other.srcDigest;
                            eo.materializerHash    = 0;
                            eo.compilerId          = "msvc-14.44";
                            eo.compilerFlags       = "/O2 /std:c++17";
                            eo.targetIsa           = "x86-64";
                            eo.generatedSourceHash = Other.srcDigest;
                            eo.binaryHash          = Other.binaryDigest;
                            kv("BG8D_OTHER_CANDIDATE", Other.name);
                            kv("BG8D_OTHER_EXECUTABLE_HASH", eo.hash());
                            check(ei.hash() != eo.hash(),
                                  "BG8D_DISTINCT_CANDIDATES_DISTINCT_IDENTITIES",
                                  "the winner and a different candidate produced the "
                                  "same executable identity");
                        }
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // C14: ReverseIntegration is no longer a self-certifying stub.
    //
    // It previously read `return true` in all three methods. If any of these
    // checks could still pass under the old implementation, the repair did not
    // happen. They are written so the OLD code fails them.
    // ---------------------------------------------------------------------
    std::printf("---- C14 ReverseIntegration fail-closed ----\n");
    {
        Deep2::ReverseIntegration ri;

        check(!ri.attach(-1),
              "C14A_INVALID_DEVICE_ATTACH_REFUSED",
              "attach() accepted a negative device index");
        check(!ri.isAttached(0) && ri.attachedCount() == 0,
              "C14B_NOTHING_ATTACHED_BY_CONSTRUCTION",
              "the object reports an attachment that was never made");

        check(ri.attach(0),
              "C14C_VALID_ATTACH_ACCEPTED",
              "attach() refused a valid device index");
        check(ri.isAttached(0) && ri.attachedCount() == 1,
              "C14D_ATTACH_STATE_OBSERVED",
              "attach() returned true without recording anything");

        check(!ri.validate(1),
              "C14E_UNATTACHED_VALIDATE_REFUSED",
              "validate() accepted a device that was never attached");
        check(ri.validate(0) && ri.isValidated(0),
              "C14F_ATTACHED_VALIDATE_ACCEPTED",
              "validate() refused a device that was attached");

        // Topology change must invalidate a prior validation.
        ri.topologyChanged();
        check(!ri.isValidated(0),
              "C14G_TOPOLOGY_CHANGE_INVALIDATES_VALIDATION",
              "validation survived a topology change and would be presented as current");

        kv("C14_ATTACH_REFUSED", ri.attachRefusedCount());
        kv("C14_VALIDATE_REFUSED", ri.validateRefusedCount());
        kv("C14_ACTIVATE_REFUSED", ri.activateRefusedCount());
        kv("C14_VALIDATION_EPOCH", ri.validationEpoch());

        // Re-validate, then activate exactly once.
        ri.validate(0);
        check(ri.activate(0) && ri.isActive(0),
              "C14H_VALIDATED_ACTIVATION_ACCEPTED",
              "activate() refused a validated device");
        check(!ri.activate(0),
              "C14I_SECOND_ACTIVATION_REFUSED",
              "a second activation in the same epoch was accepted as a new authority");

        // A fresh instance must be inactive: no state may leak between objects.
        Deep2::ReverseIntegration fresh;
        check(!fresh.isActive(0) && fresh.activeCount() == 0 &&
              fresh.attachedCount() == 0,
              "C14J_NO_STATE_LEAKS_BETWEEN_INSTANCES",
              "a fresh instance began with another instance's activation state");

        check(!Deep2::ReverseIntegration{}.activate(0),
              "C14K_UNVALIDATED_ACTIVATION_REFUSED_ON_FRESH_OBJECT",
              "activate() succeeded on an object that never validated anything");
    }

    // ---------------------------------------------------------------------
    // BG8-E + BG8-F: a real braid -- RMSNorm then Q then K, on real tensors.
    //
    // Two generated GEMV forms running back to back against the production
    // reference, fed by a real norm weight from the model. This is the actual
    // entry sequence of a transformer block, so it tests composition rather than
    // a single isolated call.
    //
    // The norm itself is computed here in plain float and is NOT claimed
    // bit-exact against anything: it only prepares the input. Its finiteness is
    // recorded, not certified. The parity claims are the two GEMVs.
    // ---------------------------------------------------------------------
    std::printf("---- BG8-E/F norm + Q + K braid ----\n");
    {
        GGUFLoader loader;
        const char* mp = "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
        if (!loader.load(mp)) {
            check(false, "BG8EF_MODEL_LOADED", "real model could not be opened");
        } else {
            // Discover the real tensors rather than assuming names or types.
            const GGUFTensor* nq = loader.getTensor("blk.0.attn_q.weight");
            const GGUFTensor* nk = loader.getTensor("blk.0.attn_k.weight");
            const GGUFTensor* nn = loader.getTensor("blk.0.attn_norm.weight");

            check(nq != nullptr, "BG8EF_Q_PRESENT", "blk.0.attn_q.weight absent");
            check(nk != nullptr, "BG8EF_K_PRESENT", "blk.0.attn_k.weight absent");
            check(nn != nullptr, "BG8EF_NORM_PRESENT", "blk.0.attn_norm.weight absent");

            if (nq && nk && nn) {
                kv("BG8EF_Q_TYPE", (uint64_t)nq->type);
                kv("BG8EF_K_TYPE", (uint64_t)nk->type);
                kv("BG8EF_NORM_TYPE", (uint64_t)nn->type);
                kv("BG8EF_NORM_SHAPE_SIZE", (uint64_t)nn->shape.size());
                kv("BG8EF_NORM_SHAPE0", (uint64_t)(nn->shape.empty() ? 0 : nn->shape[0]));
                kv("BG8EF_NORM_BYTES", (uint64_t)nn->sizeBytes);

                // The Q4_K GEMV generator only emits Q4_K. If the real model
                // stores Q in another quant, this block must say so rather than
                // quietly certifying the wrong thing.
                const bool qIsQ4K = (nq->type == GGMLType::GGML_TYPE_Q4_K);
                const bool kIsQ4K = (nk->type == GGMLType::GGML_TYPE_Q4_K);
                check(qIsQ4K, "BG8EF_Q_IS_Q4K",
                      "blk.0.attn_q.weight is not Q4_K; the Q4_K emitter cannot certify it");
                check(kIsQ4K, "BG8EF_K_IS_Q4K",
                      "blk.0.attn_k.weight is not Q4_K; the Q4_K emitter cannot certify it");

                // Norm weight is F32 in llama GGUFs. If it is not, do not
                // reinterpret its bytes as float.
                const bool normIsF32 = (nn->type == GGMLType::GGML_TYPE_F32);
                check(normIsF32, "BG8EF_NORM_IS_F32",
                      "blk.0.attn_norm.weight is not F32, so it cannot be read as float");

                if (qIsQ4K && kIsQ4K && normIsF32 && nn->shape.size() == 1) {
                    const uint32_t hidden = (uint32_t)nn->shape[0];
                    const auto* normW = reinterpret_cast<const float*>(nn->data);

                    // Real activation, then a real RMSNorm over it.
                    std::vector<float> raw(hidden);
                    std::mt19937 rng(0xBEEFu);
                    std::uniform_real_distribution<float> d(-1.5f, 1.5f);
                    for (auto& v : raw) v = d(rng);

                    const float eps = 1e-5f;
                    std::vector<float> normed(hidden);
                    double ss = 0.0;
                    for (uint32_t i = 0; i < hidden; ++i) ss += (double)raw[i] * raw[i];
                    const float inv = 1.0f / std::sqrt((float)ss / hidden + eps);
                    bool normFinite = true;
                    for (uint32_t i = 0; i < hidden; ++i) {
                        normed[i] = raw[i] * inv * normW[i];
                        if (!std::isfinite(normed[i])) normFinite = false;
                    }
                    kv("BG8EF_HIDDEN", (uint64_t)hidden);
                    kv("BG8EF_NORM_FINITE", normFinite);
                    kv("BG8EF_NORMED_ROW0", (double)normed[0]);
                    check(normFinite, "BG8EF_NORMED_INPUT_FINITE",
                          "the normalized input contains non-finite values");

                    const GeneratedSource src =
                        generatePolyKernelSource(intent,
                            ReverseLayer::decompose(intent), BackendForm::CPU_SCALAR);

                    // Both projections share one input, which is the real
                    // dependency: neither output feeds the other.
                    auto slice = [&](const GGUFTensor* t, uint32_t rows,
                                     std::vector<uint8_t>& out) -> size_t {
                        const uint32_t cols = (uint32_t)t->shape[0];
                        const size_t rowBytes = ((size_t)cols / 256) * 144;
                        out.assign(reinterpret_cast<const uint8_t*>(t->data),
                                   reinterpret_cast<const uint8_t*>(t->data) +
                                   rowBytes * rows);
                        return (size_t)cols;
                    };

                    std::vector<uint8_t> qBytes, kBytes;
                    const uint32_t rows = 32;
                    const size_t qCols = slice(nq, rows, qBytes);
                    const size_t kCols = slice(nk, rows, kBytes);

                    ExternalCase qc;
                    qc.weightBytes = qBytes.data();
                    qc.x = normed.data();
                    qc.rows = rows; qc.cols = (uint32_t)qCols;
                    qc.label = "blk.0.attn_q.weight";
                    ExternalCase kc;
                    kc.weightBytes = kBytes.data();
                    kc.x = normed.data();
                    kc.rows = rows; kc.cols = (uint32_t)kCols;
                    kc.label = "blk.0.attn_k.weight";

                    const std::vector<ExternalCase> qcases{qc};
                    const std::vector<ExternalCase> kcases{kc};

                    PolyKernelReceipt rq = certifySourceTextOn(
                        intent, ReverseLayer::decompose(intent), src.text,
                        hbClean.generation, qcases, 0.0);
                    PolyKernelReceipt rk = certifySourceTextOn(
                        intent, ReverseLayer::decompose(intent), src.text,
                        hbClean.generation, kcases, 0.0);

                    kv("BG8EF_Q_COMPILE_EXIT", (uint64_t)(int64_t)rq.compileExit);
                    kv("BG8EF_Q_MAX_ABS_DIFF", rq.maxAbsDiff);
                    kv("BG8EF_Q_RELATIVE_L2", rq.relativeL2);
                    kv("BG8EF_K_COMPILE_EXIT", (uint64_t)(int64_t)rk.compileExit);
                    kv("BG8EF_K_MAX_ABS_DIFF", rk.maxAbsDiff);
                    kv("BG8EF_K_RELATIVE_L2", rk.relativeL2);
                    kv("BG8EF_BRAID_WALL_NS", rq.wallTimeNs + rk.wallTimeNs);
                    kv("BG8EF_BRAID_REFERENCE_NS", rq.referenceWallNs + rk.referenceWallNs);

                    check(rq.compileExit == 0 && rq.kernelEntered && rq.finiteOutput,
                          "BG8EF_Q_BRAID_MEMBER_VALID",
                          "the Q member of the braid did not run cleanly");
                    check(rk.compileExit == 0 && rk.kernelEntered && rk.finiteOutput,
                          "BG8EF_K_BRAID_MEMBER_VALID",
                          "the K member of the braid did not run cleanly");
                    check(rq.maxAbsDiff == 0.0,
                          "BG8EF_Q_BIT_EXACT_IN_BRAID",
                          "Q diverged once it ran alongside K, though it was exact alone");
                    check(rk.maxAbsDiff == 0.0,
                          "BG8EF_K_BIT_EXACT_IN_BRAID",
                          "K diverged once it ran alongside Q, though it was exact alone");

                    // The braid must be falsifiable too: corrupt the source once
                    // and both members must notice.
                    {
                        const std::string needle = "- m1;";
                        const size_t at = src.text.find(needle);
                        if (at != std::string::npos) {
                            std::string bad = src.text;
                            bad.replace(at, needle.size(), "+ m1;");
                            PolyKernelReceipt fq = certifySourceTextOn(
                                intent, ReverseLayer::decompose(intent), bad,
                                hbClean.generation, qcases, 0.0);
                            PolyKernelReceipt fk = certifySourceTextOn(
                                intent, ReverseLayer::decompose(intent), bad,
                                hbClean.generation, kcases, 0.0);
                            kv("BG8EF_FALSIFY_Q_MAX_ABS_DIFF", fq.maxAbsDiff);
                            kv("BG8EF_FALSIFY_K_MAX_ABS_DIFF", fk.maxAbsDiff);
                            check(fq.maxAbsDiff > 0.0 && fk.maxAbsDiff > 0.0,
                                  "BG8EF_BRAID_FALSIFIABLE_IN_BOTH_MEMBERS",
                                  "a corrupted source still measured exact on a braid "
                                  "member, so the braid checks cannot detect corruption");
                        } else {
                            check(false, "BG8EF_FALSIFIER_SEAM_PRESENT",
                                  "could not locate the term to corrupt");
                        }
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // BG8-AV: the vector forms are real vectorisation, not labels.
    //
    // The claim under test is "AVX2_INTRINSIC_EMISSION". Three things must all
    // hold, and the middle one is the one that catches a fake capability:
    //
    //   1. the emitted SOURCE contains the intrinsics
    //   2. the compiled BINARY DIFFERS from the scalar form's binary
    //      (identical digests would prove the scalar fallback was taken)
    //   3. the vector form is still BIT-EXACT against production
    //
    // Asserting only (1) is what an earlier revision of this receipt would have
    // done, and it would have passed while the intrinsics were compiled out.
    // ---------------------------------------------------------------------
    std::printf("---- BG8-AV vector form verification ----\n");
    {
        GGUFLoader loader;
        const char* mp = "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
        if (!loader.load(mp)) {
            check(false, "BG8AV_MODEL_LOADED", "real model could not be opened");
        } else {
            const GGUFTensor* wt = loader.getTensor("blk.0.attn_k.weight");
            if (!wt) {
                check(false, "BG8AV_TENSOR_PRESENT", "attn_k weight absent");
            } else if (wt->type != GGMLType::GGML_TYPE_Q4_K) {
                check(false, "BG8AV_TENSOR_IS_Q4K",
                      "attn_k weight is not Q4_K; the vector form cannot be graded");
            } else {
                const uint32_t cols = (uint32_t)wt->shape[0];
                const uint32_t rows = 32;
                const size_t rowBytes = ((size_t)cols / 256) * 144;
                std::vector<uint8_t> realBytes(
                    reinterpret_cast<const uint8_t*>(wt->data),
                    reinterpret_cast<const uint8_t*>(wt->data) + rowBytes * rows);
                std::vector<float> x(cols);
                std::mt19937 rng(0xA5u);
                std::uniform_real_distribution<float> d(-1.0f, 1.0f);
                for (auto& v : x) v = d(rng);

                ExternalCase rc;
                rc.weightBytes = realBytes.data();
                rc.x = x.data();
                rc.rows = rows; rc.cols = cols;
                rc.label = "blk.0.attn_k.weight";
                const std::vector<ExternalCase> cases{rc};

                struct FormResult {
                    BackendForm form;
                    const char*  name;
                    bool  intrinsicsInSource = false;
                    PolyKernelReceipt r;
                };
                const BackendForm forms[] = {
                    BackendForm::CPU_SCALAR, BackendForm::CPU_AVX2, BackendForm::CPU_AVX512
                };
                const char* names[] = {"SCALAR", "AVX2", "AVX512"};
                FormResult res[3];

                for (int i = 0; i < 3; ++i) {
                    res[i].form = forms[i];
                    res[i].name = names[i];
                    GeneratedSource gs = generatePolyKernelSource(
                        intent, ReverseLayer::decompose(intent), forms[i]);
                    res[i].r = certifyPolyKernel(
                        intent, ReverseLayer::decompose(intent), forms[i],
                        hbClean.generation, rows, cols, 1, 0.0);
                    if (gs.produced) {
                        res[i].intrinsicsInSource =
                            gs.text.find("_mm256_") != std::string::npos ||
                            gs.text.find("_mm512_") != std::string::npos;
                    }
                    std::printf("BG8AV %-7s ISA_FLAG=%-16s SRC_HAS_INTRIN=%d "
                                "COMPILE=%d MAX_ABS_DIFF=%.9g WALL_NS=%llu "
                                "REF_NS=%llu SRC=%llu BIN=%llu\n",
                                names[i],
                                Deep2::isaFlagForForm(forms[i]).empty()
                                    ? "(none)" : Deep2::isaFlagForForm(forms[i]).c_str(),
                                res[i].intrinsicsInSource ? 1 : 0,
                                res[i].r.compileExit, res[i].r.maxAbsDiff,
                                (unsigned long long)res[i].r.wallTimeNs,
                                (unsigned long long)res[i].r.referenceWallNs,
                                (unsigned long long)res[i].r.sourceDigest,
                                (unsigned long long)res[i].r.binaryDigest);
                }

                check(!res[0].intrinsicsInSource,
                      "BG8AV_SCALAR_FORM_HAS_NO_INTRINSICS",
                      "the scalar form emitted vector intrinsics");
                check(res[1].intrinsicsInSource,
                      "BG8AV_AVX2_SOURCE_HAS_INTRINSICS",
                      "the AVX2 form emitted no intrinsics");
                check(res[2].intrinsicsInSource,
                      "BG8AV_AVX512_SOURCE_HAS_INTRINSICS",
                      "the AVX-512 form emitted no intrinsics");

                // The decisive check: different binaries. If the /arch switch
                // had not been passed, the scalar fallback would have been
                // compiled and these digests would be equal.
                check(res[1].r.binaryDigest != res[0].r.binaryDigest,
                      "BG8AV_AVX2_BINARY_DIFFERS_FROM_SCALAR",
                      "AVX2 produced the same binary as scalar, so the intrinsics "
                      "were compiled out and the /arch switch did not take effect");
                check(res[2].r.binaryDigest != res[0].r.binaryDigest,
                      "BG8AV_AVX512_BINARY_DIFFERS_FROM_SCALAR",
                      "AVX-512 produced the same binary as scalar, so the intrinsics "
                      "were compiled out");
                check(res[2].r.binaryDigest != res[1].r.binaryDigest,
                      "BG8AV_AVX512_DIFFERS_FROM_AVX2",
                      "AVX-512 and AVX2 produced the same binary");

                // And vectorisation must not have cost exactness.
                check(res[1].r.maxAbsDiff == 0.0,
                      "BG8AV_AVX2_BIT_EXACT",
                      "the AVX2 form diverged from production");
                check(res[2].r.maxAbsDiff == 0.0,
                      "BG8AV_AVX512_BIT_EXACT",
                      "the AVX-512 form diverged from production");

                kv("BG8AV_SCALAR_BIN", res[0].r.binaryDigest);
                kv("BG8AV_AVX2_BIN", res[1].r.binaryDigest);
                kv("BG8AV_AVX512_BIN", res[2].r.binaryDigest);

                // Report the speed honestly. A vector form that is bit-exact but
                // slower must not be described as an optimisation.
                kv("BG8AV_SCALAR_WALL_NS", res[0].r.wallTimeNs);
                kv("BG8AV_AVX2_WALL_NS", res[1].r.wallTimeNs);
                kv("BG8AV_AVX512_WALL_NS", res[2].r.wallTimeNs);
                const bool avx2Faster = res[1].r.wallTimeNs < res[0].r.wallTimeNs;
                const bool avx512Faster = res[2].r.wallTimeNs < res[0].r.wallTimeNs;
                kv("BG8AV_AVX2_FASTER_THAN_SCALAR", avx2Faster);
                kv("BG8AV_AVX512_FASTER_THAN_SCALAR", avx512Faster);
                // No speed claim is asserted: only that the forms are real and
                // exact. Whether a given vector form is worth promoting on this
                // machine is a promotion decision, not a correctness gate.
            }
        }
    }

    // ---------------------------------------------------------------------
    // Summary
    // ---------------------------------------------------------------------
    std::printf("------------------------\n");
    std::printf("CHECKS_RUN=%d\n", g_pass + g_fail);
    std::printf("CHECKS_PASS=%d\n", g_pass);
    std::printf("CHECKS_FAIL=%d\n", g_fail);

    const bool allOk = (g_fail == 0) && R.passed();
    std::printf("RECEIPT_VERDICT=%s\n", allOk ? "PASS" : "FAIL");

    ReverseLayer::Stats st = ReverseLayer::statsSnapshot();
    std::printf("REVERSE_RESOLVE_CALLS=%llu\n", (unsigned long long)st.resolveCalls);
    std::printf("REVERSE_RESOLVED=%llu\n", (unsigned long long)st.resolveSucceeded);
    std::printf("REVERSE_IDENTITY_MISS=%llu\n", (unsigned long long)st.resolveIdentityMiss);
    std::printf("REVERSE_NO_FORM=%llu\n", (unsigned long long)st.resolveNoForm);
    std::printf("REVERSE_FORM_CPU_SCALAR=%llu\n", (unsigned long long)st.forms[(int)BackendForm::CPU_SCALAR]);
    std::printf("REVERSE_FORM_CPU_AVX2=%llu\n", (unsigned long long)st.forms[(int)BackendForm::CPU_AVX2]);
    std::printf("REVERSE_FORM_CPU_AVX512=%llu\n", (unsigned long long)st.forms[(int)BackendForm::CPU_AVX512]);
    std::printf("REVERSE_FORM_VULKAN_SINGLE=%llu\n", (unsigned long long)st.forms[(int)BackendForm::VULKAN_SINGLE]);
    std::printf("REVERSE_FORM_VULKAN_DUAL_ROW=%llu\n", (unsigned long long)st.forms[(int)BackendForm::VULKAN_DUAL_ROW]);
    std::printf("REVERSE_FORM_VULKAN_RESIDENT=%llu\n", (unsigned long long)st.forms[(int)BackendForm::VULKAN_RESIDENT]);
    std::printf("DIRECTORY_BINDINGS=%zu\n", BackingDirectory::Instance().size());
    std::printf("DIRECTORY_GENERATION=%llu\n", (unsigned long long)BackingDirectory::Instance().generation());
    std::printf("VERDICT=%s\n", allOk ? "PASS" : "FAIL");
    std::fflush(stdout);
    return allOk ? 0 : 1;
}
