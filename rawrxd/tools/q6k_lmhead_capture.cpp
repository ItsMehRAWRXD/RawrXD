// ============================================================================
// tools/q6k_lmhead_capture.cpp  --  capture side of RAWRXD_Q6K_LMHEAD_ROUTE_ABC_001
// ============================================================================
// Produces the FINAL_NORM vector that the tied Q6_K LM head actually consumes.
//
// WHY THIS IS A SEPARATE TOOL RATHER THAN PART OF THE PARITY GATE
// The gate must compare three routes over ONE captured operand. If the harness
// recomputed the norm, a defect in the norm would be indistinguishable from a
// defect in the head projection -- exactly the boundary confusion that already
// cost this project one localisation cycle (FIRST_BAD_STATE narrowed to
// "FINAL_NORM_OR_LM_HEAD_OR_LOGIT_POSTPROCESS" and stopped there because the
// vector was only hashed, never inspected).
//
// So: this captures the real buffer the kernel saw, via the engine's own
// RAWRXD_PARITY_FINAL_NORM_VEC_001 path (enableParityProbeFullVectors(-3)),
// and the parity harness computes it. Nothing is recomputed here.
//
// Provenance is emitted alongside, because a stale capture silently paired with
// a different model would be an unattributable false result.
#include "Deep2Engine.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: %s <model.gguf> <out_parity_file>\n", argv[0]);
        return 2;
    }
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    const std::string model = argv[1];
    const std::string out   = argv[2];

    Deep2::Deep2Engine e;
    Deep2::ModelLoadDiag diag;
    std::printf("MODEL_PATH=%s\n", model.c_str());
    if (!e.loadModel(model, &diag)) {
        std::printf("CAPTURE=FAIL\nLOAD=FAIL stage=%s message=%s\n",
                    diag.stageName.c_str(), diag.message.c_str());
        return 4;
    }
    std::printf("LOAD=PASS\n");

    // maxSteps 0: one token is enough and keeps the capture file small.
    e.enableParityProbe(out.c_str(), 0);
    // RAWRXD_PARITY_FINAL_NORM_VEC_001: -3 is the non-layer FINAL_NORM site.
    e.enableParityProbeFullVectors(-3);

    Deep2::GenerationOptions o;
    o.maxTokens = 1;
    o.temperature = 0.0f;
    o.topK = 1;
    o.seed = 7;

    Deep2::GenerationResult r =
        e.generateStream("", o,
                         [](int32_t, const std::string&) { return true; });
    std::printf("GENERATE status=%d completed=%d generated=%llu detail=%s\n",
                static_cast<int>(r.status), r.completed ? 1 : 0,
                static_cast<unsigned long long>(r.generatedTokens),
                r.failureDetail.c_str());

    // Does the capture actually contain the vector we need? Check the file rather
    // than assume it, so a silent no-dump cannot pass as a capture.
    std::FILE* f = std::fopen(out.c_str(), "rb");
    if (!f) { std::printf("CAPTURE=FAIL reason=no_parity_file\n"); return 6; }
    std::fseek(f, 0, SEEK_END);
    const long long sz = _ftelli64(f);
    std::fseek(f, 0, SEEK_SET);
    std::string all;
    all.resize((size_t)(sz > (1 << 20) ? (1 << 20) : sz));   // first 1 MB is enough
    const size_t got = std::fread(&all[0], 1, all.size(), f);
    std::fclose(f);
    const bool hasVec = all.find("VEC=LAYER_-1_FINAL_NORM") != std::string::npos;
    std::printf("PARITY_FILE=%s BYTES=%lld\n", out.c_str(), sz);
    std::printf("FINAL_NORM_VEC_PRESENT=%d\n", hasVec ? 1 : 0);
    if (!hasVec) {
        std::printf("CAPTURE=FAIL reason=final_norm_vec_absent\n"
                    "  enableParityProbeFullVectors(-3) did not produce a dump; "
                    "the gate must not treat this as a capture\n");
        return 7;
    }
    std::printf("CAPTURE=PASS\n");
    return 0;
}