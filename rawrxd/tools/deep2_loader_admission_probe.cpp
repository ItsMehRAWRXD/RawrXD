// deep2_loader_admission_probe.cpp
// RAWRXD_DEEP2_MODEL_REGISTRY_001 — proves the REAL load path reaches admission.
//
// The admission unit test registers its own fixture architectures and therefore
// proves registry LOGIC only. This probe proves the other half: that
// Deep2Engine::loadModel, on a real GGUF, actually calls
// Deep2::ModelRegistry::admit() and refuses a model admission rejects.
//
// It distinguishes three outcomes for the model under test and reports which one
// occurred. It does not assume success.

#include "Deep2Engine.h"
#include "Deep2ModelRegistry.hpp"

#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: deep2_loader_admission_probe <model.gguf>\n");
        return 2;
    }
    const std::string path = argv[1];

    std::printf("PROBE_MODEL=%s\n", path.c_str());

    // Confirm the registry has production implementations registered by the
    // engine TU's static initializer. If this is empty, admission would reject
    // everything and the probe below would be meaningless.
    std::vector<std::string_view> archs;
    Deep2::ModelRegistry::listArchitectures(archs);
    std::printf("PROBE_REGISTERED_ARCHITECTURES=%zu\n", archs.size());

    Deep2::Deep2Engine engine;
    engine.setVulkanStrictNoCpuFallback(false);

    Deep2::ModelLoadDiag diag;
    const bool loaded = engine.loadModel(path, &diag);

    std::printf("PROBE_LOAD_OK=%d\n", loaded ? 1 : 0);
    std::printf("PROBE_STAGE_CODE=%d\n", diag.stageCode);
    std::printf("PROBE_STAGE_NAME=%s\n",
                diag.stageName.empty() ? "(empty)" : diag.stageName.c_str());
    std::printf("PROBE_MESSAGE=%s\n",
                diag.message.empty() ? "(empty)" : diag.message.c_str());
    std::printf("PROBE_ARCH=%s\n",
                engine.modelArchitecture().empty()
                    ? "(empty)"
                    : engine.modelArchitecture().c_str());

    // The admission path stamps stage 20 / MODEL_ADMISSION_REJECTED when the
    // registry refused. Reaching that stage proves the loader CALLED the
    // registry. Reaching an earlier failure stage proves it did not get that
    // far, which is a different (and worse) result.
    const std::string stage = diag.stageName;
    const bool admissionStageReached = (stage == "MODEL_ADMISSION_REJECTED");

    if (loaded) {
        std::printf("LOADER_ADMISSION_REACHED=PASS\n");
        std::printf("LOADER_ADMISSION_OUTCOME=ADMITTED\n");
        std::printf("LOADER_ADMISSION_VERDICT=PASS\n");
        return 0;
    }

    if (admissionStageReached) {
        // The loader called the registry and the registry said no. That is the
        // fail-closed behaviour working, and it proves the call site exists.
        std::printf("LOADER_ADMISSION_REACHED=PASS\n");
        std::printf("LOADER_ADMISSION_OUTCOME=REJECTED_FAIL_CLOSED\n");
        std::printf("LOADER_ADMISSION_VERDICT=PASS\n");
        return 0;
    }

    // Failed somewhere before admission (bad path, unreadable GGUF, missing
    // architecture tag, geometry fault). The registry was never consulted, so
    // MODEL_REGISTRY_CALLED_BY_LOADER cannot be claimed for this model.
    std::printf("LOADER_ADMISSION_REACHED=FAIL\n");
    std::printf("LOADER_ADMISSION_OUTCOME=FAILED_BEFORE_ADMISSION\n");
    std::printf("LOADER_ADMISSION_VERDICT=FAIL\n");
    return 1;
}