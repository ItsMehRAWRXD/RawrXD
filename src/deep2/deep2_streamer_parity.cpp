/* deep2_streamer_parity.cpp — OLLAMA_PARITY_STREAMER_001 main (≤99). */
#include "StreamerParity_Harness.hpp"
#include "Deep2DeviceManager.hpp"
#include "lavapath/ParseMibBudget.hpp"
#include "lavapath/StreamerMechanicsReceipt.hpp"
#include "lavapath/FreeTokenMicroZone.hpp"
#include "lavapath/FutureConsumerSpace.hpp"
#include "lavapath/ImportSpace68.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

using Deep2::Deep2StreamParityObs;

int main(int argc, char** argv) {
    const char* model = nullptr;
    const char* prompt = "write one short paragraph about local inference.";
    uint32_t maxTok = 32;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--model") && i + 1 < argc)
            model = argv[++i];
        else if (!std::strcmp(argv[i], "--prompt") && i + 1 < argc)
            prompt = argv[++i];
        else if (!std::strcmp(argv[i], "--max-tokens") && i + 1 < argc)
            maxTok = (uint32_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--help")) {
            StreamerUsage();
            return 2;
        }
    }
    if (!model) { StreamerUsage(); return 2; }
    if (StreamerForbiddenArgExeScan(argc, argv) != 0) return 3;

    const auto import68 = Deep2Cert::ScanCurrentExeImports68();
    Deep2Cert::EmitImportSpace68Receipt(stderr, import68);
    Deep2Cert::EmitImportSpace68Receipt(stdout, import68);
    fprintf(stderr, "FORBIDDEN_IMPORT_SCAN=%s\n",
            Deep2Cert::ImportSpace68CertPass(import68) ? "PASS" : "FAIL");
    if (!Deep2Cert::ImportSpace68CertPass(import68)) {
        fprintf(stderr, "IMPORT_CERT_REQUIRED=1 PROMOTE=0\n");
        return 5;
    }

    Deep2::DualStickEnvSnapRequested();
    const char* armDs0 = std::getenv("DEEP2_DUALSTICK_ARM");
    Deep2::DualStickMarkRequested(!(armDs0 && armDs0[0] == '0'));

    if (!StreamerArmSpeedEnv()) return 4;
    Deep2::DualStickEnvSnapAfterHarness();

    Deep2::DeviceManagerSnapshot snap{};
    Deep2::MibParseResult bud =
        Deep2::ParseMibTokenEx(std::getenv("DEEP2_WEIGHT_BUDGET_MIB"));
    if (Deep2::Deep2Device_Enumerate(snap)) {
        (void)Deep2::Deep2Device_ApplyPolicy(snap);
        Deep2::EmitGpuEnumReceipt(stderr, snap);
        Deep2::EmitGpuEnumReceipt(stdout, snap);
        const char* armDs = std::getenv("DEEP2_DUALSTICK_ARM");
        const int skipDs = (armDs && armDs[0] == '0');
        if (!skipDs) {
            Deep2::DualStickWindowPlan wp =
                Deep2::PlanDualStickWindows(snap, bud.bytes);
            Deep2::ArmDualStickNoTruncate(wp);
            Deep2::DualStickEnvSnapAfterDualstick();
            Deep2::EmitDualStickWindowReceipt(stderr, wp);
            Deep2::EmitDualStickWindowReceipt(stdout, wp);
        } else {
            fprintf(stderr, "DUALSTICK_ARM_SKIP=1\n");
            fprintf(stdout, "DUALSTICK_ARM_SKIP=1\n");
            Deep2::DualStickEnvSnapAfterDualstick();
        }
        Deep2::EmitDualStickEnvAuthority(stderr);
        Deep2::EmitDualStickEnvAuthority(stdout);
        Deep2::EmitDualStickMechanics(stderr);
        Deep2::EmitDualStickMechanics(stdout);
    }

    Deep2::freetoken::Init(FREETOKEN_ZONE_BYTES, 4);
    Deep2::future::InitFromPhysicalPool();
    Deep2::future::EmitLaw(stderr);
    Deep2::future::EmitLaw(stdout);
    Deep2::future::MarkGenerateBegin();

    uint32_t cbN = 0;
    Deep2StreamParityObs obs{};
    const bool ok =
        Deep2::Deep2GenerateStream(model, prompt, StreamerOnEv, &cbN, &obs,
                                   maxTok);
    fputc('\n', stdout);
    fflush(stdout);
    if (obs.rc == 0 && !ok) obs.rc = 1;

    StreamerEmitPostGenerate(obs, model, maxTok);
    return StreamerRuntimePass(obs) ? 0 : 1;
}
