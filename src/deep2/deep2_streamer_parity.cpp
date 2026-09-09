/* deep2_streamer_parity.cpp — OLLAMA_PARITY_STREAMER_001 main (≤99). */
#include "StreamerParity_Harness.hpp"
#include "OllamaParityReceipt.hpp"
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
    if (!StreamerArmSpeedEnv()) return 4;

    Deep2::DeviceManagerSnapshot snap{};
    Deep2::MibParseResult bud =
        Deep2::ParseMibTokenEx(std::getenv("DEEP2_WEIGHT_BUDGET_MIB"));
    if (Deep2::Deep2Device_Enumerate(snap)) {
        (void)Deep2::Deep2Device_ApplyPolicy(snap);
        Deep2::EmitGpuEnumReceipt(stderr, snap);
        Deep2::EmitGpuEnumReceipt(stdout, snap);
        Deep2::DualStickWindowPlan wp =
            Deep2::PlanDualStickWindows(snap, bud.bytes);
        Deep2::ArmDualStickNoTruncate(wp);
        Deep2::EmitDualStickWindowReceipt(stderr, wp);
        Deep2::EmitDualStickWindowReceipt(stdout, wp);
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

    Deep2::future::EmitExec(stderr, obs.tokensEmitted, obs.rc);
    Deep2::future::EmitExec(stdout, obs.tokensEmitted, obs.rc);
    fprintf(stderr, "STREAMER_TPS=%.3f TTFT_MS=%.3f TOKENS=%u PATH=%s\n",
            obs.decodeTps, obs.ttftMs, obs.tokensEmitted,
            obs.modelPath ? obs.modelPath : model);
    fprintf(stderr, "HOST_DECODE=%s\nOLLAMA_HTTP=0\n",
            std::getenv("RAWRXD_HOST_DECODE")
                ? std::getenv("RAWRXD_HOST_DECODE") : "0");

    Deep2::EmitFreeTokenMechanics(stderr);
    Deep2::EmitFreeTokenMechanics(stdout);
    Deep2::freetoken::EmitWitness(stderr);
    Deep2::EmitDualStickMechanics(stderr);
    Deep2::EmitDualStickMechanics(stdout);
    Deep2::EmitOllamaParityReceipt(stderr, obs, model);
    Deep2::EmitOllamaParityReceipt(stdout, obs, model);
    const int runtimePass = (obs.tokensEmitted >= 15 && obs.rc == 0) ? 1 : 0;
    Deep2::EmitDisposition(stderr, runtimePass, maxTok, obs.tokensEmitted,
                           obs.rc);
    Deep2::EmitDisposition(stdout, runtimePass, maxTok, obs.tokensEmitted,
                           obs.rc);
    return runtimePass ? 0 : 1;
}
