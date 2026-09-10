/* StreamerParity_Post.cpp — post-generate receipts (survive gate). */
#include "StreamerParity_Harness.hpp"
#include "OllamaParityReceipt.hpp"
#include "lavapath/StreamerMechanicsReceipt.hpp"
#include "lavapath/FreeTokenMicroZone.hpp"
#include "lavapath/FutureConsumerSpace.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include <cstdio>
#include <cstdlib>

void StreamerEmitPostGenerate(const Deep2::Deep2StreamParityObs& obs,
                              const char* model, uint32_t maxTok) {
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
    /* Survive gate: FutureConsumer/FreeToken must have real work, not a constant. */
    const int fcExec =
        (Deep2::freetoken::Pool().overwrites > 0 ||
         Deep2::freetoken::Pool().hits > 0 ||
         Deep2::DualStickState().runtimeBytesWorked > 0)
            ? 1
            : 0;
    Deep2::EmitGenerationSurvive(stderr, obs.modelOpen, obs.tokensEmitted,
                                 obs.generationReturnedNormally, obs.rc,
                                 fcExec);
    Deep2::EmitGenerationSurvive(stdout, obs.modelOpen, obs.tokensEmitted,
                                 obs.generationReturnedNormally, obs.rc,
                                 fcExec);
    Deep2::EmitOllamaParityReceipt(stderr, obs, model);
    Deep2::EmitOllamaParityReceipt(stdout, obs, model);
    const int runtimePass = (obs.tokensEmitted >= 15 && obs.rc == 0 &&
                             obs.generationReturnedNormally) ? 1 : 0;
    Deep2::EmitDisposition(stderr, runtimePass, maxTok, obs.tokensEmitted,
                           obs.rc);
    Deep2::EmitDisposition(stdout, runtimePass, maxTok, obs.tokensEmitted,
                           obs.rc);
}

int StreamerRuntimePass(const Deep2::Deep2StreamParityObs& obs) {
    return (obs.tokensEmitted >= 15 && obs.rc == 0 &&
            obs.generationReturnedNormally) ? 1 : 0;
}
