#pragma once
// =============================================================================
// Module 7: Glue — minimal engine interface stub
// Shows how Modules 1-6 connect. Replace Deep2Engine with your real engine.
// =============================================================================

#include <functional>

// Include all modules
#include "module1_types.h"
#include "module2_cancel.h"
#include "module3_utf8.h"
#include "module4_stopstring.h"
#include "module5_context.h"
#include "module6_generate.h"

// --- Engine interface ---
// Your real engine implements this. The generate() method takes
// 3 callbacks. The signature is:
//   bool generate(const char* prompt,
//                 TokenCallback       tokenCb,
//                 ErrorCallback       engineErrorCb,
//                 ErrorCallback       nonEngineErrorCb);
//
class Deep2Engine {
public:
    bool isReady() const {
        return ready_;
    }

    void setReady(bool r) {
        ready_ = r;
    }

    bool generate(
        const char* prompt,
        const TokenCallback&   tokenCb,
        const ErrorCallback&   engineErrorCb,
        const ErrorCallback&   nonEngineErrorCb
    ) {
        // --- Your real implementation here ---
        // This stub simulates a few tokens then stops.
        //
        // Return true = success, false = failure.
        // Call tokenCb(tokenStr, idx) per token.
        // Call engineErrorCb(msg) on engine failure.
        // Call nonEngineErrorCb(msg) on non-engine failure.
        //
        // NEVER throw from callbacks — the caller catches nothing.
        // NEVER call any callback after returning.
        // NEVER call any callback from a different thread than the
        //   thread that called generate().
        //
        tokenCb("Hello", 0);
        tokenCb(" world", 1);
        return true;  // placeholder
    }

private:
    bool ready_ = false;
};

// --- Convenience wrapper ---
// One-call interface that hides CancelSource from the caller.
GenerationResult generate(
    Deep2Engine* engine,
    const GenerateParams& params
) {
    CancelSource cancelSource;
    return generateRobust(engine, params, cancelSource);
}

// --- With external cancel ---
// Caller holds CancelSource and can call requestStop() from any thread.
GenerationResult generate(
    Deep2Engine* engine,
    const GenerateParams& params,
    CancelSource& cancelSource
) {
    return generateRobust(engine, params, cancelSource);
}