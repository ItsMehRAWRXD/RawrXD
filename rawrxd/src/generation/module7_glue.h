#pragma once
// =============================================================================
// module7_glue.h
// =============================================================================
//
// RAWRXD_UNSIMULATE_001
//
// This header previously DEFINED a class named `Deep2Engine` whose generate()
// emitted the hardcoded tokens "Hello" and " world" and then `return true` --
// a success for every prompt, from a header whose own comment said
// "This stub simulates a few tokens then stops" and "Replace Deep2Engine with
// your real engine".
//
// It was not inert documentation. This header is part of the RawrXDGeneration
// interface target and is included by two integration adapters that speak to
// the real engine, so a translation unit could have satisfied the generation
// interface with a class of the production engine's name returning fabricated
// text. Both adapters now declare the abstract interface themselves
// (RawrXDEngineAdapter.h) or take an engine pointer they did not define
// (Deep2GenerationAdapter.h), so nothing needs a definition from here.
//
// The class is DELETED, not stubbed. A class that is present, has the right
// name and signature, and returns success without computing anything is worse
// than one that fails to link, because the link error is visible and the
// success is not.
//
// The engine interface the generation modules expect, for reference:
//
//   class Deep2Engine {
//   public:
//       virtual ~Deep2Engine() {}
//       virtual bool isReady() const = 0;
//       virtual bool generate(const char* prompt,
//                             const TokenCallback&   tokenCb,
//                             const ErrorCallback&   engineErrorCb,
//                             const ErrorCallback&   nonEngineErrorCb) = 0;
//   };
//
// Implementations must:
//
//   * return true only after the tokens were actually produced;
//   * call tokenCb(tokenStr, idx) once per generated token;
//   * call engineErrorCb(msg) on engine failure, nonEngineErrorCb(msg) on
//     non-engine failure;
//   * never throw from a callback -- the caller catches nothing;
//   * never call a callback after returning;
//   * never call a callback from a thread other than the caller's.
//
// Include all modules
#include "module1_types.h"
#include "module2_cancel.h"
#include "module3_utf8.h"
#include "module4_stopstring.h"
#include "module5_context.h"
#include "module6_generate.h"

// --- Convenience wrapper ---
// One-call interface that hides CancelSource from the caller.
//
// Templated rather than spelled `Deep2Engine*` on purpose. The engine class
// this header used to define is gone, and these wrappers must not be what
// reintroduces it: a template is not instantiated until a caller supplies a
// complete engine type, so the header can no longer decide what an engine is.
// The type each adapter uses is declared by that adapter.
template <class EngineT>
inline GenerationResult generate(
    EngineT* engine,
    const GenerateParams& params
) {
    CancelSource cancelSource;
    return generateRobust(engine, params, cancelSource);
}

// --- With external cancel ---
// Caller holds CancelSource and can call requestStop() from any thread.
template <class EngineT>
inline GenerationResult generate(
    EngineT* engine,
    const GenerateParams& params,
    CancelSource& cancelSource
) {
    return generateRobust(engine, params, cancelSource);
}