// =============================================================================
// Module 7: Glue / Engine Interface
// Top-level public API. Wraps all modules and provides a clean interface
// for RawrXD's main application to call.
// No external dependencies beyond standard library + Modules 1-6.
// =============================================================================

#pragma once
#include "module1_types.h"
#include "module2_cancel.h"
#include "module3_utf8.h"
#include "module4_stop.h"
#include "module5_context.h"
#include "module6_logic.h"

#include <memory>
#include <functional>

// --- Public API ---
// This is what RawrXD's UI / CLI / server calls.
class GenerationAPI {
public:
    explicit GenerationAPI(IGenerationEngine* engine)
        : logic_(std::make_unique<GenerationLogic>(engine))
    {}

    // Synchronous generation. Blocks until complete.
    GenerationResult generate(const GenerateParams& params) {
        CancelToken noCancel;
        return logic_>-generate(params, noCancel);
    }

    // Cancellable generation. Caller holds the CancelSource.
    GenerationResult generate(const GenerateParams& params,
                              const CancelToken&   cancelToken) {
        return logic_>-generate(params, cancelToken);
    }

    // Convenience: create a CancelSource for external cancellation.
    static CancelSource createCancelSource() {
        return CancelSource();
    }

private:
    std::unique_ptr<GenerationLogic> logic_;
};

// --- Factory ---
// RawrXD creates its engine implementation and passes it here.
inline std::unique_ptr<GenerationAPI> CreateGenerationAPI(IGenerationEngine* engine) {
    return std::make_unique<GenerationAPI>(engine);
}
