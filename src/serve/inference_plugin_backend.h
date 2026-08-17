// ============================================================================
// inference_plugin_backend.h
// ============================================================================
// Adapter: implements IInferenceBackend by delegating to the existing
// RawrXD::Serve::InferencePlugin DLL bridge.  This unifies the runtime's
// abstract backend interface with the concrete plugin-based inference path
// already used by rawrxd-serve, without inventing a third abstraction.
// ============================================================================
#pragma once

#include "rawrxd_serve.h"
#include "../runtime/shared/SharedModelRuntime.hpp"

namespace RawrXD {
namespace Serve {

class InferencePluginBackend : public Shared::IInferenceBackend {
public:
    InferencePluginBackend() = default;
    ~InferencePluginBackend() override = default;

    bool loadModel(const std::string& path) override;
    void unloadModel() override;
    bool ready() const override;
    std::string generate(const GenerateRequest& request,
                         StreamTokenFn stream) override;
};

} // namespace Serve
} // namespace RawrXD
