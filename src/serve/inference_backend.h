#pragma once
#include "wire_format.h"
#include <string>

namespace RawrXD::Serve {

// ============================================================================
// Abstract inference backend
// ============================================================================
class InferenceBackend {
public:
    virtual ~InferenceBackend() = default;
    virtual bool loadModel(const std::string& ggufPath) = 0;
    virtual bool isLoaded() const = 0;
    virtual std::string loadedModelName() const = 0;

    // Blocking generation with streaming callback
    virtual void generate(
        const GenerateRequest& req,
        TokenCallback cb) = 0;
};

// ============================================================================
// RawrEngine adapter — wraps the existing engine
// ============================================================================
class RawrEngineBackend : public InferenceBackend {
public:
    bool loadModel(const std::string& ggufPath) override;
    bool isLoaded() const override { return m_loaded; }
    std::string loadedModelName() const override { return m_modelName; }
    void generate(
        const GenerateRequest& req,
        TokenCallback cb) override;

private:
    bool m_loaded = false;
    std::string m_modelName;
};

} // namespace RawrXD::Serve
