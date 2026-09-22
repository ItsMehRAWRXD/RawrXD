// compression_factory_stub.cpp
// Minimal stub implementation for CompressionFactory::Create to satisfy linker
// until real compression providers are wired in.

#include "autonomous_model_manager.h"
#include <memory>

class NullCompressionProvider : public ICompressionProvider {
public:
    bool IsSupported() const override { return false; }
    std::string GetActiveKernel() const override { return "none"; }
};

std::shared_ptr<ICompressionProvider> CompressionFactory::Create(int /*level*/) {
    return std::make_shared<NullCompressionProvider>();
}
