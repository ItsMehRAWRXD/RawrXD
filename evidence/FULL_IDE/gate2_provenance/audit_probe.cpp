#include "QuantParityRegistry.h"
namespace RawrXD::Deep2::Generated { using ModelGenie::Primitive; }
#include "CapabilityManifest.generated.hpp"
#include <cstdio>

int main() {
    namespace MG = RawrXD::Deep2::ModelGenie;
    using Registry = RawrXD::Deep2::QuantParityRegistry;
    MG::ModelGenome unknown;
    unknown.capabilities.requiredPrimitives = {static_cast<MG::Primitive>(0xffff)};
    const bool admitted = Registry::RuntimeExecutable(unknown);
    const auto mla = Registry::GatePrimitive(MG::Primitive::MlaDecompressFwd);
    const auto& generated = RawrXD::Deep2::Generated::kCapabilityManifest;
    std::printf("unknown_required_admitted=%d expected=0\n", int(admitted));
    std::printf("registry_mla_available=%d registry_mla_present=%d\n", int(mla.available), int(mla.kernelPresent));
    std::printf("generated_unimplemented_count=%u generated_first_unimplemented=%u generated_runtime_executable=%d\n", generated.unimplementedCount, unsigned(generated.firstUnimplementedPrimitive), int(generated.runtimeExecutable));
    return admitted ? 1 : 0;
}
