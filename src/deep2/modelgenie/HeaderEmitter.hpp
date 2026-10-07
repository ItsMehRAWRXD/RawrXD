//=============================================================================
// HeaderEmitter - Code Generation from ModelGenome
// RAWRXD_MODEL_GENIE_HEADER_EXPORT_001
//
// Generates declarative headers, NOT model-specific handwritten C++.
//=============================================================================

#pragma once

#include "ModelGenome.hpp"
#include <string>
#include <fstream>
#include <unordered_set>
#include <unordered_map>

namespace RawrXD {
namespace Deep2 {
namespace ModelGenie {

class HeaderEmitter {
public:
    explicit HeaderEmitter(const std::string& outputDir);
    
    // Generate all headers for a model
    bool EmitAll(const ModelGenome& genome);
    
    // Individual header generation
    bool EmitModelIdentity(const ModelGenome& genome);
    bool EmitModelConfig(const ModelGenome& genome);
    bool EmitTensorROM(const ModelGenome& genome);
    bool EmitBlockGenome(const ModelGenome& genome);
    bool EmitExecutionIR(const ModelGenome& genome);
    bool EmitCapabilityManifest(const ModelGenome& genome);
    bool EmitResidencyPlan(const ModelGenome& genome);
    bool EmitModelExport(const ModelGenome& genome);
    
    // SSA/Domain validation (called before EmitExecutionIR)
    bool ValidateExecutionIR(const ModelGenome& genome);

private:
    std::string outputDir_;
    
    // Helper: Open output file with header guard
    std::ofstream OpenHeader(const std::string& filename, const std::string& guardName);
    
    // Helper: Write common preamble
    void WritePreamble(std::ofstream& out, const std::string& guardName, const std::string& description);
    
    // Helpers for specific types
    std::string FormatDims(const std::array<uint32_t, 4>& dims);
    std::string FormatTensorRole(TensorRole role);
    std::string FormatOpCode(OpCode opcode);
    std::string FormatPrimitive(Primitive prim);
    std::string FormatOperandDomain(OperandDomain domain);
    std::string FormatOperandRef(const OperandRef& ref);
    std::string FormatArchitecture(Architecture arch);
    std::string FormatRopeScaling(RopeScalingType scaling);
    std::string FormatWeightTying(WeightTying tying);
    
    // Indentation
    void Indent(std::ofstream& out, int level);
};

} // namespace ModelGenie
} // namespace Deep2
} // namespace RawrXD