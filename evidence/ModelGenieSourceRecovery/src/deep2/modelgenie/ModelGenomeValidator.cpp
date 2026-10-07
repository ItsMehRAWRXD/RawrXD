//=============================================================================
// ModelGenomeValidator - Completeness and Correctness Checks
// RAWRXD_MODEL_GENIE_HEADER_EXPORT_001
//=============================================================================

#include "ModelGenome.hpp"
#include <iostream>
#include <set>

namespace RawrXD {
namespace Deep2 {
namespace ModelGenie {

//=============================================================================
// Helpers
//=============================================================================

struct ValidationResult {
    bool valid = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    
    void AddError(const std::string& msg) {
        valid = false;
        errors.push_back(msg);
    }
    
    void AddWarning(const std::string& msg) {
        warnings.push_back(msg);
    }
};

static void ValidateArchitectureParams(const ModelGenome& genome, ValidationResult& result) {
    if (genome.blockCount == 0) result.AddError("blockCount is zero");
    if (genome.embeddingLength == 0) result.AddError("embeddingLength is zero");
    if (genome.vocabSize == 0) result.AddError("vocabSize is zero");
    if (genome.headCount == 0) result.AddError("headCount is zero");
    if (genome.headCountKv == 0) result.AddError("headCountKv is zero");
    if (genome.ropeFreqBase == 0) result.AddError("ropeFreqBase is zero");
    if (genome.rmsEps <= 0.0) result.AddError("rmsEps is non-positive");
    
    if (genome.kvLoraRank == 0) result.AddWarning("kvLoraRank is zero (no MLA)");
    if (genome.keyLength == 0) result.AddWarning("keyLength is zero");
    if (genome.valueLength == 0) result.AddWarning("valueLength is zero");
    
    if (genome.expertCount > 0) {
        if (genome.expertUsedCount == 0) result.AddError("expertCount > 0 but expertUsedCount is zero");
        if (genome.expertUsedCount > genome.expertCount) result.AddError("expertUsedCount > expertCount");
        if (genome.expertFfnLength == 0) result.AddError("expertCount > 0 but expertFfnLength is zero");
        if (genome.leadingDenseBlocks >= genome.blockCount) result.AddError("leadingDenseBlocks >= blockCount");
    }
}

static void ValidateTensorDirectory(const ModelGenome& genome, ValidationResult& result) {
    if (genome.tensors.empty()) {
        result.AddError("Tensor directory is empty");
        return;
    }
    
    // Check tensor ID continuity
    for (size_t i = 0; i < genome.tensors.size(); ++i) {
        if (genome.tensors[i].tensorId != i) {
            result.AddError("Tensor ID discontinuity at index " + std::to_string(i));
        }
    }
    
    // Check required tensors exist
    bool hasEmbed = false, hasOutput = false, hasOutputNorm = false;
    for (const auto& t : genome.tensors) {
        if (t.name == "token_embd.weight") hasEmbed = true;
        if (t.name == "output.weight") hasOutput = true;
        if (t.name == "output_norm.weight") hasOutputNorm = true;
    }
    
    if (!hasEmbed) result.AddError("Missing token_embd.weight");
    if (!hasOutput) result.AddError("Missing output.weight");
    if (!hasOutputNorm) result.AddError("Missing output_norm.weight");
    
    // Check tensor count matches
    if (genome.tensorCount != genome.tensors.size()) {
        result.AddError("tensorCount (" + std::to_string(genome.tensorCount) + 
                       ") != actual tensor count (" + std::to_string(genome.tensors.size()) + ")");
    }
    
    // Check block index bounds
    for (const auto& t : genome.tensors) {
        if (t.blockIndex >= static_cast<int32_t>(genome.blockCount)) {
            result.AddError("Tensor " + t.name + " has invalid blockIndex " + std::to_string(t.blockIndex));
        }
    }
    
    // Check element counts match dims
    for (const auto& t : genome.tensors) {
        uint64_t computed = ComputeElementCount(t.dims);
        if (t.elementCount != computed && computed > 0) {
            result.AddWarning("Tensor " + t.name + " elementCount mismatch: declared=" + 
                            std::to_string(t.elementCount) + " computed=" + std::to_string(computed));
        }
    }
}

static void ValidateBlockGenomes(const ModelGenome& genome, ValidationResult& result) {
    if (genome.blocks.size() != genome.blockCount) {
        result.AddError("blocks.size() (" + std::to_string(genome.blocks.size()) + 
                       ") != blockCount (" + std::to_string(genome.blockCount) + ")");
        return;
    }
    
    for (uint32_t i = 0; i < genome.blockCount; ++i) {
        const auto& block = genome.blocks[i];
        
        if (block.blockIndex != i) {
            result.AddError("Block " + std::to_string(i) + " has wrong blockIndex " + 
                           std::to_string(block.blockIndex));
        }
        
        if (i < genome.leadingDenseBlocks) {
            // Dense block validation
            if (!block.attnNorm) result.AddError("Block " + std::to_string(i) + " missing attnNorm");
            if (!block.ffnNorm) result.AddError("Block " + std::to_string(i) + " missing ffnNorm");
            if (!block.attnKvANorm) result.AddError("Block " + std::to_string(i) + " missing attnKvANorm");
            if (!block.attnKvAMqa) result.AddError("Block " + std::to_string(i) + " missing attnKvAMqa");
            if (!block.attnKvB) result.AddError("Block " + std::to_string(i) + " missing attnKvB");
            if (!block.attnOutput) result.AddError("Block " + std::to_string(i) + " missing attnOutput");
            if (!block.attnQ) result.AddError("Block " + std::to_string(i) + " missing attnQ");
            if (!block.ffnDown) result.AddError("Block " + std::to_string(i) + " missing ffnDown");
            if (!block.ffnGate) result.AddError("Block " + std::to_string(i) + " missing ffnGate");
            if (!block.ffnUp) result.AddError("Block " + std::to_string(i) + " missing ffnUp");
        } else {
            // MoE block validation
            if (!block.attnNorm) result.AddError("Block " + std::to_string(i) + " missing attnNorm");
            if (!block.ffnNorm) result.AddError("Block " + std::to_string(i) + " missing ffnNorm");
            if (!block.attnKvANorm) result.AddError("Block " + std::to_string(i) + " missing attnKvANorm");
            if (!block.attnKvAMqa) result.AddError("Block " + std::to_string(i) + " missing attnKvAMqa");
            if (!block.attnKvB) result.AddError("Block " + std::to_string(i) + " missing attnKvB");
            if (!block.attnOutput) result.AddError("Block " + std::to_string(i) + " missing attnOutput");
            if (!block.attnQ) result.AddError("Block " + std::to_string(i) + " missing attnQ");
            if (!block.ffnDownExps) result.AddError("Block " + std::to_string(i) + " missing ffnDownExps");
            if (!block.ffnGateExps) result.AddError("Block " + std::to_string(i) + " missing ffnGateExps");
            if (!block.ffnUpExps) result.AddError("Block " + std::to_string(i) + " missing ffnUpExps");
            if (!block.ffnGateInp) result.AddError("Block " + std::to_string(i) + " missing ffnGateInp (router)");
            if (!block.ffnDownShExp) result.AddError("Block " + std::to_string(i) + " missing ffnDownShExp");
            if (!block.ffnGateShExp) result.AddError("Block " + std::to_string(i) + " missing ffnGateShExp");
            if (!block.ffnUpShExp) result.AddError("Block " + std::to_string(i) + " missing ffnUpShExp");
        }
    }
}

static void ValidateExpertBanks(const ModelGenome& genome, ValidationResult& result) {
    if (genome.expertCount == 0) return;
    
    uint32_t expectedMoEBlocks = genome.blockCount - genome.leadingDenseBlocks;
    if (genome.expertBanks.size() != expectedMoEBlocks) {
        result.AddError("expertBanks.size() (" + std::to_string(genome.expertBanks.size()) + 
                       ") != expected MoE blocks (" + std::to_string(expectedMoEBlocks) + ")");
    }
    
    for (size_t i = 0; i < genome.expertBanks.size(); ++i) {
        const auto& bank = genome.expertBanks[i];
        
        if (bank.routedExpertCount != genome.expertCount) {
            result.AddError("Expert bank " + std::to_string(i) + " routedExpertCount mismatch");
        }
        if (bank.activeExpertCount != genome.expertUsedCount) {
            result.AddError("Expert bank " + std::to_string(i) + " activeExpertCount mismatch");
        }
        if (bank.sharedExpertCount != genome.expertSharedCount) {
            result.AddError("Expert bank " + std::to_string(i) + " sharedExpertCount mismatch");
        }
        if (bank.routerTensorId == 0) result.AddError("Expert bank " + std::to_string(i) + " missing router");
        
        if (bank.routedDownTensorIds.size() != genome.expertCount) {
            if (bank.routedDownTensorIds.size() == 1) {
                result.AddWarning("Expert bank " + std::to_string(i) + " routedDown packed (1 tensor for " + std::to_string(genome.expertCount) + " experts)");
            } else {
                result.AddWarning("Expert bank " + std::to_string(i) + " routedDown size (" + std::to_string(bank.routedDownTensorIds.size()) + ") != expertCount (" + std::to_string(genome.expertCount) + ")");
            }
        }
        if (bank.routedGateTensorIds.size() != genome.expertCount) {
            if (bank.routedGateTensorIds.size() == 1) {
                result.AddWarning("Expert bank " + std::to_string(i) + " routedGate packed (1 tensor for " + std::to_string(genome.expertCount) + " experts)");
            } else {
                result.AddWarning("Expert bank " + std::to_string(i) + " routedGate size (" + std::to_string(bank.routedGateTensorIds.size()) + ") != expertCount (" + std::to_string(genome.expertCount) + ")");
            }
        }
        if (bank.routedUpTensorIds.size() != genome.expertCount) {
            if (bank.routedUpTensorIds.size() == 1) {
                result.AddWarning("Expert bank " + std::to_string(i) + " routedUp packed (1 tensor for " + std::to_string(genome.expertCount) + " experts)");
            } else {
                result.AddWarning("Expert bank " + std::to_string(i) + " routedUp size (" + std::to_string(bank.routedUpTensorIds.size()) + ") != expertCount (" + std::to_string(genome.expertCount) + ")");
            }
        }
    }
}

static void ValidateExecutionIR(const ModelGenome& genome, ValidationResult& result) {
    if (genome.executionOps.empty()) {
        result.AddError("Execution IR is empty");
        return;
    }
    
    // Check opId continuity
    for (size_t i = 0; i < genome.executionOps.size(); ++i) {
        if (genome.executionOps[i].opId != i) {
            result.AddWarning("Operation " + std::to_string(i) + " has non-sequential opId " + 
                             std::to_string(genome.executionOps[i].opId));
        }
    }
    
    // Check MLA_DECOMPRESS exists
    bool hasMlaDecompress = false;
    for (const auto& op : genome.executionOps) {
        if (op.opcode == OpCode::MlaDecompress) {
            hasMlaDecompress = true;
            if (op.requiredPrimitive != Primitive::MlaDecompressFwd) {
                result.AddError("MLA_DECOMPRESS op missing requiredPrimitive MlaDecompressFwd");
            }
        }
    }
    if (!hasMlaDecompress) result.AddError("No MLA_DECOMPRESS operation in Execution IR");
    
    // Check all required primitives have corresponding ops
    std::set<Primitive> seenPrimitives;
    for (const auto& op : genome.executionOps) {
        seenPrimitives.insert(op.requiredPrimitive);
    }
    
    for (const auto& req : genome.capabilities.requiredPrimitives) {
        if (seenPrimitives.find(req) == seenPrimitives.end()) {
            result.AddWarning("Required primitive " + std::to_string(static_cast<int>(req)) + 
                             " has no corresponding operation");
        }
    }
}

static void ValidateCapabilityManifest(const ModelGenome& genome, ValidationResult& result) {
    if (genome.capabilities.firstUnimplementedPrimitive == Primitive::None) {
        result.AddError("firstUnimplementedPrimitive not set");
    }
    
    if (genome.capabilities.unimplementedPrimitives.empty()) {
        result.AddError("No unimplemented primitives declared");
    }
    
    // Verify MLA_DECOMPRESS is in unimplemented
    bool hasMla = false;
    for (auto p : genome.capabilities.unimplementedPrimitives) {
        if (p == Primitive::MlaDecompressFwd) hasMla = true;
    }
    if (!hasMla) result.AddError("MLA_DECOMPRESS_FORWARD not in unimplemented primitives");
    
    if (genome.capabilities.runtimeExecutable) {
        result.AddError("runtimeExecutable should be false (MLA missing)");
    }
}

static void ValidateResidencyBounds(const ModelGenome& genome, ValidationResult& result) {
    if (genome.residencyBounds.maxBlockBytes == 0) result.AddError("maxBlockBytes is zero");
    if (genome.residencyBounds.meanBlockBytes == 0) result.AddError("meanBlockBytes is zero");
    if (genome.residencyBounds.maxPinnedTensorBytes == 0) result.AddError("maxPinnedTensorBytes is zero");
    
    if (genome.expertCount > 0) {
        if (genome.residencyBounds.expertRomBytes == 0) result.AddError("expertRomBytes is zero with MoE");
        if (genome.residencyBounds.maxExpertBlockBytes == 0) result.AddError("maxExpertBlockBytes is zero with MoE");
    }
    
    // These were NUGV findings
    if (genome.residencyBounds.uniformTensorSlotsSufficient) {
        result.AddWarning("uniformTensorSlotsSufficient=true (NUGV proved false)");
    }
    if (genome.residencyBounds.meanBlockCapacitySafe) {
        result.AddWarning("meanBlockCapacitySafe=true (NUGV proved false)");
    }
}

bool ValidateModelGenome(const ModelGenome& genome, ValidationResult& result) {
    std::cout << "Validating ModelGenome: " << genome.modelName << " (" 
              << ArchitectureToString(genome.architecture) << ")" << std::endl;
    
    ValidateArchitectureParams(genome, result);
    ValidateTensorDirectory(genome, result);
    ValidateBlockGenomes(genome, result);
    ValidateExpertBanks(genome, result);
    ValidateExecutionIR(genome, result);
    ValidateCapabilityManifest(genome, result);
    ValidateResidencyBounds(genome, result);
    
    if (result.valid) {
        std::cout << "Validation PASSED" << std::endl;
    } else {
        std::cout << "Validation FAILED with " << result.errors.size() << " errors" << std::endl;
    }
    
    for (const auto& w : result.warnings) {
        std::cout << "  WARNING: " << w << std::endl;
    }
    for (const auto& e : result.errors) {
        std::cout << "  ERROR: " << e << std::endl;
    }
    
    return result.valid;
}

} // namespace ModelGenie
} // namespace Deep2
} // namespace RawrXD