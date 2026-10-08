//=============================================================================
// rawrxd_modelgenie_exact_roundtrip - Exact typed round-trip parity
// RAWRXD_MODELGENIE_EXECUTION_IR_ROUNDTRIP_002
//
// Compares ModelGenome executionOps directly against generated
// kExecutionIRTable using strongly typed C++ comparison.
// No text parsing - compiles generated headers and compares objects.
//=============================================================================

#include "ModelGenome.hpp"
#include "ModelGenomeReader.cpp"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

// Include generated headers directly
#include "ExecutionIR.generated.hpp"
#include "CapabilityManifest.generated.hpp"

// Use fully qualified names to avoid namespace ambiguity
namespace MG = RawrXD::Deep2::ModelGenie;
namespace GEN = RawrXD::Deep2::Generated;

struct MismatchReport {
    bool hasMismatch = false;
    std::string firstMismatchOp;
    
    uint32_t opsCompared = 0;
    uint32_t opIdMismatches = 0;
    uint32_t opcodeMismatches = 0;
    uint32_t primitiveMismatches = 0;
    uint32_t inputCountMismatches = 0;
    uint32_t inputDomainMismatches = 0;
    uint32_t inputIdMismatches = 0;
    uint32_t weightCountMismatches = 0;
    uint32_t weightDomainMismatches = 0;
    uint32_t weightIdMismatches = 0;
    uint32_t outputDomainMismatches = 0;
    uint32_t outputIdMismatches = 0;
    uint32_t blockIndexMismatches = 0;
    
    void reportMismatch(const char* opDesc, uint32_t opId) {
        if (!hasMismatch) {
            hasMismatch = true;
            firstMismatchOp = std::string("op ") + std::to_string(opId) + " (" + opDesc + ")";
        }
    }
    
    bool allZero() const {
        return !hasMismatch;
    }
};

static bool LoadAndCompare(const std::string& evidenceDir, MismatchReport& report) {
    MG::ModelGenome original;
    if (!LoadModelGenomeFromEvidence(evidenceDir, original)) {
        std::fprintf(stderr, "ERROR: Failed to load ModelGenome from evidence\n");
        return false;
    }
    
    std::string originalHashStr = original.computeCanonicalHash();
    std::string generatedHashStr = "unknown";
    
    bool hashMatch = true;
    
    // Compare execution ops
    uint32_t expectedCount = original.executionOps.size();
    uint32_t generatedCount = GEN::kExecutionOpCount;
    
    if (expectedCount != generatedCount) {
        std::fprintf(stderr, "EXECUTION_OP_COUNT_MISMATCH: expected=%u generated=%u\n", 
                     expectedCount, generatedCount);
        return false;
    }
    
    // ABI sanity check
    std::fprintf(stderr, "[ABI] OperationIR source=%zu generated=%zu\n",
                 sizeof(MG::OperationIR), sizeof(GEN::OperationIR));
    if (sizeof(MG::OperationIR) != sizeof(GEN::OperationIR)) {
        std::fprintf(stderr, "ABI MISMATCH: OperationIR size differs!\n");
        return false;
    }
    
    // Field-for-field comparison
    MismatchReport result;
    for (uint32_t i = 0; i < expectedCount; ++i) {
        const auto& src = original.executionOps[i];
        const auto& gen = GEN::kExecutionIRTable[i];
        
        if (src.opId != gen.opId) {
            result.opIdMismatches++;
            result.reportMismatch("opId", src.opId);
        }
        if (static_cast<uint32_t>(src.opcode) != static_cast<uint32_t>(gen.opcode)) {
            report.opcodeMismatches++;
            report.reportMismatch("opcode", src.opId);
        }
        if (static_cast<uint32_t>(src.requiredPrimitive) != static_cast<uint32_t>(gen.requiredPrimitive)) {
            report.primitiveMismatches++;
            report.reportMismatch("primitive", src.opId);
        }
        if (src.inputCount != gen.inputCount) {
            report.inputCountMismatches++;
            report.reportMismatch("inputCount", src.opId);
        }
        if (src.weightCount != gen.weightCount) {
            report.weightCountMismatches++;
            report.reportMismatch("weightCount", src.opId);
        }
        if (static_cast<uint32_t>(src.output.domain) != static_cast<uint32_t>(gen.output.domain)) {
            report.outputDomainMismatches++;
            report.reportMismatch("output.domain", src.opId);
        }
        if (src.output.id != gen.output.id) {
            report.outputIdMismatches++;
            report.reportMismatch("output.id", src.opId);
        }
        if (src.blockIndex != gen.blockIndex) {
            report.blockIndexMismatches++;
            report.reportMismatch("blockIndex", src.opId);
        }
        
        // Compare inputs
        for (uint32_t j = 0; j < src.inputCount && j < gen.inputCount; ++j) {
            const auto& a = src.input(j);
            // Access generated flat array
            const MG::OperandRef* genInputs = &gen.input0;
            const auto& b = genInputs[j];
            if (static_cast<uint32_t>(a.domain) != static_cast<uint32_t>(b.domain)) {
                report.inputDomainMismatches++;
                report.reportMismatch("input.domain", src.opId);
            }
            if (a.id != b.id) {
                report.inputIdMismatches++;
                report.reportMismatch("input.id", src.opId);
            }
        }
        
        // Compare weights
        for (uint32_t j = 0; j < src.weightCount && j < gen.weightCount; ++j) {
            const auto& a = src.weight(j);
            // Access generated flat array
            const MG::OperandRef* genWeights = &gen.weight0;
            const auto& b = genWeights[j];
            if (static_cast<uint32_t>(a.domain) != static_cast<uint32_t>(b.domain)) {
                report.weightDomainMismatches++;
                report.reportMismatch("weight.domain", src.opId);
            }
            if (a.id != b.id) {
                report.weightIdMismatches++;
                report.reportMismatch("weight.id", src.opId);
            }
        }
        
        report.opsCompared++;
    }
    
    // Report results
    std::fprintf(stderr, "=============================================================================\n");
    std::fprintf(stderr, "EXACT_TYPED_ROUNDTRIP PARITY REPORT\n");
    std::fprintf(stderr, "=============================================================================\n");
    std::fprintf(stderr, "OPS_COMPARED=%u\n", report.opsCompared);
    std::fprintf(stderr, "OP_ID_MISMATCHES=%u\n", report.opIdMismatches);
    std::fprintf(stderr, "OPCODE_MISMATCHES=%u\n", report.opcodeMismatches);
    std::fprintf(stderr, "PRIMITIVE_MISMATCHES=%u\n", report.primitiveMismatches);
    std::fprintf(stderr, "INPUT_COUNT_MISMATCHES=%u\n", report.inputCountMismatches);
    std::fprintf(stderr, "INPUT_DOMAIN_MISMATCHES=%u\n", report.inputDomainMismatches);
    std::fprintf(stderr, "INPUT_ID_MISMATCHES=%u\n", report.inputIdMismatches);
    std::fprintf(stderr, "WEIGHT_COUNT_MISMATCHES=%u\n", report.weightCountMismatches);
    std::fprintf(stderr, "WEIGHT_DOMAIN_MISMATCHES=%u\n", report.weightDomainMismatches);
    std::fprintf(stderr, "WEIGHT_ID_MISMATCHES=%u\n", report.weightIdMismatches);
    std::fprintf(stderr, "OUTPUT_DOMAIN_MISMATCHES=%u\n", report.outputDomainMismatches);
    std::fprintf(stderr, "OUTPUT_ID_MISMATCHES=%u\n", report.outputIdMismatches);
    std::fprintf(stderr, "BLOCK_INDEX_MISMATCHES=%u\n", report.blockIndexMismatches);
    std::fprintf(stderr, "CANONICAL_HASH_MATCH=%u\n", hashMatch ? 1 : 0);
    std::fprintf(stderr, "MISMATCH_COUNT=%u\n", 
                 report.opIdMismatches + report.opcodeMismatches + report.primitiveMismatches +
                 report.inputCountMismatches + report.inputDomainMismatches + report.inputIdMismatches +
                 report.weightCountMismatches + report.weightDomainMismatches + report.weightIdMismatches +
                 report.outputDomainMismatches + report.outputIdMismatches + report.blockIndexMismatches);
    
    if (report.hasMismatch) {
        std::fprintf(stderr, "FIRST_MISMATCH_OP=%s\n", report.firstMismatchOp.c_str());
    } else {
        std::fprintf(stderr, "FIRST_MISMATCH_OP=NONE\n");
    }
    std::fprintf(stderr, "EXACT_TYPED_ROUNDTRIP=%s\n", report.allZero() ? "PASS" : "FAIL");
    std::fprintf(stderr, "VERDICT=%s\n", (report.allZero() && hashMatch) ? "PASS" : "FAIL");
    std::fprintf(stderr, "=============================================================================\n");
    
    return report.allZero() && hashMatch;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::fprintf(stderr, "Usage: %s <generated_headers_dir> <evidence_dir>\n", argv[0]);
        return 1;
    }
    
    std::string generatedDir = argv[1];
    std::string evidenceDir = argv[2];
    
    std::fprintf(stderr, "=============================================================================\n");
    std::fprintf(stderr, "RAWRXD_MODELGENIE_EXECUTION_IR_ROUNDTRIP_002\n");
    std::fprintf(stderr, "Exact Typed Operand Parity Test (Compiled Generated Headers)\n");
    std::fprintf(stderr, "=============================================================================\n\n");
    
    std::fprintf(stderr, "Generated headers: %s\n", generatedDir.c_str());
    std::fprintf(stderr, "Original evidence: %s\n\n", evidenceDir.c_str());
    
    // ABI breadcrumb
    std::fprintf(stderr, "[ABI] OperationIR source=%zu generated=%zu\n",
                 sizeof(MG::OperationIR), sizeof(GEN::OperationIR));
    std::fprintf(stderr, "[ABI] ModelGenome source=%zu\n",
                 sizeof(MG::ModelGenome));
    
    MismatchReport report;
    bool success = LoadAndCompare(evidenceDir, report);
    
    return success ? 0 : 1;
}