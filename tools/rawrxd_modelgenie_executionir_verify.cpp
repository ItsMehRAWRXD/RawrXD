//=============================================================================
// rawrxd_modelgenie_executionir_verify - Standalone ExecutionIR Structural Verifier
// RAWRXD_EXECUTIONIR_STRUCTURAL_AUTHORITY_001
//
// Lightweight validator for the 300-op ExecutionIR table.
// Does NOT execute operations; only validates table structure.
//=============================================================================

#include <cstdint>
#include <cstdio>
#include <algorithm>
#include "ModelGenome.hpp"

// Generated headers expect ModelGenie types to be visible without qualification
// inside RawrXD::Deep2::Generated. Bridge that gap here rather than editing
// auto-generated output.
namespace RawrXD {
namespace Deep2 {
using ModelGenie::Architecture;
using ModelGenie::RopeScalingType;
using ModelGenie::WeightTying;
using ModelGenie::TensorRole;
using ModelGenie::GGMLType;
using ModelGenie::Primitive;
using ModelGenie::OpCode;
}
}

#include "ModelExport.generated.hpp"

namespace Generated = ::RawrXD::Deep2::Generated;
namespace ModelGenie  = ::RawrXD::Deep2::ModelGenie;

int main() {
    static_assert(Generated::kExecutionOpCount == 300, "Expected 300 ops");

    uint32_t mla = 0;
    uint32_t moe = 0;
    uint32_t errors = 0;

    for (uint32_t i = 0; i < Generated::kExecutionOpCount; ++i) {
        const auto& op = Generated::kExecutionIRTable[i];

        if (op.opId != i) {
            ++errors;
            fprintf(stderr, "[ERROR] opId mismatch at %u: expected %u, got %u\n", i, i, op.opId);
        }

        if (op.inputCount > 8) {
            ++errors;
            fprintf(stderr, "[ERROR] op %u has too many inputs: %u\n", i, op.inputCount);
        }

        if (op.weightCount > 8) {
            ++errors;
            fprintf(stderr, "[ERROR] op %u has too many weights: %u\n", i, op.weightCount);
        }

        if (op.blockIndex != UINT32_MAX && op.blockIndex >= 27) {
            ++errors;
            fprintf(stderr, "[ERROR] op %u has invalid blockIndex: %u\n", i, op.blockIndex);
        }

        if (op.opcode == ModelGenie::OpCode::MlaDecompress) {
            ++mla;
        }

        if (op.opcode == ModelGenie::OpCode::MoEExecute) {
            ++moe;
        }
    }

    printf("OPS_DECLARED=300\n");
    printf("OPS_VERIFIED=%u\n", Generated::kExecutionOpCount);
    printf("MLA_OPS=%u\n", mla);
    printf("MOE_OPS=%u\n", moe);
    printf("STRUCTURAL_ERRORS=%u\n", errors);

    if (errors > 0) {
        fprintf(stderr, "VERDICT=FAIL\n");
        return 1;
    }

    printf("VERDICT=PASS\n");
    return 0;
}
