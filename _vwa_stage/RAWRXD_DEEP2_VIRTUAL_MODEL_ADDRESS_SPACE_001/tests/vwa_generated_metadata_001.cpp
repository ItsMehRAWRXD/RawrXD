// Compile from actual RawrXD checkout with src/deep2/modelgenie and generated
// include paths. Validates the full 377-tensor / 300-op metadata handoff.
#include "ModelGenome.hpp"
namespace RawrXD { namespace Deep2 {
using ModelGenie::Architecture;
using ModelGenie::RopeScalingType;
using ModelGenie::WeightTying;
using ModelGenie::TensorRole;
using ModelGenie::GGMLType;
using ModelGenie::Primitive;
using ModelGenie::OpCode;
} }
#include "ModelExport.generated.hpp"
#include "vwa/VwaScheduler.hpp"
#include "vwa/VwaGeneratedBridge.hpp"
#include <cstddef>
#include <cstdio>
#include <vector>

namespace G = RawrXD::Deep2::Generated;
int main() {
    constexpr size_t nRom = sizeof(G::kTensorROMTable) / sizeof(G::kTensorROMTable[0]);
    constexpr size_t nIr = sizeof(G::kExecutionIRTable) / sizeof(G::kExecutionIRTable[0]);
    constexpr size_t nBanks = sizeof(G::kExpertBankTable) / sizeof(G::kExpertBankTable[0]);
    static_assert(nRom == 377, "Unexpected generated ROM count");
    static_assert(nIr == 300, "Unexpected generated operation count");
    static_assert(nBanks == 26, "Unexpected generated expert-bank count");
    ::Deep2::vwa::VwaSpace space;
    if (!::Deep2::vwa::RegisterGeneratedRom(
            space, G::kTensorROMTable, nRom, G::kModelDataStart,
            G::kExpertBankTable, nBanks)) return 2;
    ::Deep2::vwa::VwaScheduler sched(space);
    if (!sched.BindIR(G::kExecutionIRTable, nIr)) return 3;
    uint64_t unresolved = 0;
    for (size_t i=0; i<nIr; ++i)
        for (auto id : sched.IR().Tensors(i))
            if (!space.Find(id)) ++unresolved;
    const uint32_t experts[] = {0,2,4,6,8,10};
    std::vector<::Deep2::vwa::BlockRange> ranges;
    const bool expertPlan = ::Deep2::vwa::RangesForSelectedExperts(
        space, G::kExpertBankTable[0], experts, 6, ranges);
    const bool ok = !unresolved && expertPlan && ranges.size()==18 &&
        space.Count()==nRom && G::kResidencyBounds.expertRomBytes==9527361536ULL;
    std::printf("ROM_DIRECTORY_COUNT=%zu\nIR_COUNT=%zu\nBANK_COUNT=%zu\n"
        "IR_REFERENCE_ERRORS=%llu\nEXPERT_TOPK_RANGES=%zu\n"
        "LOGICAL_MODEL_BYTES=%llu\n"
        "GENERATED_AUTHORITY=%s\n",
        space.Count(), sched.IR().Count(), nBanks,
        static_cast<unsigned long long>(unresolved), ranges.size(),
        static_cast<unsigned long long>(space.LogicalBytes()), ok?"PASS":"FAIL");
    return ok?0:4;
}
