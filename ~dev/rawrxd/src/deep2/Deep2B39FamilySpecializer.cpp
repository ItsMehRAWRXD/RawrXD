#include "Deep2B39FamilySpecializer.hpp"

namespace Deep2 {

B39FamilyPlan B39FamilySpecializer::specialize(const B39FamilyShape& s) noexcept {
    B39FamilyPlan p{};
    p.waveWidth = s.waveWidth;
    p.workgroup = s.waveWidth >= 64 ? 256u : 128u;
    p.rowsPerGroup = s.regCount >= 256 ? 4u : 2u;
    p.stages = s.ldsBytes >= 65536 ? 2u : 1u;
    p.useWaveDot = s.hasWaveDot;
    p.useVNNI = s.hasVNNI;
    p.useRegisterTiling = s.regCount >= 128;
    p.useCooperativeGemv = s.ldsBytes >= 65536 && s.waveWidth >= 64;
    p.specialized = s.family != B39ArchFamily::GENERIC;
    return p;
}

std::string B39FamilySpecializer::familyName(B39ArchFamily f) noexcept {
    switch (f) {
        case B39ArchFamily::RDNA3:   return "RDNA3";
        case B39ArchFamily::RDNA4:   return "RDNA4";
        case B39ArchFamily::CDNA2:   return "CDNA2";
        case B39ArchFamily::CDNA3:   return "CDNA3";
        default:                     return "GENERIC";
    }
}

} // namespace Deep2
