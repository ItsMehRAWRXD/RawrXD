#pragma once
#include <cstdint>
#include <string>

namespace Deep2 {

enum class B39ArchFamily : uint8_t {
    RDNA3,
    RDNA4,
    CDNA2,
    CDNA3,
    GENERIC
};

struct B39FamilyShape {
    B39ArchFamily family = B39ArchFamily::GENERIC;
    uint32_t waveWidth = 64;
    uint32_t ldsBytes = 65536;
    uint32_t regCount = 256;
    bool hasWaveDot = false;
    bool hasVNNI = false;
};

struct B39FamilyPlan {
    uint32_t waveWidth = 64;
    uint32_t workgroup = 256;
    uint32_t rowsPerGroup = 4;
    uint32_t stages = 2;
    bool useWaveDot = false;
    bool useVNNI = false;
    bool useRegisterTiling = true;
    bool useCooperativeGemv = false;
    bool specialized = true;
};

class B39FamilySpecializer {
public:
    static B39FamilyPlan specialize(const B39FamilyShape&) noexcept;
    static std::string familyName(B39ArchFamily) noexcept;
};

} // namespace Deep2