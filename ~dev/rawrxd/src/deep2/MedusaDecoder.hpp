#pragma once
// Stub: Medusa speculative decoder
#include <cstdint>
namespace Deep2 {
struct MedusaConfig {};
struct MedusaStats { int accepted=0; int rejected=0; };
class MedusaDecoder {
public:
    MedusaStats stats;
};
} // namespace Deep2
