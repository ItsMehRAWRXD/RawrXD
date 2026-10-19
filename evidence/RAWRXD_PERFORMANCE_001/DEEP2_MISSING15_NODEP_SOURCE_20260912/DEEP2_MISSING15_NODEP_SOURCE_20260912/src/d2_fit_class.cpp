#include "d2_nodep.h"

extern "C" D2FitClass d2_fit_classify(uint64_t model_bytes, const D2ResidencyBudget* b) {
    if (!b || !model_bytes) return D2_FIT_INVALID;
    if (model_bytes <= b->vram_bytes) return D2_FIT_VRAM_HOT;
    if (model_bytes <= b->vram_bytes + b->ram_bytes) return D2_FIT_MIXED_RAM;
    if (model_bytes <= b->vram_bytes + b->ram_bytes + b->cold_bytes) return D2_FIT_COLD_BACKED;
    return D2_FIT_INVALID;
}
