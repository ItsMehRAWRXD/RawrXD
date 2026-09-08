#pragma once
/* QKV / O_PROJ / KVA advertise variants into one tune framework. */
#include "KernelTune.hpp"

namespace rawr::ktune {

/* Only 64-row oproj SPV is executable today; others advertised, not runnable. */
inline const Variant kQkvSharedXVariants[] = {
    {"qkv_sx_32", 32u, "gemv_q4k_qkv_sx_32.spv", true},
    {"qkv_sx_64", 64u, "gemv_q4k_qkv_sx_64.spv", true},
    {"qkv_sx_128", 128u, "gemv_q4k_qkv_sx_128.spv", true},
    {"qkv_sx_256", 256u, "gemv_q4k_qkv_sx_256.spv", true},
};

inline Descriptor QkvSharedXDesc() noexcept {
    return {"QKV_SHARED_X", kQkvSharedXVariants, 4u};
}

inline const Variant kKvaSharedXVariants[] = {
    {"kva_sx_16", 16u, "gemv_q4k_kva.spv", true},
    {"kva_sx_64", 64u, nullptr, false},
    {"kva_sx_128", 128u, nullptr, false},
    {"kva_sx_256", 256u, nullptr, false},
};

inline Descriptor KvaSharedXDesc() noexcept {
    return {"KVA_SHARED_X", kKvaSharedXVariants, 4u};
}

inline const Variant kOprojVariants[] = {
    {"oproj_64", 64u, "gemv_q4k_oproj.spv", true},
};

inline Descriptor OprojDesc() noexcept {
    return {"O_PROJ_TAG6", kOprojVariants, 1u};
}

} // namespace rawr::ktune
