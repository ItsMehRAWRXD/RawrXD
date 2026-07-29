<<<<<<< HEAD
#pragma once
// feature_flags.hpp
namespace rxd::features {
    constexpr bool LSP_SEMANTIC_TOKENS = false;      // Deferred (high complexity)
    constexpr bool LSP_LINKED_EDITING  = false;      // Future release
    constexpr bool LSP_INLAY_HINTS     = true;       // Implemented
    constexpr bool LSP_CALL_HIERARCHY  = false;      // Planned
    constexpr bool AVX_512_TEXT_PROC   = true;       // MASM bridge active
    constexpr bool INCREMENTAL_SYNC    = true;       // Myers diff active
}
=======
// feature_flags.hpp
namespace rxd::features {
    constexpr bool LSP_SEMANTIC_TOKENS = false;      // Deferred (high complexity)
    constexpr bool LSP_LINKED_EDITING  = false;      // Future release
    constexpr bool LSP_INLAY_HINTS     = true;       // Implemented
    constexpr bool LSP_CALL_HIERARCHY  = false;      // Planned
    constexpr bool AVX_512_TEXT_PROC   = true;       // MASM bridge active
    constexpr bool INCREMENTAL_SYNC    = true;       // Myers diff active
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
