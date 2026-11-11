#pragma once
#include "Deep2B61QwenNext.hpp"
#include "Deep2B62Nemotron.hpp"
#include "Deep2B63GptOss.hpp"
#include "Deep2B64Laguna.hpp"
#include "Deep2B65DeepSeekFlash.hpp"
#include <vector>

namespace Deep2 {

inline std::vector<ModelPerformanceContract> B61_65ShowcaseContracts() {
    return {
        B61QwenNextContract(),
        B62NemotronContract(),
        B63GptOssContract(),
        B64LagunaContract(),
        B65DeepSeekFlashContract()
    };
}

} // namespace Deep2
