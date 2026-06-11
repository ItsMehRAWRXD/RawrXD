#pragma once
#include <string>

namespace rawrxd {
namespace rag_lite {

inline void requestBackgroundScan(std::string root) {
    (void)root;
}

inline std::string buildPromptInjection(const std::string& context, size_t maxLen) {
    (void)maxLen;
    return context;
}

} // namespace rag_lite
} // namespace rawrxd
