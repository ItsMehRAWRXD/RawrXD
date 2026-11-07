#pragma once
#include <string_view>
namespace rawrxd::agent {
inline bool hasToolPayload(std::string_view output) noexcept {
    if (!(output.substr(0,5) == "TOOL:" || output.substr(0,5) == "tool:")) return false;
    const auto payload = output.substr(5);
    return payload.find_first_not_of(" \t\r\n") != std::string_view::npos;
}
}
