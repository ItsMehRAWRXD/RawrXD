#pragma once
#include "rawr_output_router.hpp"
#include <iostream>
#include <string>
namespace rawr {
inline bool ReadReplLine(std::string& line) {
    Diag("rawr> ");
    if (!std::getline(std::cin, line)) return false;
    return !line.empty();
}
} // namespace rawr
