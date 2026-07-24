#pragma once
#include "ReverseTypes.hpp"
#include <string>

namespace rxd::reverse {

class ReverseModelLoader {
public:
    static ReverseModel LoadFromFile(const std::string& path);
    static ReverseModel LoadFromJson(const std::string& json);
};

} // namespace rxd::reverse
