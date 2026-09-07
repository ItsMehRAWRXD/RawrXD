// RKCCompiler.hpp — compile question backward into required goal tree
#pragma once
#include "RKCTypes.hpp"
#include <string>
#include <vector>

namespace RawrXD {
namespace RKC {

struct CompiledGoal {
    std::string goalKey;
    std::string task;
    std::vector<std::string> requiredKeys;
    std::vector<std::string> constraints;
};

CompiledGoal CompileGoal(const std::string& query);

} // namespace RKC
} // namespace RawrXD
