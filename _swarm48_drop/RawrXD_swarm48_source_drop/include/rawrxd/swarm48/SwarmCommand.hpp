#pragma once
#include "Common.hpp"

namespace rawrxd::swarm48 {

struct SwarmCommand {
    std::string device;
    std::string model;
    std::string task;
};

inline std::optional<SwarmCommand> parse_rawr_command(std::span<const std::string> argv) {
    // Expected logical argv: [rawr, r9700|7800xt|auto|dual, model, task...]
    if (argv.size() < 4 || argv[0] != "rawr") return std::nullopt;
    SwarmCommand c{argv[1], argv[2], {}};
    for (std::size_t i = 3; i < argv.size(); ++i) {
        if (!c.task.empty()) c.task.push_back(' ');
        c.task += argv[i];
    }
    return c;
}

} // namespace rawrxd::swarm48
