#pragma once
#include "Common.hpp"
#include <string_view>

namespace rawrxd::swarm48 {

struct SwarmCommand {
    enum class Target : std::uint8_t { r9700, rx7800xt, auto_select, dual };
    Target target{Target::auto_select};
    std::string model_hint;
    std::string prompt;
};

inline SwarmCommand parse_swarm_command(std::string_view cmd) {
    SwarmCommand out;
    if (cmd.rfind("rawr r9700 ", 0) == 0) {
        out.target = SwarmCommand::Target::r9700;
        cmd.remove_prefix(11);
    } else if (cmd.rfind("rawr 7800xt ", 0) == 0) {
        out.target = SwarmCommand::Target::rx7800xt;
        cmd.remove_prefix(12);
    } else if (cmd.rfind("rawr auto ", 0) == 0) {
        out.target = SwarmCommand::Target::auto_select;
        cmd.remove_prefix(10);
    } else if (cmd.rfind("rawr dual ", 0) == 0) {
        out.target = SwarmCommand::Target::dual;
        cmd.remove_prefix(10);
    }
    auto sp = cmd.find(' ');
    if (sp != std::string_view::npos) {
        out.model_hint = std::string(cmd.substr(0, sp));
        out.prompt = std::string(cmd.substr(sp + 1));
    } else {
        out.model_hint = std::string(cmd);
    }
    return out;
}

} // namespace rawrxd::swarm48
