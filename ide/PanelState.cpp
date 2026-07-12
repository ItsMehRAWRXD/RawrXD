#include "ide/PanelState.hpp"

static std::unordered_map<std::string, bool> states;

void PanelState::Register(const std::string& id) {
    states[id] = false;
}

void PanelState::Toggle(const std::string& id) {
    states[id] = !states[id];
}

bool PanelState::Visible(const std::string& id) {
    auto it = states.find(id);
    return (it != states.end()) ? it->second : false;
}
