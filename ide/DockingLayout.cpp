#include "ide/DockingLayout.hpp"
#include <unordered_map>

static std::unordered_map<std::string, DockingLayout::Position> layout;

void DockingLayout::Init() {
    // Initialize docking layout
}

void DockingLayout::Add(const std::string& panelId, Position pos) {
    layout[panelId] = pos;
}

void DockingLayout::Apply() {
    // Apply docking layout
}
