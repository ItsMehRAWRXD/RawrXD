#include "worldforge_bridge.hpp"
#include <cmath>
#include <fstream>
#include <iomanip>

double WorldForgeBridge::sampleHeightAt(float x, float z) const {
    for (const HeightEdit& edit : edits_) {
        if (std::fabs(edit.x - x) < 0.1f && std::fabs(edit.z - z) < 0.1f) return edit.y;
    }
    return kg::sampleHeight(x, z, world_.settings);
}

void WorldForgeBridge::editHeight(float x, float z, double y) {
    for (HeightEdit& edit : edits_) {
        if (std::fabs(edit.x - x) < 0.1f && std::fabs(edit.z - z) < 0.1f) { edit.y = y; return; }
    }
    edits_.push_back({x, z, y});
}

void WorldForgeBridge::clearEdits() { edits_.clear(); }

bool WorldForgeBridge::saveEdits(const std::string& path) const {
    std::ofstream out(path, std::ios::trunc);
    if (!out) return false;
    out << edits_.size() << "\n" << std::setprecision(17);
    for (const HeightEdit& edit : edits_) out << edit.x << " " << edit.z << " " << edit.y << "\n";
    return static_cast<bool>(out);
}

bool WorldForgeBridge::loadEdits(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;
    size_t count = 0;
    in >> count;
    edits_.clear();
    for (size_t i = 0; i < count; ++i) {
        HeightEdit edit;
        in >> edit.x >> edit.z >> edit.y;
        if (!in) return false;
        edits_.push_back(edit);
    }
    return true;
}
