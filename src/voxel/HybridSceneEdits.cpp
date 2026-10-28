#include "HybridScene.hpp"

#include <cmath>

namespace sunshine {

void HybridScene::applyEdits() {
    for (const SceneEntity& entity : entities_) {
        if (entity.kind != GeometryKind::VoxelVolume) continue;
        for (const VoxelEdit& edit : entity.edits) {
            const int32_t cx = static_cast<int32_t>(std::floor(static_cast<double>(edit.x) / kChunkSize));
            const int32_t cz = static_cast<int32_t>(std::floor(static_cast<double>(edit.z) / kChunkSize));
            world_.chunk(cx, cz).set(edit.x - cx * kChunkSize, edit.y,
                                     edit.z - cz * kChunkSize, edit.block);
        }
    }
}

}  // namespace sunshine
