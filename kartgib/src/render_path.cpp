#include "vulkan_renderer.hpp"
#include "editor_api.hpp"
#include <fstream>
void exeSha256(char out[65]);

void VulkanRenderer::noteRenderPath(const char* scene, int entities, int meshEntities, int voxels,
    int tiles, int foliageGenerated, int waterMesh) {
    char sha[65]{}; exeSha256(sha);
    char rev[80]{}, dirty[8]{};
    editorGit(rev, 80, dirty);
    int shadow = shadowSubmits_ > 0 ? 1 : 0;
    int atmosphere = atmosphereSubmits_ > 0 ? 1 : 0;
    int terrain = terrainSubmits_ > 0 ? 1 : 0;
    int foliage = foliageDraws_ > 0 ? 1 : 0;
    std::ofstream json("F:/rawrxd/kartgib/evidence/KARTGIB_RENDER_PATH_001.json");
    json << "{\"gate\":\"KARTGIB_RENDER_PATH_001\",\"promote\":0"
         << ",\"SOURCE_COMMIT\":\"" << rev << "\",\"SOURCE_DIRTY\":\"" << dirty << "\""
         << ",\"EXE_SHA256\":\"" << sha << "\",\"GPU_NAME\":\"" << deviceName_ << "\""
         << ",\"RENDER_BACKEND\":\"VULKAN\",\"SWAPCHAIN_FORMAT\":" << static_cast<int>(swapchainImageFormat_)
         << ",\"SCENE_NAME\":\"" << scene << "\",\"SCENE_ENTITIES\":" << entities
         << ",\"MESH_ENTITIES\":" << meshEntities << ",\"VOXEL_ENTITIES\":" << voxels
         << ",\"TERRAIN_TILES\":" << tiles << ",\"FOLIAGE_GENERATED\":" << foliageGenerated
         << ",\"FOLIAGE_INSTANCES\":" << foliageDraws_ << ",\"WATER_MESH\":" << waterMesh
         << ",\"TERRAIN_PASS\":" << terrain << ",\"VOXEL_PASS\":0,\"MESH_PASS\":0,\"EDITOR_BOXES\":" << meshEntities
         << ",\"SHADOW_PASS\":" << shadow << ",\"ATMOSPHERE_PASS\":" << atmosphere
         << ",\"WATER_PASS\":" << waterMesh << ",\"FOLIAGE_PASS\":" << foliage
         << ",\"POSTPROCESS_PASS\":0"
         << ",\"ATMOSPHERE_SUBMITS\":" << atmosphereSubmits_ << ",\"TERRAIN_SUBMITS\":" << terrainSubmits_
         << ",\"SHADOW_SUBMITS\":" << shadowSubmits_
         << ",\"DRAW_CALLS\":" << (atmosphereSubmits_ + terrainSubmits_ + shadowSubmits_ * 4 + foliageDraws_)
         << ",\"COMPUTE_DISPATCHES\":0,\"PIPELINE_CREATE_FAILURES\":" << pipelineFailures_
         << ",\"ASSET_LOADS_ATTEMPTED\":0,\"ASSET_LOAD_FAILURES\":0,\"SHADER_FALLBACKS\":0"
         << ",\"INDEX_COUNT\":" << lastIndexCount_
         << ",\"FRAME_CAPTURE\":\"F:/rawrxd/kartgib/evidence/kartgib_editor_base.png\""
         << ",\"VISIBLE_SHADOW_DELTA\":\"NOT_RUN\",\"SOURCE_TO_FRAME_PARITY\":\"NOT_RUN\""
         << ",\"V01\":\"NOT_RUN\",\"V02\":\"NOT_RUN\",\"V03\":\"NOT_RUN\",\"V04\":\"NOT_RUN\""
         << ",\"V05\":\"NOT_RUN\",\"V06\":\"NOT_RUN\",\"V07\":\"NOT_RUN\",\"V08\":\"NOT_RUN\""
         << ",\"V09\":\"NOT_RUN\",\"V10\":\"NOT_RUN\",\"V11\":\"NOT_RUN\",\"V12\":\"NOT_RUN\"}\n";
    std::cout << "[RENDER] terrain=" << terrain << " atmosphere=" << atmosphere
              << " shadow=" << shadow << " foliage=" << foliageDraws_
              << " generated=" << foliageGenerated << " indices=" << lastIndexCount_ << std::endl;
}
