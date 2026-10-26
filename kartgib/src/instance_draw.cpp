#include "vulkan_renderer.hpp"
#include <cstring>

static void uploadMesh(VulkanRenderer& renderer, const Vertex* verts, int vcount,
    const uint32_t* idx, int icount, VkBuffer& vb, VkDeviceMemory& vm, VkBuffer& ib, VkDeviceMemory& im) {
    VkDeviceSize vs = sizeof(Vertex) * static_cast<VkDeviceSize>(vcount);
    renderer.createBuffer(vs, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, vb, vm);
    void* data = nullptr;
    vkMapMemory(renderer.getDevice(), vm, 0, vs, 0, &data);
    std::memcpy(data, verts, static_cast<size_t>(vs));
    vkUnmapMemory(renderer.getDevice(), vm);
    VkDeviceSize is = sizeof(uint32_t) * static_cast<VkDeviceSize>(icount);
    renderer.createBuffer(is, VK_BUFFER_USAGE_INDEX_BUFFER_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, ib, im);
    vkMapMemory(renderer.getDevice(), im, 0, is, 0, &data);
    std::memcpy(data, idx, static_cast<size_t>(is));
    vkUnmapMemory(renderer.getDevice(), im);
}

void VulkanRenderer::createProductMeshes() {
    Vertex grass[8]{};
    float cross[8][3] = {{0,0,0},{1.2f,0,0},{1.2f,4.0f,0},{0,4.0f,0},{0,0,0},{0,0,1.2f},{0,4.0f,1.2f},{0,4.0f,0}};
    for (int i = 0; i < 8; ++i) {
        grass[i].pos[0] = cross[i][0]; grass[i].pos[1] = cross[i][1] * 2.5f; grass[i].pos[2] = cross[i][2];
        grass[i].normal[1] = 1.0f; grass[i].uv[1] = 4.0f;
    }
    uint32_t gi[] = {0,2,1,0,3,2,4,6,5,4,7,6};
    uploadMesh(*this, grass, 8, gi, 12, grassVb_, grassMem_, grassIb_, grassIndexMem_);
    Vertex hud[4]{};
    float q[4][2] = {{-0.95f,0.78f},{-0.42f,0.78f},{-0.42f,0.94f},{-0.95f,0.94f}};
    for (int i = 0; i < 4; ++i) {
        hud[i].pos[0] = q[i][0]; hud[i].pos[1] = q[i][1]; hud[i].uv[1] = 5.0f; hud[i].normal[1] = 1.0f;
    }
    uint32_t hi[] = {0,1,2,0,2,3};
    uploadMesh(*this, hud, 4, hi, 6, hudVb_, hudMem_, hudIb_, hudIndexMem_);
}

void VulkanRenderer::uploadInstances(const float* xyz, int count) {
    if (instVb_ != VK_NULL_HANDLE) {
        vkDestroyBuffer(device_, instVb_, nullptr);
        vkFreeMemory(device_, instMem_, nullptr);
        instVb_ = VK_NULL_HANDLE;
    }
    instCount_ = static_cast<uint32_t>(count);
    if (count <= 0) return;
    VkDeviceSize sz = sizeof(float) * 3 * static_cast<VkDeviceSize>(count);
    createBuffer(sz, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, instVb_, instMem_);
    void* data = nullptr;
    vkMapMemory(device_, instMem_, 0, sz, 0, &data);
    std::memcpy(data, xyz, static_cast<size_t>(sz));
    vkUnmapMemory(device_, instMem_);
}

void VulkanRenderer::drawProduct(VkCommandBuffer cmd) {
    if (productPipeline_ == VK_NULL_HANDLE || instVb_ == VK_NULL_HANDLE) return;
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, productPipeline_);
    VkViewport viewport{}; viewport.width = (float)swapchainExtent_.width; viewport.height = (float)swapchainExtent_.height; viewport.maxDepth = 1;
    vkCmdSetViewport(cmd, 0, 1, &viewport);
    VkRect2D scissor{}; scissor.extent = swapchainExtent_;
    vkCmdSetScissor(cmd, 0, 1, &scissor);
    VkDeviceSize offs[2] = {0, 0};
    if (instCount_ > 0) {
        VkBuffer bufs[2] = {grassVb_, instVb_};
        vkCmdBindVertexBuffers(cmd, 0, 2, bufs, offs);
        vkCmdBindIndexBuffer(cmd, grassIb_, 0, VK_INDEX_TYPE_UINT32);
        if (productQuery_ != VK_NULL_HANDLE)
            vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, productQuery_, 0);
        vkCmdDrawIndexed(cmd, 12, instCount_, 0, 0, 0);
        foliageDraws_ += instCount_;
        if (productQuery_ != VK_NULL_HANDLE)
            vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, productQuery_, 1);
    }
    VkBuffer hud[2] = {hudVb_, instVb_};
    vkCmdBindVertexBuffers(cmd, 0, 2, hud, offs);
    vkCmdBindIndexBuffer(cmd, hudIb_, 0, VK_INDEX_TYPE_UINT32);
    vkCmdDrawIndexed(cmd, 6, 1, 0, 0, 0);
}
