// vulkan_fwd_stubs.cpp — satisfy linker when Vulkan SDK is absent
#include "vulkan_compute.h"
#if !RAWR_VULKAN_AVAILABLE
namespace CPUInference {
static VulkanCompute::DeviceBuf g_dummy{};
bool VulkanCompute::EnsureForwardArena(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return false; }
bool VulkanCompute::UploadHidden(const float*, uint32_t) { return false; }
bool VulkanCompute::DownloadHidden(float*, uint32_t) { return false; }
bool VulkanCompute::CopyArenaHiddenTo(VulkanCompute&, uint32_t) { return false; }
bool VulkanCompute::DispatchGemvDevice(const float*, uint64_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t) { return false; }
bool VulkanCompute::DispatchGemvPacked(const void*, size_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t) { return false; }
bool VulkanCompute::DispatchGemvQ6kPacked(const void*, size_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t) { return false; }
bool VulkanCompute::DispatchGEMVQ6kPacked(const void*, size_t, const float*, float*, uint32_t, uint32_t) { return false; }
bool VulkanCompute::DispatchGemvQuant(int, const void*, size_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t) { return false; }
bool VulkanCompute::DispatchGEMVQuant(int, const void*, size_t, const float*, float*, uint32_t, uint32_t, uint64_t) { return false; }
bool VulkanCompute::EnsureQ4kPipeline() { return false; }
bool VulkanCompute::EnsureQ4kFusedPipeline() { return false; }
bool VulkanCompute::DispatchGEMVFusedQ4KT(const void*, size_t, const float*, float*,
                                          uint32_t, uint32_t, uint64_t) {
    return false;
}
bool VulkanCompute::EnsureQ6kPipeline() { return false; }
bool VulkanCompute::EnsureQ5kPipeline() { return false; }
bool VulkanCompute::EnsureQ3kPipeline() { return false; }
bool VulkanCompute::EnsureQ2kPipeline() { return false; }
bool VulkanCompute::EnsureQ8Pipeline() { return false; }
bool VulkanCompute::CreateGemvPipe(const char*, VkPipeline&) { return false; }
bool VulkanCompute::SelectPackedPipe(int, VkPipeline&, uint64_t*&) { return false; }
bool VulkanCompute::EnsureFusedPool() { return false; }
bool VulkanCompute::SubmitFusedPool(VkCommandBuffer, uint32_t) { return false; }
void VulkanCompute::ReleaseFusedPool() {}
bool VulkanCompute::TuneFromDevice() { return false; }
bool VulkanCompute::DispatchGEMVPacked(const void*, size_t, const float*, float*, uint32_t, uint32_t, uint64_t) { return false; }
bool VulkanCompute::BindGemvStorage(VkBuffer, size_t, VkBuffer, size_t, VkBuffer, size_t, VkPipeline, uint32_t, uint32_t, uint32_t) { return false; }
bool VulkanCompute::DispatchRmsNorm(DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t, float) { return false; }
bool VulkanCompute::DispatchResidualAdd(DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t) { return false; }
bool VulkanCompute::DispatchRope(DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint32_t, uint32_t, float) { return false; }
bool VulkanCompute::DispatchAttnDecode(DeviceBuf&, DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint32_t, uint32_t, float, uint32_t) { return false; }
bool VulkanCompute::DispatchSwiGLU(DeviceBuf&, DeviceBuf&, DeviceBuf&, uint32_t) { return false; }
bool VulkanCompute::AppendKV(DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, uint32_t) { return false; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaHidden() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaResidual() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaNormed() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaQ() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaK() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaV() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaAttn() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaGate() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaUp() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaDown() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaFFNAct() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaAttnW() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaFfnW() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaKCache() { return g_dummy; }
VulkanCompute::DeviceBuf& VulkanCompute::ArenaVCache() { return g_dummy; }
bool VulkanCompute::BeginFusedLayer() { return false; }
bool VulkanCompute::EndFusedLayer() { return false; }
bool VulkanCompute::FlushFusedRestart() { return false; }
bool VulkanCompute::FusedBarrier() { return false; }
VkDescriptorSet VulkanCompute::NextGemvDs() { return nullptr; }
bool VulkanCompute::RecordCompute(VkPipeline, VkPipelineLayout, VkDescriptorSet, const void*, uint32_t, uint32_t) { return false; }
bool VulkanCompute::RecordCopy(VkBuffer, VkBuffer, VkDeviceSize, VkDeviceSize, VkDeviceSize) { return false; }
bool VulkanCompute::UploadNormWeight(DeviceBuf&, const float*, uint32_t) { return false; }
bool VulkanCompute::EnsureWeightWindow(size_t, uint32_t, size_t) { return false; }
void VulkanCompute::ResetWeightWindowLayerCursor() {}
bool VulkanCompute::PrefetchWeight(const void*, size_t, uint32_t&) { return false; }
bool VulkanCompute::WaitWeightUpload(uint32_t) { return false; }
bool VulkanCompute::SubmitGemvPrefetch(uint32_t, DeviceBuf&, DeviceBuf&, uint32_t, uint32_t, size_t, int) { return false; }
bool VulkanCompute::WaitWeightCompute(uint32_t) { return false; }
bool VulkanCompute::FlushWeightComputes() { return true; }
bool VulkanCompute::LoadComputePipeline(const char*, uint32_t, uint32_t, VkPipeline&, VkPipelineLayout&, VkDescriptorSetLayout&, VkDescriptorPool&, VkDescriptorSet&) { return false; }
bool VulkanCompute::SubmitOne(VkCommandBuffer) { return false; }
bool VulkanCompute::DownloadDeviceLocal(VkBuffer, void*, size_t) { return false; }
bool VulkanCompute::CopyDeviceToDevice(VkBuffer, VkBuffer, size_t) { return false; }
void VulkanCompute::ReleaseForwardArena() {}
bool VulkanCompute::ExecuteRMSNorm(float*, uint32_t, float) { return false; }
bool VulkanCompute::ExecuteSiLU(float*, uint32_t) { return false; }
bool VulkanCompute::DownloadBuf(DeviceBuf&, float*, uint32_t) { return false; }
bool VulkanCompute::UploadBuf(DeviceBuf&, const float*, uint32_t) { return false; }
bool VulkanCompute::StreamWeightToSlot(const void*, size_t, VkBuffer&) { return false; }
bool VulkanCompute::EnsurePinnedPackedWeight(const void*, size_t, uint32_t, uint32_t,
                                             VkBuffer&, uint64_t) {
    return false;
}
bool VulkanCompute::HasPinnedGemvWeight(uint64_t, size_t, uint32_t, uint32_t) const {
    return false;
}
void VulkanCompute::ReleaseWeightWindow() {}
void VulkanCompute::ClearPinnedGemvWeights() {}
size_t VulkanCompute::WeightBudgetBytes() const { return 0; }
size_t VulkanCompute::WeightPinBudgetFloor() const { return 0; }
void VulkanCompute::SetPinResidentBudget(size_t) {}
uint64_t VulkanCompute::WeightPinCacheCount() const { return 0; }
uint64_t VulkanCompute::WeightPinResidentBytes() const { return 0; }
bool VulkanCompute::WantWeightStream() { return false; }
size_t VulkanCompute::DeviceLocalHeapBytes() const { return 0; }
bool VulkanCompute::ApplyWeightWindowPolicy(size_t, size_t, uint32_t, size_t) { return false; }
}
#endif
