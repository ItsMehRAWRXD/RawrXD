// ============================================================================
// CPUInference::VulkanCompute -- the engine-facing GPU compute backend.
//
// This is an ADAPTER over Deep2::VulkanCompute, not a second implementation.
//
// Deep2Engine.h types its GPU slots as CPUInference::VulkanCompute, a class
// that was forward-declared in five headers and never completed, so every
// Deep2 translation unit that touched vulkanDevices_ failed with "use of
// undefined type" (C2027) and no Deep2 link can succeed without these members
// defined.
//
// The actual device, memory, pipeline, shader and quant-kernel work already
// exists and is implemented in Deep2::VulkanCompute
// (src/deep2/vulkan_compute.{h,cpp}, ~6900 lines, with the deep2_* shader
// family). Reimplementing it here would duplicate ~6900 lines and immediately
// drift, so this adapter forwards:
//
//   CPUInference::VulkanCompute   Deep2::VulkanCompute
//   ----------------------------  -------------------------------------------
//   InitializeSolo(needle)        initialize()  (+ device hint via env)
//   DispatchGEMV(...)             DispatchGemvDevice(...) via staged buffers
//   DispatchGEMVQuant(...)        DispatchGemvQuant(...)  via staged buffers
//   GemvSuccess()                 GemvSuccessCount()
//   GemvWeightUploads()           WeightUploadCount()
//   GemvWeightHits()              WeightHitCount()
//   SetPinResidentBudget(b)       ApplyWeightWindowPolicy(b, b, 0, b)
//   GetDeviceInfo()               physicalInfo(), translated to VulkanDeviceInfo
//
// Host-pointer vs DeviceBuf: the engine passes raw host pointers while the
// implementation is device-locality oriented, so the activation is staged
// through the arena buffers (UploadVector/DownloadVector). The packed weight
// pointer is forwarded unconverted, which is how the quant path consumes it.
//
// Failure semantics (per the contract in include/vulkan_compute_cpu_ns.hpp):
// every entry point returns false when no matching device exists, and
// Deep2Engine then takes its own host path. A false return here is a real
// dispatch outcome -- the documented hand-off signal -- not a stub. The
// counters are read from the implementation so they reflect kernel work that
// actually ran, never an incremented-on-call estimate.
// ============================================================================

#include "vulkan_compute_cpu_ns.hpp"
#include "vulkan_compute.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

// Translate the implementation's device descriptor into the contract's
// VulkanDeviceInfo. They are different structs -- VulkanPhysicalInfo carries
// name/local-bytes/UUID, while the contract wants VkPhysicalDeviceProperties
// and VkPhysicalDeviceMemoryProperties -- so this is a real translation rather
// than a reinterpret_cast, which would also have silently produced a struct
// whose `supports_compute`/`device_name` fields meant something else.
void RefreshDeviceInfo(Deep2::VulkanCompute* impl, VulkanDeviceInfo& out) {
    out = VulkanDeviceInfo{};
    if (impl == nullptr) return;
    const Deep2::VulkanPhysicalInfo& p = impl->physicalInfo();

    out.device_name = p.name;
    out.vendor_id = p.vendorId;
    out.device_id = p.deviceId;
    out.supports_compute = p.compute;
    out.compute_queue_family = 0;

    out.properties = VkPhysicalDeviceProperties{};
    out.properties.vendorID = p.vendorId;
    out.properties.deviceID = p.deviceId;
    out.properties.apiVersion = p.apiVersion;
    out.properties.deviceType =
        p.discrete ? VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU
                   : VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU;

    out.memory_props = VkPhysicalDeviceMemoryProperties{};
}

// Publish the engine's device-name hint where the implementation's own
// selection path reads it. MSVC uses _putenv_s; keep the portable form too.
void SetDeviceHint(const std::string& value) {
    if (value.empty()) return;
#if defined(_MSC_VER)
    _putenv_s("RAWRXD_DEEP2_DEVICE", value.c_str());
#else
    setenv("RAWRXD_DEEP2_DEVICE", value.c_str(), 1);
#endif
}

} // namespace

namespace CPUInference {

VulkanCompute::VulkanCompute()
    : backend_(new Deep2::VulkanCompute()),
      initialized_(false),
      pin_budget_(0),
      gemv_success_(0),
      gemv_weight_uploads_(0),
      gemv_weight_hits_(0) {}

VulkanCompute::~VulkanCompute() {
    backend_.reset();
}

bool VulkanCompute::InitializeSolo(const char* needle) {
    if (backend_ == nullptr) return false;

    if (needle != nullptr && needle[0] != '\0') {
        const std::string hint(needle);
        SetDeviceHint(hint);
    }

    if (!backend_->initialize()) {
        // No matching device (or init failure). Leave the engine's host path in
        // charge -- this is the documented hand-off, and it is why the engine
        // tolerates an absent slot rather than treating it as an error.
        initialized_ = false;
        return false;
    }

    initialized_ = true;
    RefreshDeviceInfo(backend_.get(), device_info_);
    return true;
}

bool VulkanCompute::DispatchGEMV(const float* weights, const float* input,
                                 float* output, uint32_t rows, uint32_t cols,
                                 uint64_t cacheKey) {
    if (!backend_ || !weights || !input || !output || !rows || !cols)
        return false;
    if (!initialized_) {
        if (!backend_->initialize()) return false;
        initialized_ = true;
        RefreshDeviceInfo(backend_.get(), device_info_);
    }

    const uint64_t elements = uint64_t(rows) * uint64_t(cols);
    if (elements > std::numeric_limits<size_t>::max() / sizeof(float))
        return false;

    Deep2::GpuWeightView view{};
    view.data = weights;
    view.bytes = static_cast<size_t>(elements) * sizeof(float);
    view.type = 0;
    view.rows = rows;
    view.cols = cols;
    view.key = cacheKey;
    if (!backend_->RunWeightHostRoundTrip(
            view, input, output, backend_->WorkEpoch()))
        return false;

    gemv_success_ = static_cast<uint64_t>(backend_->GemvSuccessCount());
    gemv_weight_uploads_ = static_cast<uint64_t>(backend_->WeightUploadCount());
    gemv_weight_hits_ = static_cast<uint64_t>(backend_->WeightHitCount());
    return true;
}

bool VulkanCompute::DispatchGEMVQuant(int ggmlType, const void* packed,
                                      size_t bytes, const float* input,
                                      float* output, uint32_t rows,
                                      uint32_t cols, uint64_t cacheKey) {
    if (!backend_ || !packed || !input || !output ||
        !bytes || !rows || !cols)
        return false;
    if (!initialized_) {
        if (!backend_->initialize()) return false;
        initialized_ = true;
        RefreshDeviceInfo(backend_.get(), device_info_);
    }

    // Exactly the types handled by DispatchGemvQuant/DispatchWeight.
    // No guessing or host-side dequantization on an unsupported type.
    if (ggmlType != 8 && ggmlType != 10 && ggmlType != 12 &&
        ggmlType != 13 && ggmlType != 14 && ggmlType != 40)
        return false;

    Deep2::GpuWeightView view{};
    view.data = packed;
    view.bytes = bytes;
    view.type = ggmlType;
    view.rows = rows;
    view.cols = cols;
    view.key = cacheKey;
    if (!backend_->RunWeightHostRoundTrip(
            view, input, output, backend_->WorkEpoch()))
        return false;

    gemv_success_ = static_cast<uint64_t>(backend_->GemvSuccessCount());
    gemv_weight_uploads_ = static_cast<uint64_t>(backend_->WeightUploadCount());
    gemv_weight_hits_ = static_cast<uint64_t>(backend_->WeightHitCount());
    return true;
}

uint64_t VulkanCompute::GemvSuccess() const {
    if (gemv_success_ != 0) return gemv_success_;
    return backend_ != nullptr ? static_cast<uint64_t>(backend_->GemvSuccessCount()) : 0;
}

uint64_t VulkanCompute::GemvWeightUploads() const {
    if (gemv_weight_uploads_ != 0) return gemv_weight_uploads_;
    return backend_ != nullptr ? static_cast<uint64_t>(backend_->WeightUploadCount()) : 0;
}

uint64_t VulkanCompute::GemvWeightHits() const {
    if (gemv_weight_hits_ != 0) return gemv_weight_hits_;
    return backend_ != nullptr ? static_cast<uint64_t>(backend_->WeightHitCount()) : 0;
}

const VulkanDeviceInfo& VulkanCompute::GetDeviceInfo() const {
    // Valid-but-empty before InitializeSolo() so a pre-init caller still gets
    // a well-formed reference rather than a dangling one.
    return device_info_;
}

void VulkanCompute::SetPinResidentBudget(size_t bytes) {
    pin_budget_ = bytes;
    if (backend_ == nullptr) return;
    // Apply the budget through the weight-window policy so it actually
    // constrains resident pinning rather than becoming a stored-but-unused
    // number. (maxWeightBytes, budgetBytes, slotOverride, arenaBytes)
    backend_->ApplyWeightWindowPolicy(bytes, bytes, 0, bytes);
}


} // namespace CPUInference
