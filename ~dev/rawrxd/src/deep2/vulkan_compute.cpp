// ============================================================================
// vulkan_compute.cpp — Batch 9 real Vulkan device/runtime implementation
// ============================================================================
#include "vulkan_compute.h"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <thread>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace {

constexpr uint32_t OP_PROBE    = 0;
constexpr uint32_t OP_GEMV_F32 = 1;
constexpr uint32_t OP_RMSNORM  = 2;
constexpr uint32_t OP_RESIDUAL = 3;
constexpr uint32_t OP_SWIGLU   = 4;
constexpr uint32_t OP_ROPE     = 5;
constexpr uint32_t OP_ATTN     = 6;
constexpr uint32_t OP_MLA_ATTN = 7;

bool mulOverflow(size_t a, size_t b, size_t& out) {
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a) return true;
    out = a * b;
    return false;
}

uint64_t quantWeightKey(const void* p, size_t bytes, int type) {
    uint64_t x = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(p));
    x ^= static_cast<uint64_t>(bytes) * 0x9E3779B185EBCA87ull;
    x ^= static_cast<uint64_t>(static_cast<uint32_t>(type)) << 32;
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

bool finiteVector(const std::vector<float>& v) {
    for (float x : v) if (!std::isfinite(x)) return false;
    return true;
}

uint64_t hostDomainToNs(VkTimeDomainEXT domain, uint64_t raw) {
#ifdef _WIN32
    if (domain == VK_TIME_DOMAIN_QUERY_PERFORMANCE_COUNTER_EXT) {
        LARGE_INTEGER f{};
        if (!QueryPerformanceFrequency(&f) || f.QuadPart <= 0) return 0;
        long double ns = static_cast<long double>(raw) * 1000000000.0L /
                         static_cast<long double>(f.QuadPart);
        return static_cast<uint64_t>(ns);
    }
#endif
    // CLOCK_MONOTONIC(_RAW)_EXT timestamps are nanoseconds.
    return raw;
}

} // namespace

VulkanCompute::VulkanCompute(uint32_t physicalOrdinal)
    : requestedOrdinal_(physicalOrdinal) {}

VulkanCompute::~VulkanCompute() {
    cleanup();
}

uint64_t VulkanCompute::nowNs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::vector<VulkanPhysicalInfo> VulkanCompute::EnumeratePhysicalDevices() {
    std::vector<VulkanPhysicalInfo> out;

    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "RawrXD Deep2 Batch9";
    app.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;

    VkInstance inst = VK_NULL_HANDLE;
    if (vkCreateInstance(&ci, nullptr, &inst) != VK_SUCCESS) return out;

    uint32_t n = 0;
    if (vkEnumeratePhysicalDevices(inst, &n, nullptr) != VK_SUCCESS || n == 0) {
        vkDestroyInstance(inst, nullptr);
        return out;
    }

    std::vector<VkPhysicalDevice> devs(n);
    if (vkEnumeratePhysicalDevices(inst, &n, devs.data()) != VK_SUCCESS) {
        vkDestroyInstance(inst, nullptr);
        return out;
    }

    for (uint32_t i = 0; i < n; ++i) {
        VkPhysicalDeviceProperties p{};
        VkPhysicalDeviceMemoryProperties mp{};
        vkGetPhysicalDeviceProperties(devs[i], &p);
        vkGetPhysicalDeviceMemoryProperties(devs[i], &mp);

        VkPhysicalDeviceIDProperties idp{
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES
        };
        VkPhysicalDeviceProperties2 p2{
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2
        };
        p2.pNext = &idp;
        vkGetPhysicalDeviceProperties2(devs[i], &p2);

        // Deduplicate by deviceUUID — skip D3D12 aliases of same physical GPU
        bool dup = false;
        for (const auto& existing : out) {
            if (std::memcmp(existing.deviceUUID, idp.deviceUUID,
                            VK_UUID_SIZE) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        // Fallback dedup by (vendorId, deviceId) for D3D12 wrappers with different UUIDs
        bool dupFallback = false;
        for (const auto& existing : out) {
            if (existing.vendorId == p.vendorID && existing.deviceId == p.deviceID) {
                dupFallback = true;
                break;
            }
        }
        if (dupFallback) {
            std::fprintf(stderr,
                "VK_PHYS_DEDUP ordinal=%u name=%s vendor=0x%04X device=0x%04X reason=FALLBACK_DEDUP\n",
                i, p.deviceName, p.vendorID, p.deviceID);
            continue;
        }

        uint32_t qn = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devs[i], &qn, nullptr);
        std::vector<VkQueueFamilyProperties> q(qn);
        vkGetPhysicalDeviceQueueFamilyProperties(devs[i], &qn, q.data());

        bool compute = false;
        for (const auto& f : q)
            if (f.queueCount && (f.queueFlags & VK_QUEUE_COMPUTE_BIT)) {
                compute = true;
                break;
            }

        uint64_t local = 0;
        for (uint32_t h = 0; h < mp.memoryHeapCount; ++h)
            if (mp.memoryHeaps[h].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)
                local += mp.memoryHeaps[h].size;

        VulkanPhysicalInfo d{};
        d.ordinal = static_cast<uint32_t>(out.size());
        d.vendorId = p.vendorID;
        d.deviceId = p.deviceID;
        d.apiVersion = p.apiVersion;
        d.deviceLocalBytes = local;
        d.discrete = p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU;
        d.compute = compute;
        d.name = p.deviceName;
        std::memcpy(d.deviceUUID, idp.deviceUUID, VK_UUID_SIZE);
        std::fprintf(stderr,
            "VK_PHYS ordinal=%u name=%s vendor=0x%04X device=0x%04X type=%u "
            "discrete=%d compute=%d localGB=%.2f\n",
            d.ordinal, d.name.c_str(), d.vendorId, d.deviceId,
            (unsigned)p.deviceType,
            d.discrete ? 1 : 0, d.compute ? 1 : 0,
            (double)d.deviceLocalBytes / (1024.0*1024.0*1024.0));
        out.push_back(std::move(d));
    }

    vkDestroyInstance(inst, nullptr);
    return out;
}

size_t VulkanCompute::ForwardArenaReserveBytes(
    uint32_t hidden, uint32_t intermediate,
    uint32_t, uint32_t kvHeads, uint32_t headDim,
    uint32_t maxSeq, uint32_t layers, uint32_t kvLayers)
{
    const uint64_t H = hidden;
    const uint64_t I = intermediate;
    const uint64_t kv = static_cast<uint64_t>(kvHeads) * headDim;
    const uint64_t seqCap = std::min<uint64_t>(maxSeq ? maxSeq : 1, 4096);
    const uint64_t kvCount = kvLayers ? kvLayers : layers;
    uint64_t floats =
        H * 8ull + I * 3ull + kv * 2ull +
        kvCount * seqCap * kv * 2ull;
    if (floats > std::numeric_limits<size_t>::max() / sizeof(float))
        return std::numeric_limits<size_t>::max();
    return static_cast<size_t>(floats * sizeof(float));
}

size_t VulkanCompute::ForwardArenaReserveBytes(int) {
    return 0;
}

bool VulkanCompute::createInstance() {
    VkApplicationInfo app{};
    app.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app.pApplicationName = "RawrXD Deep2";
    app.applicationVersion = VK_MAKE_VERSION(9,0,0);
    app.pEngineName = "Deep2 Sovereign";
    app.engineVersion = VK_MAKE_VERSION(9,0,0);
    app.apiVersion = VK_API_VERSION_1_2;

    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.pApplicationInfo = &app;
    return vkCreateInstance(&ci, nullptr, &instance_) == VK_SUCCESS;
}

bool VulkanCompute::selectPhysical() {
    uint32_t n = 0;
    if (vkEnumeratePhysicalDevices(instance_, &n, nullptr) != VK_SUCCESS ||
        n == 0) return false;

    std::vector<VkPhysicalDevice> rawDevs(n);
    if (vkEnumeratePhysicalDevices(instance_, &n, rawDevs.data()) != VK_SUCCESS)
        return false;

    // Deduplicate by deviceUUID — match EnumeratePhysicalDevices() ordering
    std::vector<VkPhysicalDevice> devs;
    devs.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        VkPhysicalDeviceProperties p{};
        vkGetPhysicalDeviceProperties(rawDevs[i], &p);
        VkPhysicalDeviceIDProperties idp{
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES
        };
        VkPhysicalDeviceProperties2 p2{
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2
        };
        p2.pNext = &idp;
        vkGetPhysicalDeviceProperties2(rawDevs[i], &p2);
        bool dup = false;
        for (auto existingVk : devs) {
            VkPhysicalDeviceIDProperties existingId{
                VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES
            };
            VkPhysicalDeviceProperties2 existingP2{
                VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2
            };
            existingP2.pNext = &existingId;
            vkGetPhysicalDeviceProperties2(existingVk, &existingP2);
            if (std::memcmp(existingId.deviceUUID, idp.deviceUUID,
                            VK_UUID_SIZE) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        // Fallback dedup by (vendorId, deviceId) to align with EnumeratePhysicalDevices()
        for (auto existingVk : devs) {
            VkPhysicalDeviceProperties existingP{};
            vkGetPhysicalDeviceProperties(existingVk, &existingP);
            if (existingP.vendorID == p.vendorID && existingP.deviceID == p.deviceID) {
                dup = true;
                break;
            }
        }
        if (!dup) devs.push_back(rawDevs[i]);
    }
    if (requestedOrdinal_ >= devs.size()) return false;
    physical_ = devs[requestedOrdinal_];

    VkPhysicalDeviceProperties p{};
    VkPhysicalDeviceMemoryProperties mp{};
    vkGetPhysicalDeviceProperties(physical_, &p);
    vkGetPhysicalDeviceMemoryProperties(physical_, &mp);

    info_.ordinal = requestedOrdinal_;
    info_.vendorId = p.vendorID;
    info_.deviceId = p.deviceID;
    info_.apiVersion = p.apiVersion;
    info_.name = p.deviceName;
    info_.discrete = p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU;
    timestampPeriodNs_ = p.limits.timestampPeriod;

    for (uint32_t h = 0; h < mp.memoryHeapCount; ++h)
        if (mp.memoryHeaps[h].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)
            info_.deviceLocalBytes += mp.memoryHeaps[h].size;

    uint32_t qn = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(physical_, &qn, nullptr);
    std::vector<VkQueueFamilyProperties> q(qn);
    vkGetPhysicalDeviceQueueFamilyProperties(physical_, &qn, q.data());

    int best = -1;
    for (uint32_t i = 0; i < qn; ++i) {
        if (!q[i].queueCount || !(q[i].queueFlags & VK_QUEUE_COMPUTE_BIT)) continue;
        if ((q[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) == 0) {
            best = static_cast<int>(i);
            break;
        }
        if (best < 0) best = static_cast<int>(i);
    }
    if (best < 0) return false;

    queueFamily_ = static_cast<uint32_t>(best);
    timestampValidBits_ = q[queueFamily_].timestampValidBits;
    info_.compute = true;
    return true;
}

bool VulkanCompute::createDevice() {
    uint32_t extCount = 0;
    vkEnumerateDeviceExtensionProperties(physical_, nullptr, &extCount, nullptr);
    std::vector<VkExtensionProperties> ext(extCount);
    if (extCount)
        vkEnumerateDeviceExtensionProperties(physical_, nullptr, &extCount, ext.data());

    bool haveCalibrated = false;
    bool haveMemoryBudget = false;
    bool haveExternalMemoryHost = false;
    for (const auto& e : ext) {
        if (std::strcmp(e.extensionName,
                        VK_EXT_CALIBRATED_TIMESTAMPS_EXTENSION_NAME) == 0)
            haveCalibrated = true;
        if (std::strcmp(e.extensionName,
                        VK_EXT_MEMORY_BUDGET_EXTENSION_NAME) == 0)
            haveMemoryBudget = true;
        if (std::strcmp(e.extensionName,
                        VK_EXT_EXTERNAL_MEMORY_HOST_EXTENSION_NAME) == 0)
            haveExternalMemoryHost = true;
    }

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qi{};
    qi.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qi.queueFamilyIndex = queueFamily_;
    qi.queueCount = 1;
    qi.pQueuePriorities = &prio;

    std::vector<const char*> enabled;
    if (haveCalibrated)
        enabled.push_back(VK_EXT_CALIBRATED_TIMESTAMPS_EXTENSION_NAME);
    if (haveMemoryBudget)
        enabled.push_back(VK_EXT_MEMORY_BUDGET_EXTENSION_NAME);
    if (haveExternalMemoryHost)
        enabled.push_back(VK_EXT_EXTERNAL_MEMORY_HOST_EXTENSION_NAME);

    VkDeviceCreateInfo di{};
    di.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    di.queueCreateInfoCount = 1;
    di.pQueueCreateInfos = &qi;
    di.enabledExtensionCount = static_cast<uint32_t>(enabled.size());
    di.ppEnabledExtensionNames = enabled.empty() ? nullptr : enabled.data();

    VkResult vr = vkCreateDevice(physical_, &di, nullptr, &device_);
    if (vr != VK_SUCCESS) {
        std::fprintf(stderr,
            "BATCH9_VK_CREATE_DEVICE_FAIL ordinal=%u vk_result=%d name=%s\n",
            requestedOrdinal_, static_cast<int>(vr), info_.name.c_str());
        return false;
    }

    vkGetDeviceQueue(device_, queueFamily_, 0, &queue_);
    memoryBudgetAvailable_ = haveMemoryBudget;

    if (haveCalibrated) {
        fpGetCalibrated_ = reinterpret_cast<PFN_vkGetCalibratedTimestampsEXT>(
            vkGetDeviceProcAddr(device_, "vkGetCalibratedTimestampsEXT"));

        auto fpDomains =
            reinterpret_cast<PFN_vkGetPhysicalDeviceCalibrateableTimeDomainsEXT>(
                vkGetInstanceProcAddr(
                    instance_, "vkGetPhysicalDeviceCalibrateableTimeDomainsEXT"));

        if (fpGetCalibrated_ && fpDomains) {
            uint32_t count = 0;
            if (fpDomains(physical_, &count, nullptr) == VK_SUCCESS && count) {
                std::vector<VkTimeDomainEXT> domains(count);
                if (fpDomains(physical_, &count, domains.data()) == VK_SUCCESS) {
#ifdef _WIN32
                    auto want = VK_TIME_DOMAIN_QUERY_PERFORMANCE_COUNTER_EXT;
#else
                    auto want = VK_TIME_DOMAIN_CLOCK_MONOTONIC_EXT;
#endif
                    if (std::find(domains.begin(), domains.end(), want) != domains.end()) {
                        hostTimeDomain_ = want;
                        calibratedAvailable_ = timestampValidBits_ != 0;
                    }
                }
            }
        }
    }

    return true;
}

VulkanCompute::SharedHostImportResult
VulkanCompute::TestSharedHostImport(size_t testBytes) const {
    SharedHostImportResult r{};
    if (!device_) return r;

    const size_t allocSize = testBytes > 0 ? testBytes : 4096;
    const size_t alignedSize = (allocSize + 4095ULL) & ~4095ULL;

    // Use VirtualAlloc for guaranteed page-aligned allocation (≥64 KiB alignment).
    void* hostPtr = VirtualAlloc(nullptr, alignedSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!hostPtr) return r;

    auto fpGetMemProps = reinterpret_cast<PFN_vkGetMemoryHostPointerPropertiesEXT>(
        vkGetDeviceProcAddr(device_, "vkGetMemoryHostPointerPropertiesEXT"));
    if (!fpGetMemProps) {
        VirtualFree(hostPtr, 0, MEM_RELEASE);
        return r;
    }

    VkMemoryHostPointerPropertiesEXT props{};
    props.sType = VK_STRUCTURE_TYPE_MEMORY_HOST_POINTER_PROPERTIES_EXT;
    VkResult qr = fpGetMemProps(device_, VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT,
                                  hostPtr, &props);
    r.hostPointerQueryResult = static_cast<int32_t>(qr);
    if (qr != VK_SUCCESS) {
        VirtualFree(hostPtr, 0, MEM_RELEASE);
        return r;
    }
    r.memoryTypeBits = props.memoryTypeBits;

    VkPhysicalDeviceMemoryProperties mp{};
    vkGetPhysicalDeviceMemoryProperties(physical_, &mp);

    uint32_t memType = UINT32_MAX;
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i) {
        if ((props.memoryTypeBits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            memType = i;
            break;
        }
    }
    if (memType == UINT32_MAX) {
        for (uint32_t i = 0; i < mp.memoryTypeCount; ++i) {
            if (props.memoryTypeBits & (1u << i)) {
                memType = i;
                break;
            }
        }
    }
    if (memType == UINT32_MAX) {
        VirtualFree(hostPtr, 0, MEM_RELEASE);
        r.importMemoryResult = static_cast<int32_t>(VK_ERROR_INCOMPATIBLE_DRIVER);
        return r;
    }

    VkImportMemoryHostPointerInfoEXT importInfo{};
    importInfo.sType = VK_STRUCTURE_TYPE_IMPORT_MEMORY_HOST_POINTER_INFO_EXT;
    importInfo.handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_HOST_ALLOCATION_BIT_EXT;
    importInfo.pHostPointer = hostPtr;

    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = alignedSize;
    ai.memoryTypeIndex = memType;
    ai.pNext = &importInfo;

    VkDeviceMemory importedMemory = VK_NULL_HANDLE;
    VkResult ar = vkAllocateMemory(device_, &ai, nullptr, &importedMemory);
    r.importMemoryResult = static_cast<int32_t>(ar);
    if (ar != VK_SUCCESS) {
        VirtualFree(hostPtr, 0, MEM_RELEASE);
        return r;
    }

    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = alignedSize;
    bi.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkBuffer buffer = VK_NULL_HANDLE;
    VkResult br = vkCreateBuffer(device_, &bi, nullptr, &buffer);
    if (br != VK_SUCCESS) {
        vkFreeMemory(device_, importedMemory, nullptr);
        VirtualFree(hostPtr, 0, MEM_RELEASE);
        r.bindResult = static_cast<int32_t>(br);
        return r;
    }

    VkResult bindR = vkBindBufferMemory(device_, buffer, importedMemory, 0);
    r.bindResult = static_cast<int32_t>(bindR);

    vkDestroyBuffer(device_, buffer, nullptr);
    vkFreeMemory(device_, importedMemory, nullptr);
    VirtualFree(hostPtr, 0, MEM_RELEASE);
    return r;
}

bool VulkanCompute::createCommandPool() {
    VkCommandPoolCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    ci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT |
               VK_COMMAND_POOL_CREATE_TRANSIENT_BIT;
    ci.queueFamilyIndex = queueFamily_;
    return vkCreateCommandPool(device_, &ci, nullptr, &commandPool_) == VK_SUCCESS;
}

bool VulkanCompute::createDescriptorSystems() {
    VkDescriptorPoolSize ps{};
    ps.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    ps.descriptorCount = 524288;

    VkDescriptorPoolCreateInfo pi{};
    pi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pi.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    pi.maxSets = 131072;
    pi.poolSizeCount = 1;
    pi.pPoolSizes = &ps;
    if (vkCreateDescriptorPool(device_, &pi, nullptr, &descriptorPool_) != VK_SUCCESS)
        return false;

    VkDescriptorSetLayoutBinding ops[4]{};
    for (uint32_t i = 0; i < 4; ++i) {
        ops[i].binding = i;
        ops[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        ops[i].descriptorCount = 1;
        ops[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo oi{};
    oi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    oi.bindingCount = 4;
    oi.pBindings = ops;
    if (vkCreateDescriptorSetLayout(device_, &oi, nullptr, &opsSetLayout_) != VK_SUCCESS)
        return false;

    VkDescriptorSetLayoutBinding qb[3]{};
    for (uint32_t i = 0; i < 3; ++i) {
        qb[i].binding = i;
        qb[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        qb[i].descriptorCount = 1;
        qb[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo qi{};
    qi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    qi.bindingCount = 3;
    qi.pBindings = qb;
    return vkCreateDescriptorSetLayout(device_, &qi, nullptr, &qSetLayout_) == VK_SUCCESS;
}

std::string VulkanCompute::shaderPath(const char* file) const {
    std::vector<std::filesystem::path> dirs;
    if (const char* env = std::getenv("RAWRXD_DEEP2_SHADER_DIR"))
        dirs.emplace_back(env);
#ifdef DEEP2_SHADER_DIR
    dirs.emplace_back(DEEP2_SHADER_DIR);
#endif
    dirs.emplace_back(std::filesystem::path(__FILE__).parent_path() / "shaders");
    dirs.emplace_back("src/deep2/shaders");
    dirs.emplace_back("~dev/rawrxd/src/deep2/shaders");
    dirs.emplace_back("shaders");
    dirs.emplace_back("shaders/deep2");

    for (const auto& d : dirs) {
        auto p = d / file;
        std::error_code ec;
        if (std::filesystem::exists(p, ec))
            return p.string();
    }
    return {};
}

bool VulkanCompute::createPipelineFromFile(
    const std::string& file, VkDescriptorSetLayout layout,
    uint32_t pushBytes, VkPipelineLayout& pipelineLayout,
    VkPipeline& pipeline)
{
    std::ifstream f(file, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize sz = f.tellg();
    if (sz <= 0 || (sz % 4) != 0) return false;
    f.seekg(0, std::ios::beg);

    std::vector<uint32_t> code(static_cast<size_t>(sz) / 4);
    if (!f.read(reinterpret_cast<char*>(code.data()), sz)) return false;

    VkShaderModuleCreateInfo sm{};
    sm.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    sm.codeSize = static_cast<size_t>(sz);
    sm.pCode = code.data();
    VkShaderModule module = VK_NULL_HANDLE;
    if (vkCreateShaderModule(device_, &sm, nullptr, &module) != VK_SUCCESS)
        return false;

    VkPushConstantRange pcr{};
    pcr.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pcr.offset = 0;
    pcr.size = pushBytes;

    VkPipelineLayoutCreateInfo li{};
    li.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    li.setLayoutCount = 1;
    li.pSetLayouts = &layout;
    li.pushConstantRangeCount = pushBytes ? 1u : 0u;
    li.pPushConstantRanges = pushBytes ? &pcr : nullptr;

    bool ok = vkCreatePipelineLayout(device_, &li, nullptr, &pipelineLayout)
              == VK_SUCCESS;
    if (ok) {
        VkPipelineShaderStageCreateInfo stage{};
        stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
        stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
        stage.module = module;
        stage.pName = "main";

        VkComputePipelineCreateInfo ci{};
        ci.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
        ci.stage = stage;
        ci.layout = pipelineLayout;
        ok = vkCreateComputePipelines(
                 device_, VK_NULL_HANDLE, 1, &ci, nullptr, &pipeline)
             == VK_SUCCESS;
    }
    vkDestroyShaderModule(device_, module, nullptr);
    return ok;
}

bool VulkanCompute::createPipelines() {
    const std::string ops = shaderPath("deep2_ops.spv");
    const std::string q = shaderPath("deep2_qgemv.spv");
    const std::string qb = shaderPath("deep2_qgemv_batch.spv");
    const std::string q4r = shaderPath("deep2_qgemv_batch4row.spv");
    const std::string q8r = shaderPath("deep2_qgemv_batch8row.spv");
    const std::string am = shaderPath("deep2_argmax.spv");
    const std::string so = shaderPath("deep2_spec_ops.spv");
    const std::string sa = shaderPath("deep2_spec_attn.spv");
    const std::string ac = shaderPath("deep2_spec_accept.spv");

    std::fprintf(stderr,
        "[SHADER_PATH] ops=%s q=%s qb=%s q4r=%s q8r=%s am=%s so=%s sa=%s ac=%s\n",
        ops.empty()?"NOTFOUND":ops.c_str(),
        q.empty()?"NOTFOUND":q.c_str(),
        qb.empty()?"NOTFOUND":qb.c_str(),
        q4r.empty()?"NOTFOUND":q4r.c_str(),
        q8r.empty()?"NOTFOUND":q8r.c_str(),
        am.empty()?"NOTFOUND":am.c_str(),
        so.empty()?"NOTFOUND":so.c_str(),
        sa.empty()?"NOTFOUND":sa.c_str(),
        ac.empty()?"NOTFOUND":ac.c_str());
    std::fflush(stderr);

    bool okOps=false, okQ=false, okQb=false, okQ4r=false, okQ8r=false;
    if (!ops.empty())
        okOps=createPipelineFromFile(
            ops, opsSetLayout_, sizeof(OpsPush), opsPipelineLayout_, opsPipeline_);
    if (!q.empty())
        okQ=createPipelineFromFile(
            q, qSetLayout_, sizeof(QPush), qPipelineLayout_, qPipeline_);
    if(!qb.empty())
        okQb=createPipelineFromFile(
            qb,qSetLayout_,sizeof(QBatchPush),
            qBatchPipelineLayout_,qBatchPipeline_);
    if(!q4r.empty())
        okQ4r=createPipelineFromFile(
            q4r,qSetLayout_,sizeof(QBatchPush),
            qBatch4RowPipelineLayout_,qBatch4RowPipeline_);
    if(!q8r.empty())
        okQ8r=createPipelineFromFile(
            q8r,qSetLayout_,sizeof(QBatchPush),
            qBatch8RowPipelineLayout_,qBatch8RowPipeline_);
    if(!am.empty())
        (void)createPipelineFromFile(
            am,qSetLayout_,sizeof(ArgmaxPush),
            argmaxPipelineLayout_,argmaxPipeline_);
    if(!so.empty())
        (void)createPipelineFromFile(
            so,opsSetLayout_,sizeof(SpecOpsPush),
            specOpsPipelineLayout_,specOpsPipeline_);
    if(!sa.empty())
        (void)createPipelineFromFile(
            sa,opsSetLayout_,sizeof(SpecAttnPush),
            specAttnPipelineLayout_,specAttnPipeline_);

    std::fprintf(stderr,
        "[PIPELINE_CREATE] ops=%u q=%u qb=%u q4r=%u q8r=%u\n",
        okOps?1u:0u, okQ?1u:0u, okQb?1u:0u, okQ4r?1u:0u, okQ8r?1u:0u);
    std::fflush(stderr);

    return opsPipeline_ != VK_NULL_HANDLE;
}

bool VulkanCompute::DispatchGemvQ4KBatch8Row(
    const void* weights,size_t weightBytes,
    DeviceBuf& inputBatch,DeviceBuf& outputBatch,
    uint32_t rows,uint32_t cols,uint32_t batch)
{
    if(!qBatch8RowPipeline_||!weights||!weightBytes||
       !rows||!cols||!batch||batch>4) return false;
    DeviceBuf* wb=nullptr;
    if(!ensureWeightQuant(12,weights,weightBytes,wb)) return false;
    VkCommandBuffer cmd=fusedCmd_;
    VkQueryPool query=fusedQuery_;
    const bool own=!fused_;
    if(own&&!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getQuantDescriptor(*wb,inputBatch,outputBatch);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,qBatch8RowPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,qBatch8RowPipelineLayout_,
        0,1,&set,0,nullptr);
    QBatchPush p{};
    p.type=12;p.rows=rows;p.cols=cols;
    p.weightBytes=(uint32_t)weightBytes;p.batch=batch;
    vkCmdPushConstants(
        cmd,qBatch8RowPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    vkCmdDispatch(cmd,(rows+7u)/8u,1,1);
    recordComputeBarrier(cmd);
    ++q4kBatch8RowOps_;
    q4kBatchWeightBytes_+=weightBytes;
    if(!own) return true;
    GpuWorkInterval wi{};
    const bool ok=endSubmitWait(
        cmd,query,GpuWorkKind::ModelCompute,
        weightBytes,workEpoch_,&wi);
    if(ok) q4kBatchGpuNs_+=wi.calibratedDurationNs();
    return ok;
}

VulkanCompute::Q4KBatchTile VulkanCompute::SelectQ4KBatchTile(
    const void* weights,size_t weightBytes,
    DeviceBuf& inputBatch,DeviceBuf& scratchOutput,
    uint32_t rows,uint32_t cols,uint32_t batch)
{
    const char* force=std::getenv("DEEP2_Q4K_FORCE_TILE");
    if(force&&force[0]=='8') return Q4KBatchTile::Eight;
    if(force&&force[0]=='4') return Q4KBatchTile::Four;
    const char* at=std::getenv("DEEP2_Q4K_AUTOTUNE");
    if(at&&at[0]=='0') return Q4KBatchTile::Four;

    Q4KTileKey key{rows,cols,batch};
    auto it=q4kTileChoices_.find(key);
    if(it!=q4kTileChoices_.end()) return it->second.tile;

    // Autotune is warmup-only and only when not inside an existing fused cmd.
    // If called during fused execution, defer the choice to 4-row until a
    // standalone warmup call seals this geometry.
    if(fused_||!qBatch8RowPipeline_) return Q4KBatchTile::Four;

    auto timeOne=[&](Q4KBatchTile t)->uint64_t {
        uint64_t before=q4kBatchGpuNs_;
        bool ok=t==Q4KBatchTile::Eight
            ? DispatchGemvQ4KBatch8Row(
                weights,weightBytes,inputBatch,scratchOutput,
                rows,cols,batch)
            : DispatchGemvQ4KBatch4Row(
                weights,weightBytes,inputBatch,scratchOutput,
                rows,cols,batch);
        if(!ok) return UINT64_MAX;
        return q4kBatchGpuNs_-before;
    };
    const uint64_t n4=timeOne(Q4KBatchTile::Four);
    const uint64_t n8=timeOne(Q4KBatchTile::Eight);
    Q4KTileChoice c{};
    c.fourNs=n4;c.eightNs=n8;
    c.tile=(n8<n4)?Q4KBatchTile::Eight:Q4KBatchTile::Four;
    q4kTileChoices_[key]=c;
    ++q4kAutotuneRuns_;
    return c.tile;
}

bool VulkanCompute::DispatchGemvQ4KBatch4Row(
    const void* weights,size_t weightBytes,
    DeviceBuf& inputBatch,DeviceBuf& outputBatch,
    uint32_t rows,uint32_t cols,uint32_t batch)
{
    if(!qBatch4RowPipeline_||!weights||!weightBytes||
       !rows||!cols||!batch||batch>4)
        return false;
    DeviceBuf* wb=nullptr;
    if(!ensureWeightQuant(12,weights,weightBytes,wb)) return false;

    VkCommandBuffer cmd=fusedCmd_;
    VkQueryPool query=fusedQuery_;
    const bool own=!fused_;
    if(own&&!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getQuantDescriptor(*wb,inputBatch,outputBatch);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,qBatch4RowPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,qBatch4RowPipelineLayout_,
        0,1,&set,0,nullptr);
    QBatchPush p{};
    p.type=12;p.rows=rows;p.cols=cols;
    p.weightBytes=(uint32_t)weightBytes;p.batch=batch;
    vkCmdPushConstants(
        cmd,qBatch4RowPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    vkCmdDispatch(cmd,(rows+3u)/4u,1,1);
    recordComputeBarrier(cmd);
    ++q4kBatch4RowOps_;
    q4kBatchWeightBytes_+=weightBytes;
    if(!own) return true;

    GpuWorkInterval wi{};
    const bool ok=endSubmitWait(
        cmd,query,GpuWorkKind::ModelCompute,
        weightBytes,workEpoch_,&wi);
    if(ok) q4kBatchGpuNs_+=wi.calibratedDurationNs();
    return ok;
}

bool VulkanCompute::RunSpecAttentionHostBatch(
    const float* q,const float* k,const float* v,float* output,
    uint32_t heads,uint32_t kvHeads,uint32_t headDim,
    uint32_t seqLen,uint32_t basePos,uint32_t batch,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!q||!k||!v||!output||!heads||!kvHeads||!headDim||
       !seqLen||!batch||batch>4||heads%kvHeads!=0)
        return false;
    SetWorkEpoch(epoch);
    const size_t qn=(size_t)batch*heads*headDim;
    const size_t kvn=(size_t)kvHeads*seqLen*headDim;
    if(!EnsureScratch(100,qn)||!EnsureScratch(101,kvn)||
       !EnsureScratch(102,kvn)||!EnsureScratch(103,qn))
        return false;
    auto& qb=Scratch(100);auto& kb=Scratch(101);
    auto& vb=Scratch(102);auto& ob=Scratch(103);
    if(!UploadVector(qb,q,qn)||!UploadVector(kb,k,kvn)||
       !UploadVector(vb,v,kvn))
        return false;

    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getOpsDescriptor(qb,kb,vb,ob);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAttnPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAttnPipelineLayout_,
        0,1,&set,0,nullptr);
    SpecAttnPush p{};
    p.headDim=headDim;p.heads=heads;p.kvHeads=kvHeads;
    p.seqLen=seqLen;p.basePos=basePos;p.batch=batch;
    p.scale=1.0f/std::sqrt((float)headDim);
    vkCmdPushConstants(
        cmd,specAttnPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    const uint32_t total=batch*heads*headDim;
    vkCmdDispatch(cmd,(total+63u)/64u,1,1);
    recordComputeBarrier(cmd);
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelCompute,0,epoch,nullptr))
        return false;
    return DownloadVector(ob,output,qn);
}

bool VulkanCompute::dispatchSpecOps(
    DeviceBuf& a,DeviceBuf& b,DeviceBuf& c,DeviceBuf& d,
    const SpecOpsPush& p)
{
    if(!specOpsPipeline_||!p.width||!p.batch||p.batch>4) return false;
    VkCommandBuffer cmd=fusedCmd_;
    VkQueryPool query=fusedQuery_;
    const bool own=!fused_;
    if(own&&!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getOpsDescriptor(a,b,c,d);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specOpsPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specOpsPipelineLayout_,
        0,1,&set,0,nullptr);
    vkCmdPushConstants(
        cmd,specOpsPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    vkCmdDispatch(cmd,p.batch,1,1);
    recordComputeBarrier(cmd);
    if(!own) return true;
    return endSubmitWait(
        cmd,query,GpuWorkKind::ModelCompute,0,workEpoch_,nullptr);
}

bool VulkanCompute::RunSpecRmsNormHostBatch(
    const float* input,const float* weight,float* output,
    uint32_t width,uint32_t batch,float eps,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!input||!weight||!output||!width||!batch||batch>4) return false;
    SetWorkEpoch(epoch);
    const size_t n=(size_t)width*batch;
    if(!EnsureScratch(90,n)||!EnsureScratch(91,width)||
       !EnsureScratch(92,n)||!EnsureScratch(93,1))
        return false;
    auto& in=Scratch(90);auto& w=Scratch(91);
    auto& out=Scratch(92);auto& dummy=Scratch(93);
    if(!UploadVector(in,input,n)||!UploadVector(w,weight,width))
        return false;
    SpecOpsPush p{};p.op=0;p.width=width;p.batch=batch;p.eps=eps;
    if(!dispatchSpecOps(in,w,out,dummy,p)) return false;
    return DownloadVector(out,output,n);
}

bool VulkanCompute::RunSpecSwiGLUHostBatch(
    const float* gate,const float* up,float* output,
    uint32_t width,uint32_t batch,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!gate||!up||!output||!width||!batch||batch>4) return false;
    SetWorkEpoch(epoch);
    const size_t n=(size_t)width*batch;
    const size_t nbytes=n*sizeof(float);
    std::fprintf(stderr,"[SwiGLU] width=%u batch=%u n=%zu nbytes=%zu\n",width,batch,n,nbytes); std::fflush(stderr);

    if(!EnsureScratch(94,n)||!EnsureScratch(95,n)||
       !EnsureScratch(96,n)||!EnsureScratch(97,1))
        return false;
    auto& g=Scratch(94);auto& u=Scratch(95);
    auto& o=Scratch(96);auto& d=Scratch(97);
    std::fprintf(stderr,"[SwiGLU] buf g(id=%llu size=%zu) u(id=%llu size=%zu) o(id=%llu size=%zu) d(id=%llu size=%zu)\n",
        (unsigned long long)g.id,(size_t)g.size,(unsigned long long)u.id,(size_t)u.size,(unsigned long long)o.id,(size_t)o.size,(unsigned long long)d.id,(size_t)d.size); std::fflush(stderr);
    if(g.size<nbytes||u.size<nbytes||o.size<nbytes||d.size<sizeof(float)){
        std::fprintf(stderr,"[SwiGLU] FATAL: scratch undersized\n"); std::fflush(stderr);
        return false;
    }

    if(!UploadVector(g,gate,n)||!UploadVector(u,up,n)) return false;
    SpecOpsPush p{};p.op=1;p.width=width;p.batch=batch;
    std::fprintf(stderr,"[SwiGLU] dispatch op=%u width=%u batch=%u\n",p.op,p.width,p.batch); std::fflush(stderr);
    if(!dispatchSpecOps(g,u,o,d,p)) return false;
    std::fprintf(stderr,"[SwiGLU] download n=%zu\n",n); std::fflush(stderr);
    return DownloadVector(o,output,n);
}

bool VulkanCompute::DispatchArgmaxBatch(
    DeviceBuf& logits,DeviceBuf& values,DeviceBuf& indices,
    uint32_t rows,uint32_t batch)
{
    if(!argmaxPipeline_||!rows||!batch||batch>4) return false;
    VkCommandBuffer cmd=fusedCmd_;
    VkQueryPool query=fusedQuery_;
    const bool own=!fused_;
    if(own&&!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getQuantDescriptor(logits,values,indices);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,argmaxPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,argmaxPipelineLayout_,
        0,1,&set,0,nullptr);
    ArgmaxPush p{rows,batch};
    vkCmdPushConstants(
        cmd,argmaxPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    vkCmdDispatch(cmd,batch,1,1);
    recordComputeBarrier(cmd);
    if(!own) return true;
    return endSubmitWait(
        cmd,query,GpuWorkKind::ModelCompute,0,workEpoch_,nullptr);
}

bool VulkanCompute::RunWeightBatchQ4KTop1(
    const GpuWeightView& weight,const float* inputBatch,uint32_t batch,
    uint32_t rowBase,uint32_t* outIndex,float* outValue,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weight.valid()||weight.type!=12||!inputBatch||!outIndex||!outValue||
       !batch||batch>4) return false;
    SetWorkEpoch(epoch);
    const size_t inCount=(size_t)batch*weight.cols;
    const size_t logitCount=(size_t)batch*weight.rows;
    if(!EnsureScratch(80,inCount)||!EnsureScratch(81,logitCount)||
       !EnsureScratch(82,batch)||!EnsureScratch(83,batch))
        return false;
    auto& in=Scratch(80);auto& lg=Scratch(81);
    auto& mv=Scratch(82);auto& mi=Scratch(83);
    const size_t inBytes=inCount*sizeof(float);
    const size_t retBytes=batch*(sizeof(float)+sizeof(uint32_t));
    DeviceBuf* us=nullptr;DeviceBuf* ds=nullptr;
    void* um=nullptr;void* dm=nullptr;
    if(!ensureMappedStaging(true,inBytes,us,um)||
       !ensureMappedStaging(false,retBytes,ds,dm))
        return false;
    std::memcpy(um,inputBatch,inBytes);
    if(!BeginFusedLayer()) return false;
    if(!recordCopy(fusedCmd_,*us,in,inBytes)||
       !DispatchGemvQ4KBatch(
           weight.data,weight.bytes,in,lg,weight.rows,weight.cols,batch)||
       !DispatchArgmaxBatch(lg,mv,mi,weight.rows,batch)||
       !recordCopy(fusedCmd_,mv,*ds,batch*sizeof(float),0,0)||
       !recordCopy(fusedCmd_,mi,*ds,batch*sizeof(uint32_t),0,
                   batch*sizeof(float))) {
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    }
    if(!EndFusedLayer()) return false;
    const float* vals=(const float*)dm;
    const uint32_t* idx=(const uint32_t*)(
        (const uint8_t*)dm+batch*sizeof(float));
    for(uint32_t b=0;b<batch;++b) {
        outValue[b]=vals[b];
        outIndex[b]=rowBase+idx[b];
    }
    return true;
}

bool VulkanCompute::initialize() {
    cleanup();
    if (!createInstance() || !selectPhysical() || !createDevice() ||
        !createCommandPool() || !createDescriptorSystems()) {
        cleanup();
        return false;
    }

    (void)createPipelines(); // Device runtime is valid even before shader build.
    initialized_ = true;
    (void)ReserveDecodeScratch();
    ++deviceGeneration_; // any pre-init promotion is now stale
    residentDispatchDepth_ = 0;

    std::fprintf(stderr,
        "BATCH9_VK_DEVICE ordinal=%u name=%s vendor=0x%04x vram=%llu "
        "compute_pipeline=%u qgemv_pipeline=%u batch4row=%u batch8row=%u calibrated=%u\n",
        info_.ordinal, info_.name.c_str(), info_.vendorId,
        static_cast<unsigned long long>(info_.deviceLocalBytes),
        opsPipeline_ ? 1u : 0u, qPipeline_ ? 1u : 0u,
        qBatch4RowPipeline_ ? 1u : 0u, qBatch8RowPipeline_ ? 1u : 0u,
        calibratedAvailable_ ? 1u : 0u);
    return true;
}

bool VulkanCompute::ReserveDecodeScratch() {
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    const size_t bytes = 128u * 1024u * 1024u; // 128 MiB
    const size_t floats = bytes / sizeof(float);
    if (!EnsureScratch(104, floats)) {
        std::fprintf(stderr, "[SCRATCH_RESERVE_FAIL] attention bytes=%zu\n", bytes);
        return false;
    }
    scratchReservedBytes_ = bytes;
    std::fprintf(stderr, "[SCRATCH_RESERVE_OK] attention bytes=%zu\n", bytes);
    return true;
}

uint32_t VulkanCompute::findMemoryType(
    uint32_t bits, VkMemoryPropertyFlags required) const
{
    VkPhysicalDeviceMemoryProperties mp{};
    vkGetPhysicalDeviceMemoryProperties(physical_, &mp);
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i)
        if ((bits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & required) == required)
            return i;
    return UINT32_MAX;
}

size_t VulkanCompute::deviceLocalHeapHeadroom() const {
    if (!memoryBudgetAvailable_) return SIZE_MAX;

    VkPhysicalDeviceMemoryProperties mp{};
    vkGetPhysicalDeviceMemoryProperties(physical_, &mp);

    VkPhysicalDeviceMemoryBudgetPropertiesEXT budget{};
    budget.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_BUDGET_PROPERTIES_EXT;

    VkPhysicalDeviceMemoryProperties2 mp2{};
    mp2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2;
    mp2.pNext = &budget;

    vkGetPhysicalDeviceMemoryProperties2(physical_, &mp2);

    size_t total = 0;
    for (uint32_t h = 0; h < mp.memoryHeapCount; ++h) {
        if (mp.memoryHeaps[h].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
            if (budget.heapBudget[h] > budget.heapUsage[h])
                total += static_cast<size_t>(budget.heapBudget[h] - budget.heapUsage[h]);
        }
    }
    return total;
}

bool VulkanCompute::checkLiveHeapAdmission(size_t bytes) const {
    if (!memoryBudgetAvailable_) return true;
    size_t headroom = deviceLocalHeapHeadroom();
    size_t emergency = info_.deviceLocalBytes / 20;
    const size_t minEmergency = (size_t)512 << 20;
    const size_t maxEmergency = (size_t)2048 << 20;
    if (emergency < minEmergency) emergency = minEmergency;
    if (emergency > maxEmergency) emergency = maxEmergency;
    if (headroom <= emergency) return false;
    if (bytes > headroom - emergency) return false;
    return true;
}

bool VulkanCompute::createBuffer(
    VkDeviceSize bytes, VkBufferUsageFlags usage,
    VkMemoryPropertyFlags required, DeviceBuf& out)
{
    destroyBuffer(out);
    if (!device_ || bytes == 0) {
        fprintf(stderr, "[CB_FAIL] device=%p bytes=%zu\n", (void*)device_, (size_t)bytes);
        return false;
    }

    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = bytes;
    bi.usage = usage;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    VkResult rcb = vkCreateBuffer(device_, &bi, nullptr, &out.buffer);
    if (rcb != VK_SUCCESS) {
        fprintf(stderr, "[CB_FAIL] vkCreateBuffer failed bytes=%zu rc=%d\n", (size_t)bytes, (int)rcb);
        return false;
    }

    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(device_, out.buffer, &mr);
    uint32_t mt = findMemoryType(mr.memoryTypeBits, required);
    if (mt == UINT32_MAX) {
        fprintf(stderr, "[CB_FAIL] findMemoryType failed bytes=%zu memTypeBits=0x%x required=0x%x\n",
                (size_t)bytes, mr.memoryTypeBits, (unsigned)required);
        vkDestroyBuffer(device_, out.buffer, nullptr);
        out = {};
        return false;
    }

    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = mr.size;
    ai.memoryTypeIndex = mt;
    VkResult ram = vkAllocateMemory(device_, &ai, nullptr, &out.memory);
    if (ram != VK_SUCCESS) {
        fprintf(stderr, "[CB_FAIL] vkAllocateMemory failed bytes=%zu allocSize=%zu mt=%u rc=%d\n",
                (size_t)bytes, (size_t)mr.size, mt, (int)ram);
        vkDestroyBuffer(device_, out.buffer, nullptr);
        out = {};
        return false;
    }
    if (vkBindBufferMemory(device_, out.buffer, out.memory, 0) != VK_SUCCESS) {
        fprintf(stderr, "[CB_FAIL] vkBindBufferMemory failed bytes=%zu\n", (size_t)bytes);
        destroyBuffer(out);
        return false;
    }
    out.size = bytes;
    out.memoryFlags = required;
    out.id = nextBufferId_++;
    return true;
}

void VulkanCompute::destroyBuffer(DeviceBuf& b) {
    if (!device_) { b = {}; return; }
    if (b.buffer) vkDestroyBuffer(device_, b.buffer, nullptr);
    if (b.memory) vkFreeMemory(device_, b.memory, nullptr);
    b = {};
}

bool VulkanCompute::ensureMappedStaging(
    bool upload, size_t bytes, DeviceBuf*& buffer, void*& mapped)
{
    buffer = upload ? &uploadStaging_ : &downloadStaging_;
    void*& mapRef = upload ? uploadMapped_ : downloadMapped_;
    size_t& cap = upload ? uploadStagingBytes_ : downloadStagingBytes_;

    if (buffer->buffer && cap >= bytes && mapRef) {
        mapped = mapRef;
        return true;
    }

    if (mapRef && buffer->memory) {
        vkUnmapMemory(device_, buffer->memory);
        mapRef = nullptr;
    }
    destroyBuffer(*buffer);
    cap = 0;

    // Geometric growth prevents repeated realloc when activation dimensions
    // alternate between hidden and FFN widths.
    size_t want = 4096;
    while (want < bytes && want <= std::numeric_limits<size_t>::max() / 2u)
        want *= 2u;
    if (want < bytes) want = bytes;

    const VkBufferUsageFlags usage = upload
        ? VK_BUFFER_USAGE_TRANSFER_SRC_BIT
        : VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    if (!createBuffer(
            want, usage,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
            VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
            *buffer))
        return false;

    if (vkMapMemory(device_, buffer->memory, 0, want, 0, &mapRef) != VK_SUCCESS) {
        destroyBuffer(*buffer);
        mapRef = nullptr;
        return false;
    }
    cap = want;
    mapped = mapRef;
    return true;
}

bool VulkanCompute::beginCommand(
    VkCommandBuffer& cmd, VkQueryPool& query, bool timestamped)
{
    cmd = VK_NULL_HANDLE;
    query = VK_NULL_HANDLE;
    VkCommandBufferAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool = commandPool_;
    ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = 1;
    if (vkAllocateCommandBuffers(device_, &ai, &cmd) != VK_SUCCESS)
        return false;

    if (timestamped && timestampValidBits_) {
        VkQueryPoolCreateInfo qi{};
        qi.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        qi.queryType = VK_QUERY_TYPE_TIMESTAMP;
        qi.queryCount = 2;
        if (vkCreateQueryPool(device_, &qi, nullptr, &query) != VK_SUCCESS)
            query = VK_NULL_HANDLE;
    }

    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(cmd, &bi) != VK_SUCCESS) {
        if (query) vkDestroyQueryPool(device_, query, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
        cmd = VK_NULL_HANDLE;
        query = VK_NULL_HANDLE;
        return false;
    }

    if (query) {
        vkCmdResetQueryPool(cmd, query, 0, 2);
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, query, 0);
    }
    return true;
}

bool VulkanCompute::calibrateTick(uint64_t deviceTick, uint64_t& hostNs) const {
    hostNs = 0;
    if (!calibratedAvailable_ || !fpGetCalibrated_ || !timestampValidBits_)
        return false;

    VkCalibratedTimestampInfoEXT infos[2]{};
    infos[0].sType = VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT;
    infos[0].timeDomain = VK_TIME_DOMAIN_DEVICE_EXT;
    infos[1].sType = VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT;
    infos[1].timeDomain = hostTimeDomain_;

    uint64_t ts[2]{};
    uint64_t maxDev = 0;
    if (fpGetCalibrated_(device_, 2, infos, ts, &maxDev) != VK_SUCCESS)
        return false;

    const uint64_t hostCalNs = hostDomainToNs(hostTimeDomain_, ts[1]);
    if (!hostCalNs) return false;

    uint64_t mask = ~0ull;
    if (timestampValidBits_ < 64)
        mask = (1ull << timestampValidBits_) - 1ull;

    const uint64_t cal = ts[0] & mask;
    const uint64_t ev = deviceTick & mask;
    const uint64_t deltaTicks = (cal - ev) & mask;
    const long double deltaNs =
        static_cast<long double>(deltaTicks) *
        static_cast<long double>(timestampPeriodNs_);

    if (deltaNs > static_cast<long double>(hostCalNs)) return false;
    hostNs = hostCalNs - static_cast<uint64_t>(deltaNs);
    return true;
}

bool VulkanCompute::finalizeInterval(
    VkQueryPool query, uint64_t hostSubmitNs, uint64_t hostCompleteNs,
    uint64_t epoch, uint64_t bytes, GpuWorkKind kind,
    GpuWorkInterval& out)
{
    out = {};
    out.epoch = epoch;
    out.hostSubmitNs = hostSubmitNs;
    out.hostCompleteNs = hostCompleteNs;
    out.bytes = bytes;
    out.deviceOrdinal = requestedOrdinal_;
    out.kind = kind;

    if (!query) return true;

    uint64_t q[2]{};
    VkResult vr = vkGetQueryPoolResults(
        device_, query, 0, 2, sizeof(q), q, sizeof(uint64_t),
        VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WAIT_BIT);
    if (vr != VK_SUCCESS) return true;

    uint64_t s = 0, e = 0;
    if (calibrateTick(q[0], s) && calibrateTick(q[1], e) && e >= s) {
        out.gpuStartNs = s;
        out.gpuEndNs = e;
        out.calibrated = true;
    }
    return true;
}

void VulkanCompute::recordInterval(const GpuWorkInterval& interval) {
    std::lock_guard<std::mutex> lock(intervalMu_);
    intervals_.push_back(interval);
    while (intervals_.size() > 256) intervals_.pop_front();
}

bool VulkanCompute::endSubmitWait(
    VkCommandBuffer cmd, VkQueryPool query,
    GpuWorkKind kind, uint64_t bytes, uint64_t epoch,
    GpuWorkInterval* interval)
{
    if (!cmd) return false;
    if (query)
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, query, 1);
    if (vkEndCommandBuffer(cmd) != VK_SUCCESS) return false;

    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence = VK_NULL_HANDLE;
    if (vkCreateFence(device_, &fi, nullptr, &fence) != VK_SUCCESS)
        return false;

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;

    const uint64_t submitNs = nowNs();
    VkResult submit = vkQueueSubmit(queue_, 1, &si, fence);
    if (submit != VK_SUCCESS) {
        vkDestroyFence(device_, fence, nullptr);
        return false;
    }
    ++queueSubmitCount_;

    VkResult wait = vkWaitForFences(device_, 1, &fence, VK_TRUE, UINT64_MAX);
    const uint64_t completeNs = nowNs();

    GpuWorkInterval wi{};
    if (wait == VK_SUCCESS) {
        finalizeInterval(query, submitNs, completeNs, epoch, bytes, kind, wi);
        recordInterval(wi);
        if (interval) *interval = wi;
    }

    vkDestroyFence(device_, fence, nullptr);
    if (query) vkDestroyQueryPool(device_, query, nullptr);
    vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
    return wait == VK_SUCCESS;
}

void VulkanCompute::recordComputeBarrier(VkCommandBuffer cmd) {
    VkMemoryBarrier mb{};
    mb.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER;
    mb.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT | VK_ACCESS_TRANSFER_WRITE_BIT;
    mb.dstAccessMask = VK_ACCESS_SHADER_READ_BIT | VK_ACCESS_SHADER_WRITE_BIT |
                       VK_ACCESS_TRANSFER_READ_BIT | VK_ACCESS_TRANSFER_WRITE_BIT;
    vkCmdPipelineBarrier(
        cmd,
        VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT | VK_PIPELINE_STAGE_TRANSFER_BIT,
        VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT | VK_PIPELINE_STAGE_TRANSFER_BIT,
        0, 1, &mb, 0, nullptr, 0, nullptr);
}

bool VulkanCompute::recordCopy(
    VkCommandBuffer cmd, const DeviceBuf& src, DeviceBuf& dst,
    VkDeviceSize bytes, VkDeviceSize srcOffset, VkDeviceSize dstOffset)
{
    if (!src || !dst || bytes == 0 ||
        srcOffset + bytes > src.size || dstOffset + bytes > dst.size)
        return false;
    VkBufferCopy c{};
    c.srcOffset = srcOffset;
    c.dstOffset = dstOffset;
    c.size = bytes;
    vkCmdCopyBuffer(cmd, src.buffer, dst.buffer, 1, &c);
    recordComputeBarrier(cmd);
    return true;
}

VkDescriptorSet VulkanCompute::getOpsDescriptor(
    DeviceBuf& a,DeviceBuf& b,DeviceBuf& c,DeviceBuf& d)
{
    DescriptorKey key{a.id,b.id,c.id,d.id};
    auto hit=opsDescriptorCache_.find(key);
    if(hit!=opsDescriptorCache_.end()) return hit->second;

    VkDescriptorSetAllocateInfo ai{};
    ai.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ai.descriptorPool=descriptorPool_;
    ai.descriptorSetCount=1;
    ai.pSetLayouts=&opsSetLayout_;
    VkDescriptorSet set=VK_NULL_HANDLE;
    if(vkAllocateDescriptorSets(device_,&ai,&set)!=VK_SUCCESS)
        return VK_NULL_HANDLE;

    DeviceBuf* bufs[4]={&a,&b,&c,&d};
    VkDescriptorBufferInfo bi[4]{};
    VkWriteDescriptorSet wr[4]{};
    for(uint32_t i=0;i<4;++i){
        bi[i].buffer=bufs[i]->buffer;
        bi[i].offset=0;
        bi[i].range=bufs[i]->size;
        wr[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        wr[i].dstSet=set;
        wr[i].dstBinding=i;
        wr[i].descriptorCount=1;
        wr[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        wr[i].pBufferInfo=&bi[i];
    }
    vkUpdateDescriptorSets(device_,4,wr,0,nullptr);
    opsDescriptorCache_.emplace(key,set);
    return set;
}

VkDescriptorSet VulkanCompute::getQuantDescriptor(
    DeviceBuf& w,DeviceBuf& in,DeviceBuf& out)
{
    DescriptorKey key{w.id,in.id,out.id,0};
    auto hit=quantDescriptorCache_.find(key);
    if(hit!=quantDescriptorCache_.end()) return hit->second;

    VkDescriptorSetAllocateInfo ai{};
    ai.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ai.descriptorPool=descriptorPool_;
    ai.descriptorSetCount=1;
    ai.pSetLayouts=&qSetLayout_;
    VkDescriptorSet set=VK_NULL_HANDLE;
    if(vkAllocateDescriptorSets(device_,&ai,&set)!=VK_SUCCESS)
        return VK_NULL_HANDLE;

    DeviceBuf* bufs[3]={&w,&in,&out};
    VkDescriptorBufferInfo bi[3]{};
    VkWriteDescriptorSet wr[3]{};
    for(uint32_t i=0;i<3;++i){
        bi[i].buffer=bufs[i]->buffer;
        bi[i].offset=0;
        bi[i].range=bufs[i]->size;
        wr[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        wr[i].dstSet=set;
        wr[i].dstBinding=i;
        wr[i].descriptorCount=1;
        wr[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        wr[i].pBufferInfo=&bi[i];
    }
    vkUpdateDescriptorSets(device_,3,wr,0,nullptr);
    quantDescriptorCache_.emplace(key,set);
    return set;
}

VkDescriptorSet VulkanCompute::getQuantDescriptorRange(
    DeviceBuf& w, VkDeviceSize wOffset, VkDeviceSize wRange,
    DeviceBuf& in, DeviceBuf& out)
{
    // DEEP2_COLD_ROW_RACE_001: storage descriptor over a byte RANGE of a
    // (partially promoted) weight buffer so the shader's row indexing
    // starts at rowBase. Range descriptors are never cached: the caller's
    // lane frees them after the fence (vkFreeDescriptorSets), so RCU
    // retirement can never strand a descriptor at a destroyed buffer.
    if (!w || !in || !out || wRange == 0 || wOffset + wRange > w.size)
        return VK_NULL_HANDLE;
    VkDescriptorSetAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ai.descriptorPool = descriptorPool_;
    ai.descriptorSetCount = 1;
    ai.pSetLayouts = &qSetLayout_;
    VkDescriptorSet set = VK_NULL_HANDLE;
    if (vkAllocateDescriptorSets(device_, &ai, &set) != VK_SUCCESS)
        return VK_NULL_HANDLE;

    VkDescriptorBufferInfo bi[3]{};
    VkWriteDescriptorSet wr[3]{};
    DeviceBuf* bufs[3] = {&w, &in, &out};
    for (uint32_t i = 0; i < 3; ++i) {
        bi[i].buffer = bufs[i]->buffer;
        bi[i].offset = i == 0 ? wOffset : 0;
        bi[i].range = i == 0 ? wRange : bufs[i]->size;
        wr[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        wr[i].dstSet = set;
        wr[i].dstBinding = i;
        wr[i].descriptorCount = 1;
        wr[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        wr[i].pBufferInfo = &bi[i];
    }
    vkUpdateDescriptorSets(device_, 3, wr, 0, nullptr);
    return set;
}

bool VulkanCompute::uploadToBuffer(DeviceBuf& dst, const void* src, size_t bytes) {
    if (!dst || !src || !bytes || bytes > dst.size) return false;

    DeviceBuf* staging = nullptr;
    void* mapped = nullptr;
    if (!ensureMappedStaging(true, bytes, staging, mapped)) return false;
    std::memcpy(mapped, src, bytes);

    VkCommandBuffer cmd{};
    VkQueryPool query{};
    return beginCommand(cmd, query, true) &&
           recordCopy(cmd, *staging, dst, bytes) &&
           endSubmitWait(cmd, query, GpuWorkKind::ModelTransfer,
                         bytes, workEpoch_, nullptr);
}

bool VulkanCompute::uploadToBufferRange(
    DeviceBuf& dst,const void* src,size_t bytes,VkDeviceSize dstOffset)
{
    if(!dst||!src||!bytes||dstOffset>dst.size||
       bytes>dst.size-dstOffset)
        return false;
    DeviceBuf* staging=nullptr;
    void* mapped=nullptr;
    if(!ensureMappedStaging(true,bytes,staging,mapped)) return false;
    std::memcpy(mapped,src,bytes);
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    return beginCommand(cmd,query,true) &&
           recordCopy(cmd,*staging,dst,bytes,0,dstOffset) &&
           endSubmitWait(cmd,query,GpuWorkKind::ModelTransfer,
                         bytes,workEpoch_,nullptr);
}

void VulkanCompute::ResetSpecKvMirror() {
    for(auto& b:specKMirror_) destroyBuffer(b);
    for(auto& b:specVMirror_) destroyBuffer(b);
    specKMirror_.clear();specVMirror_.clear();
    specKvLayers_=specKvHeads_=specKvHeadDim_=specKvCapacity_=0;
}

bool VulkanCompute::EnsureSpecKvMirror(
    uint32_t layers,uint32_t kvHeads,uint32_t headDim,uint32_t maxSeq)
{
    if(!layers||!kvHeads||!headDim||!maxSeq) return false;
    if(specKvLayers_==layers&&specKvHeads_==kvHeads&&
       specKvHeadDim_==headDim&&specKvCapacity_==maxSeq&&
       specKMirror_.size()==layers&&specVMirror_.size()==layers)
        return true;

    ResetSpecKvMirror();
    const uint64_t floats=(uint64_t)kvHeads*maxSeq*headDim;
    if(floats>SIZE_MAX/sizeof(float)) return false;
    const size_t bytes=(size_t)floats*sizeof(float);
    specKMirror_.resize(layers);
    specVMirror_.resize(layers);
    for(uint32_t l=0;l<layers;++l) {
        if(!createBuffer(
                bytes,
                VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
                VK_BUFFER_USAGE_TRANSFER_DST_BIT|
                VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,specKMirror_[l])||
           !createBuffer(
                bytes,
                VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
                VK_BUFFER_USAGE_TRANSFER_DST_BIT|
                VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,specVMirror_[l])) {
            ResetSpecKvMirror();
            return false;
        }
    }
    specKvLayers_=layers;specKvHeads_=kvHeads;
    specKvHeadDim_=headDim;specKvCapacity_=maxSeq;
    return true;
}

bool VulkanCompute::UploadSpecKvRange(
    uint32_t layer,uint32_t start,uint32_t count,
    const float* kTokenMajor,const float* vTokenMajor)
{
    if(layer>=specKMirror_.size()||!count||!kTokenMajor||!vTokenMajor||
       start>specKvCapacity_||count>specKvCapacity_-start)
        return false;
    const size_t hd=specKvHeadDim_;
    std::vector<float> tmp((size_t)count*hd);
    for(uint32_t h=0;h<specKvHeads_;++h) {
        for(uint32_t t=0;t<count;++t) {
            const float* ks=kTokenMajor+
                ((size_t)t*specKvHeads_+h)*hd;
            std::memcpy(tmp.data()+(size_t)t*hd,ks,hd*sizeof(float));
        }
        const VkDeviceSize off=
            ((VkDeviceSize)h*specKvCapacity_+start)*hd*sizeof(float);
        if(!uploadToBufferRange(
                specKMirror_[layer],tmp.data(),
                tmp.size()*sizeof(float),off))
            return false;
        for(uint32_t t=0;t<count;++t) {
            const float* vs=vTokenMajor+
                ((size_t)t*specKvHeads_+h)*hd;
            std::memcpy(tmp.data()+(size_t)t*hd,vs,hd*sizeof(float));
        }
        if(!uploadToBufferRange(
                specVMirror_[layer],tmp.data(),
                tmp.size()*sizeof(float),off))
            return false;
    }
    return true;
}

bool VulkanCompute::RunSpecAttentionResident(
    uint32_t layer,const float* q,float* output,
    uint32_t heads,uint32_t kvHeads,uint32_t headDim,
    uint32_t seqLen,uint32_t basePos,uint32_t batch,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(layer>=specKMirror_.size()||!q||!output||!heads||!kvHeads||
       !headDim||!seqLen||!batch||batch>4||seqLen>specKvCapacity_)
        return false;
    SetWorkEpoch(epoch);
    const size_t qn=(size_t)batch*heads*headDim;
    if(!EnsureScratch(104,qn)||!EnsureScratch(105,qn))
        return false;
    auto& qb=Scratch(104);auto& ob=Scratch(105);
    if(!UploadVector(qb,q,qn)) return false;
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getOpsDescriptor(
        qb,specKMirror_[layer],specVMirror_[layer],ob);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAttnPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAttnPipelineLayout_,
        0,1,&set,0,nullptr);
    SpecAttnPush p{};
    p.headDim=headDim;p.heads=heads;p.kvHeads=kvHeads;
    p.seqLen=seqLen;p.capacity=specKvCapacity_;
    p.basePos=basePos;p.batch=batch;
    p.scale=1.0f/std::sqrt((float)headDim);
    vkCmdPushConstants(
        cmd,specAttnPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    const uint32_t total=batch*heads*headDim;
    vkCmdDispatch(cmd,(total+63u)/64u,1,1);
    recordComputeBarrier(cmd);
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelCompute,0,epoch,nullptr))
        return false;
    return DownloadVector(ob,output,qn);
}

bool VulkanCompute::downloadFromBuffer(
    const DeviceBuf& src, void* dst, size_t bytes)
{
    if (!src || !dst || !bytes || bytes > src.size) return false;

    DeviceBuf* staging = nullptr;
    void* mapped = nullptr;
    if (!ensureMappedStaging(false, bytes, staging, mapped)) return false;

    VkCommandBuffer cmd{};
    VkQueryPool query{};
    bool ok = beginCommand(cmd, query, true) &&
              recordCopy(cmd, src, *staging, bytes) &&
              endSubmitWait(cmd, query, GpuWorkKind::ModelTransfer,
                            bytes, workEpoch_, nullptr);
    if (ok) std::memcpy(dst, mapped, bytes);
    return ok;
}


bool VulkanCompute::dispatchOps(
    DeviceBuf& aa, DeviceBuf& bb, DeviceBuf& cc, DeviceBuf& dd,
    const OpsPush& push, uint32_t groupsX, GpuWorkKind kind)
{
    if (!opsPipeline_ || !aa || !bb || !cc || !dd || groupsX == 0)
        return false;

    VkCommandBuffer cmd = fusedCmd_;
    VkQueryPool query = fusedQuery_;
    const bool own = !fused_;
    if (own) {
        if (!beginCommand(cmd, query, true)) return false;
    }

    // DEEP2_RESIDENT_OPS_BREAKDOWN_001: sampled GPU timestamp pair around
    // this ops dispatch, tagged by op kind + lane (1-in-N; post-fence
    // collection reuses the parity pool). Op kinds: 0=probe,1=gemv_f32,
    // 2=rmsnorm,3=residual,4=swiglu,5=rope,6=attn,7=mla_attn.
    const uint32_t opKind = push.op & 15u;
    const uint32_t sampleLane = q4kLane_;
    const uint32_t currPipeline = kPipelineOps;
    // FUSED-ONLY sampling (see dispatchQuant): own=true dispatches are
    // never collected — skip them so meta stays in lockstep with ticks.
    const bool sampleOps = !own && q4kParityQuery_ && q4kParitySampleEvery_ &&
        (q4kParitySeq_ % q4kParitySampleEvery_) == 0 &&
        q4kParityNext_ < q4kParityCapacity_;
    const uint32_t opsSlot = sampleOps ? q4kParityNext_ : 0u;
    if (sampleOps) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                            q4kParityQuery_, opsSlot * 3u);
    }
    ++q4kParitySeq_;

    VkDescriptorSet set=getOpsDescriptor(aa,bb,cc,dd);
    if(set==VK_NULL_HANDLE) return false;

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, opsPipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                            opsPipelineLayout_, 0, 1, &set, 0, nullptr);
    vkCmdPushConstants(cmd, opsPipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(push), &push);
    vkCmdDispatch(cmd, groupsX, 1, 1);
    recordComputeBarrier(cmd);

    if (sampleOps) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                            q4kParityQuery_, opsSlot * 3u + 1u);
    }
    if (sampleOps) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                            q4kParityQuery_, opsSlot * 3u + 2u);
        // Ops samples are recorded with lane = 16 + laneTag (the op kind
        // rides in `rows`, the work-unit count in `cols`) so the shared
        // accumulator can split them from Q4K samples (lanes 1/2).
        q4kParityMeta_.push_back(
            Q4kParitySample{opKind, push.n, 16u + sampleLane, prevPipelineType_});
        ++q4kParityNext_;
    }
    prevPipelineType_ = currPipeline;

    if (!own) return true;
    return endSubmitWait(cmd, query, kind, 0, workEpoch_, nullptr);
}

bool VulkanCompute::dispatchQuant(
    DeviceBuf& weights, DeviceBuf& input, DeviceBuf& output,
    const QPush& push)
{
    if (!qPipeline_ || !weights || !input || !output) return false;

    VkCommandBuffer cmd = fusedCmd_;
    VkQueryPool query = fusedQuery_;
    const bool own = !fused_;
    if (own) {
        if (!beginCommand(cmd, query, true)) return false;
    }

    // DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001: lane-tagged counters + geometry
    // capture. Every quant dispatch through this entry point — dual-row
    // (DispatchWeight) and resident (gemv lambda) alike — records rows,
    // lane tag, and the bound pipeline for the shader/layout match law.
    {
        const uint32_t lane = q4kLane_;
        if (lane < 3) {
            ++q4kDispatchCount_[lane];
            q4kRows_[lane] += push.rows;
            q4kPipelineSeen_[lane] = qPipeline_;
        }
    }

    // Sampled GPU timestamp pair around this dispatch (mid-buffer writes
    // into the parity pool; collected post-fence). 1-in-N to bound cost.
    // FUSED-ONLY: own=true dispatches run on a fresh command buffer whose
    // samples would never be collected (accumulate runs in EndFusedLayer)
    // — sampling them would desync meta from ticks, so skip them.
    const uint32_t currPipeline = kPipelineQuant;
    const bool sample = !own && q4kParityQuery_ && q4kParitySampleEvery_ &&
        (q4kParitySeq_ % q4kParitySampleEvery_) == 0 &&
        q4kParityNext_ < q4kParityCapacity_;
    const uint32_t slot = sample ? q4kParityNext_ : 0u;
    if (sample) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                            q4kParityQuery_, slot * 3u);
    }
    ++q4kParitySeq_;

    VkDescriptorSet set=getQuantDescriptor(weights,input,output);
    if(set==VK_NULL_HANDLE) return false;

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, qPipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                            qPipelineLayout_, 0, 1, &set, 0, nullptr);
    vkCmdPushConstants(cmd, qPipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(push), &push);
    // deep2_qgemv.comp maps exactly one 256-lane workgroup to each row.
    vkCmdDispatch(cmd, push.rows, 1, 1);
    recordComputeBarrier(cmd);

    if (sample) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                            q4kParityQuery_, slot * 3u + 1u);
    }
    if (sample) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
                            q4kParityQuery_, slot * 3u + 2u);
        q4kParityMeta_.push_back(
            Q4kParitySample{push.rows, push.cols, q4kLane_, prevPipelineType_});
        ++q4kParityNext_;
    }
    prevPipelineType_ = currPipeline;

    if (!own) return true;
    return endSubmitWait(cmd, query, GpuWorkKind::ModelCompute,
                         push.weightBytes, workEpoch_, nullptr);
}

bool VulkanCompute::RunComputeProbe(
    size_t elements, float scale, float bias, std::vector<float>* out)
{
    if (!initialized_ || !opsPipeline_ || elements == 0 ||
        elements > std::numeric_limits<uint32_t>::max())
        return false;

    const size_t bytes = elements * sizeof(float);
    DeviceBuf a{}, b{}, c{}, d{};
    const VkBufferUsageFlags usage =
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
        VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
        VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    if (!createBuffer(bytes, usage, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, a) ||
        !createBuffer(bytes, usage, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, b) ||
        !createBuffer(bytes, usage, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, c) ||
        !createBuffer(bytes, usage, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, d)) {
        destroyBuffer(a); destroyBuffer(b); destroyBuffer(c); destroyBuffer(d);
        return false;
    }

    std::vector<float> input(elements);
    for (size_t i = 0; i < elements; ++i)
        input[i] = static_cast<float>((i % 127) - 63) * 0.03125f;

    bool ok = uploadToBuffer(a, input.data(), bytes);
    if (ok) {
        OpsPush p{};
        p.op = OP_PROBE;
        p.n = static_cast<uint32_t>(elements);
        p.f0 = scale;
        p.f1 = bias;
        ok = dispatchOps(a,b,c,d,p,
                         (static_cast<uint32_t>(elements)+63u)/64u,
                         GpuWorkKind::CapabilityProbe);
    }

    std::vector<float> result(elements);
    if (ok) ok = downloadFromBuffer(c, result.data(), bytes);
    if (ok) {
        for (size_t i = 0; i < elements; ++i) {
            const float expect = input[i] * scale + bias;
            if (!std::isfinite(result[i]) ||
                std::fabs(result[i] - expect) > 1e-5f * std::max(1.0f,std::fabs(expect))) {
                ok = false;
                break;
            }
        }
    }
    if (ok && out) *out = result;

    destroyBuffer(a); destroyBuffer(b); destroyBuffer(c); destroyBuffer(d);
    return ok;
}

bool VulkanCompute::SubmitMaterialUploadAsync(
    const void* src, size_t bytes, uint64_t epoch, MaterialTicket& t)
{
    t = {};
    if (!initialized_ || !src || !bytes) return false;

    const size_t padded = (bytes + 3u) & ~size_t(3u);
    if (!createBuffer(padded, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, t.staging) ||
        !createBuffer(padded,
                      VK_BUFFER_USAGE_TRANSFER_DST_BIT |
                      VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, t.target)) {
        destroyBuffer(t.staging); destroyBuffer(t.target);
        return false;
    }

    void* mapped = nullptr;
    if (vkMapMemory(device_, t.staging.memory, 0, padded, 0, &mapped) != VK_SUCCESS) {
        destroyBuffer(t.staging); destroyBuffer(t.target);
        return false;
    }
    std::memcpy(mapped, src, bytes);
    if (padded > bytes)
        std::memset(static_cast<unsigned char*>(mapped)+bytes, 0, padded-bytes);
    vkUnmapMemory(device_, t.staging.memory);

    if (!beginCommand(t.cmd, t.query, true) ||
        !recordCopy(t.cmd, t.staging, t.target, padded)) {
        destroyBuffer(t.staging); destroyBuffer(t.target);
        return false;
    }
    if (t.query)
        vkCmdWriteTimestamp(
            t.cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, t.query, 1);
    if (vkEndCommandBuffer(t.cmd) != VK_SUCCESS) return false;

    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    if (vkCreateFence(device_, &fi, nullptr, &t.fence) != VK_SUCCESS)
        return false;

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &t.cmd;

    t.hostSubmitNs = nowNs();
    if (vkQueueSubmit(queue_, 1, &si, t.fence) != VK_SUCCESS)
        return false;

    t.epoch = epoch;
    t.bytes = bytes;
    t.submitted = true;
    return true;
}

bool VulkanCompute::WaitMaterialUpload(
    MaterialTicket& t, GpuWorkInterval* interval)
{
    if (!t.submitted || !t.fence) return false;
    VkResult wait = vkWaitForFences(device_, 1, &t.fence, VK_TRUE, UINT64_MAX);
    const uint64_t done = nowNs();

    GpuWorkInterval wi{};
    if (wait == VK_SUCCESS) {
        finalizeInterval(t.query, t.hostSubmitNs, done, t.epoch, t.bytes,
                         GpuWorkKind::ModelTransfer, wi);
        recordInterval(wi);
        if (interval) *interval = wi;
    }

    if (t.fence) vkDestroyFence(device_, t.fence, nullptr);
    if (t.query) vkDestroyQueryPool(device_, t.query, nullptr);
    if (t.cmd) vkFreeCommandBuffers(device_, commandPool_, 1, &t.cmd);
    destroyBuffer(t.staging);
    destroyBuffer(t.target);
    t = {};
    return wait == VK_SUCCESS;
}

bool VulkanCompute::SubmitWeightPrimeAsync(
    const void* src, size_t bytes, int type,
    uint64_t cacheKey, uint64_t epoch, MaterialTicket& ticket)
{
    (void)cacheKey;
    if (!src || !bytes) return false;
    if (type != 0 && type != 8 && type != 10 && type != 12 && type != 14)
        return false;
    return SubmitMaterialUploadAsync(src, bytes, epoch, ticket);
}

bool VulkanCompute::CommitWeightPrime(
    MaterialTicket& t, int type, uint64_t cacheKey,
    GpuWorkInterval* interval)
{
    if (!t.submitted || !t.fence || !t.target) return false;

    VkResult wait = vkWaitForFences(device_,1,&t.fence,VK_TRUE,UINT64_MAX);
    const uint64_t done=nowNs();
    if(wait!=VK_SUCCESS) return false;

    GpuWorkInterval wi{};
    finalizeInterval(t.query,t.hostSubmitNs,done,t.epoch,t.bytes,
                     GpuWorkKind::ModelTransfer,wi);
    recordInterval(wi);
    if(interval) *interval=wi;

    const uint64_t key = type==0
        ? cacheKey
        : quantWeightKey(
              reinterpret_cast<const void*>(static_cast<uintptr_t>(cacheKey)),
              t.bytes,type);
    if(!key) return false;

    auto old=weightCache_.find(key);
    if(old!=weightCache_.end()){
        weightCacheBytes_-=old->second.bytes;
        destroyBuffer(old->second.buffer);
        weightCache_.erase(old);
    }

    WeightCacheEntry e{};
    e.buffer=t.target;
    e.bytes=t.bytes;
    e.type=type;
    t.target={};
    weightCacheBytes_+=e.bytes;
    weightCache_.emplace(key,std::move(e));
    ++weightUploads_;

    if(t.fence) vkDestroyFence(device_,t.fence,nullptr);
    if(t.query) vkDestroyQueryPool(device_,t.query,nullptr);
    if(t.cmd) vkFreeCommandBuffers(device_,commandPool_,1,&t.cmd);
    destroyBuffer(t.staging);
    t={};
    return true;
}

std::vector<GpuWorkInterval>
VulkanCompute::RecentIntervals(uint64_t epoch) const {
    std::lock_guard<std::mutex> lock(intervalMu_);
    std::vector<GpuWorkInterval> out;
    for (const auto& i : intervals_)
        if (i.epoch == epoch) out.push_back(i);
    return out;
}

GpuWorkInterval VulkanCompute::LastInterval() const {
    std::lock_guard<std::mutex> lock(intervalMu_);
    return intervals_.empty() ? GpuWorkInterval{} : intervals_.back();
}

bool VulkanCompute::EnsureForwardArena(
    uint32_t hidden, uint32_t intermediate,
    uint32_t heads, uint32_t kvHeads, uint32_t headDim,
    uint32_t maxSeq, uint32_t layers, uint32_t kvLayers)
{
    if (!initialized_ || !hidden || !intermediate || !heads ||
        !kvHeads || !headDim || !maxSeq || !layers) return false;

    uint32_t seqCap = std::min<uint32_t>(maxSeq, 4096);
    if (const char* e = std::getenv("DEEP2_GPU_KV_SEQ_CAP")) {
        unsigned long v = std::strtoul(e, nullptr, 10);
        if (v) seqCap = std::min<uint32_t>(maxSeq, static_cast<uint32_t>(v));
    }

    // kvLayers=0 preserves legacy all-layer K/V sizing. A multi-GPU
    // layer-split slot only executes its own contiguous layer range, so
    // sizing K/V to that range reclaims dead cache VRAM (Batch3 #12).
    const uint32_t kvLayerCount =
        kvLayers ? std::min<uint32_t>(kvLayers, layers) : layers;

    if (hidden_ == hidden && intermediate_ == intermediate &&
        heads_ == heads && kvHeads_ == kvHeads && headDim_ == headDim &&
        maxSeq_ == seqCap && layers_ == layers && arenaHidden_ &&
        kvArenaLayers_ == kvLayerCount)
        return true;

    auto kill = [&](DeviceBuf& b){ destroyBuffer(b); };
    kill(arenaHidden_); kill(arenaAttnW_); kill(arenaFfnW_); kill(arenaNormed_);
    kill(arenaQ_); kill(arenaK_); kill(arenaV_); kill(arenaAttn_);
    kill(arenaResidual_); kill(arenaGate_); kill(arenaUp_); kill(arenaFFNAct_);
    kill(arenaDown_); kill(arenaKCache_); kill(arenaVCache_);

    hidden_ = hidden; intermediate_ = intermediate; heads_ = heads;
    kvHeads_ = kvHeads; headDim_ = headDim; maxSeq_ = seqCap; layers_ = layers;
    kvDim_ = kvHeads * headDim;
    kvArenaLayers_ = kvLayerCount;

    const VkBufferUsageFlags u =
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
        VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
        VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    auto allocF = [&](DeviceBuf& b, uint64_t n) -> bool {
        if (!n || n > std::numeric_limits<VkDeviceSize>::max()/sizeof(float))
            return false;
        return createBuffer(
            static_cast<VkDeviceSize>(n*sizeof(float)), u,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, b);
    };

    uint64_t cacheFloats =
        static_cast<uint64_t>(kvLayerCount) * maxSeq_ * kvDim_;

    return allocF(arenaHidden_, hidden_) &&
           allocF(arenaAttnW_, hidden_) &&
           allocF(arenaFfnW_, hidden_) &&
           allocF(arenaNormed_, hidden_) &&
           allocF(arenaQ_, hidden_) &&
           allocF(arenaK_, kvDim_) &&
           allocF(arenaV_, kvDim_) &&
           allocF(arenaAttn_, hidden_) &&
           allocF(arenaResidual_, hidden_) &&
           allocF(arenaGate_, intermediate_) &&
           allocF(arenaUp_, intermediate_) &&
           allocF(arenaFFNAct_, intermediate_) &&
           allocF(arenaDown_, std::max(hidden_, intermediate_)) &&
           allocF(arenaKCache_, cacheFloats) &&
           allocF(arenaVCache_, cacheFloats);
}

bool VulkanCompute::ApplyWeightWindowPolicy(
    size_t maxWeightBytes, size_t budgetBytes,
    uint32_t, size_t arenaBytes)
{
    if (!maxWeightBytes || !budgetBytes || budgetBytes < maxWeightBytes)
        return false;
    size_t effectiveBudget = budgetBytes;
    if (arenaBytes && effectiveBudget > arenaBytes)
        effectiveBudget -= arenaBytes;
    const size_t emergencyBytes = (size_t)512 << 20;
    if (effectiveBudget > scratchReservedBytes_ + emergencyBytes)
        effectiveBudget -= (scratchReservedBytes_ + emergencyBytes);
    else
        effectiveBudget = 0;
    weightBudgetBytes_ = effectiveBudget;
    return true;
}

bool VulkanCompute::UploadHidden(const float* src, uint32_t count) {
    return src && count <= hidden_ &&
           uploadToBuffer(arenaHidden_, src, count*sizeof(float));
}

bool VulkanCompute::DownloadHidden(float* dst, uint32_t count) {
    return dst && count <= hidden_ &&
           downloadFromBuffer(arenaHidden_, dst, count*sizeof(float));
}

bool VulkanCompute::CopyArenaHiddenTo(VulkanCompute& dst, uint32_t count) {
    lastCrossDeviceCopyUsedHost_ = true;
    dst.lastCrossDeviceCopyUsedHost_ = true;
    if (!count || count > hidden_ || count > dst.hidden_) return false;
    std::vector<float> host(count);
    return DownloadHidden(host.data(), count) &&
           dst.UploadHidden(host.data(), count);
}

bool VulkanCompute::UploadNormWeight(
    DeviceBuf& dst, const float* src, size_t count)
{
    return src && count*sizeof(float) <= dst.size &&
           uploadToBuffer(dst, src, count*sizeof(float));
}

VulkanCompute::DeviceBuf* VulkanCompute::ResolveResidentF32(
    const float* src, uint64_t key, size_t count)
{
    if (!src || !count ||
        count > std::numeric_limits<size_t>::max() / sizeof(float))
        return nullptr;
    DeviceBuf* out = nullptr;
    if (!ensureWeightF32(src, key, count * sizeof(float), out))
        return nullptr;
    return out;
}

bool VulkanCompute::ensureReusableFusedSubmitObjects() {
    if(!device_||!commandPool_) return false;

    if(reusableFusedCmd_==VK_NULL_HANDLE){
        VkCommandBufferAllocateInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool=commandPool_;
        ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount=1;
        if(vkAllocateCommandBuffers(device_,&ai,&reusableFusedCmd_)!=VK_SUCCESS)
            return false;
    }
    if(reusableFusedFence_==VK_NULL_HANDLE){
        VkFenceCreateInfo fi{};
        fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        if(vkCreateFence(device_,&fi,nullptr,&reusableFusedFence_)!=VK_SUCCESS)
            return false;
    }
    if(timestampValidBits_ && reusableFusedQuery_==VK_NULL_HANDLE){
        VkQueryPoolCreateInfo qi{};
        qi.sType=VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        qi.queryType=VK_QUERY_TYPE_TIMESTAMP;
        qi.queryCount=2;
        if(vkCreateQueryPool(device_,&qi,nullptr,&reusableFusedQuery_)!=VK_SUCCESS)
            return false;
    }
    // DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001: parity timestamp pool
    // (2 queries per sample slot; 1-in-N sampled dispatches).
    if(q4kParityQuery_==VK_NULL_HANDLE && timestampValidBits_){
        VkQueryPoolCreateInfo qi{};
        qi.sType=VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        qi.queryType=VK_QUERY_TYPE_TIMESTAMP;
        qi.queryCount=q4kParityCapacity_*3u;
        if(vkCreateQueryPool(device_,&qi,nullptr,&q4kParityQuery_)!=VK_SUCCESS)
            return false;
    }
    return true;
}

void VulkanCompute::accumulateQ4kParitySamples() noexcept {
    if(!q4kParityQuery_ || q4kParityMeta_.empty()) {
        q4kParityMeta_.clear();
        q4kParityNext_=0;
        return;
    }
    // Non-blocking read; incomplete triples are skipped (fence guarantees
    // completion for this fused layer, but defensive check costs nothing).
    std::vector<uint64_t> ticks(q4kParityNext_*3u,0u);
    const size_t n=q4kParityNext_*3u;
    const VkResult vr = n
        ? vkGetQueryPoolResults(
            device_,q4kParityQuery_,0,
            static_cast<uint32_t>(n),
            ticks.size()*sizeof(uint64_t),ticks.data(),
            sizeof(uint64_t),VK_QUERY_RESULT_64_BIT)
        : VK_SUCCESS;
    if(vr==VK_SUCCESS){
        uint64_t mask = ~0ull;
        if (timestampValidBits_ < 64)
            mask = (1ull << timestampValidBits_) - 1ull;
        for(size_t i=0;i<q4kParityMeta_.size();++i){
            const uint64_t s=ticks[i*3u],e=ticks[i*3u+1u],b=ticks[i*3u+2u];
            const Q4kParitySample& m=q4kParityMeta_[i];
            // Skip if any timestamp is identical (uninitialized / unavailable).
            if(e==s && b==e && !(((e-s)&mask)|((b-e)&mask))) continue;
            const uint64_t kernelGap=(e-s)&mask;
            const uint64_t kernelNs=static_cast<uint64_t>(
                static_cast<long double>(kernelGap)*
                static_cast<long double>(timestampPeriodNs_));
            const uint64_t barrierGap=(b-e)&mask;
            const uint64_t barrierNs=static_cast<uint64_t>(
                static_cast<long double>(barrierGap)*
                static_cast<long double>(timestampPeriodNs_));
            uint32_t lane=0;
            uint32_t currPipeline=0;
            if(m.lane>=16u){
                lane=m.lane-16u;
                currPipeline=kPipelineOps;
            } else if(m.lane && m.lane<3){
                lane=m.lane;
                currPipeline=kPipelineQuant;
            }
            if(lane && currPipeline){
                const uint32_t transition=m.prevPipeline*3+currPipeline;
                if(transition<9){
                    transitionKernelNs_[lane][transition]+=kernelNs;
                    ++transitionKernelCount_[lane][transition];
                    transitionBarrierNs_[lane][transition]+=barrierNs;
                }
            }
            if(m.lane>=16u){
                // Ops-pipeline sample: lane = 16 + laneTag, rows = opKind.
                const uint32_t lane=m.lane-16u;
                const uint32_t opKind=m.rows & 15u;
                if(lane && opKind<8){
                    opsSampledNs_[lane][opKind]+=kernelNs;
                    ++opsSampledCount_[lane][opKind];
                    opsSampledUnits_[lane][opKind]+=m.cols;
                }
            } else if(m.lane && m.lane<3){
                q4kSampledNs_[m.lane]+=kernelNs;
                ++q4kSampledCount_[m.lane];
                q4kSampledRows_[m.lane]+=m.rows;
            }
        }
    }
    q4kParityMeta_.clear();
    q4kParityNext_=0;
}

bool VulkanCompute::BeginFusedLayer() {

    if (fused_ || !initialized_ || !opsPipeline_) return false;
    if(!ensureReusableFusedSubmitObjects()) return false;

    // DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001: invalidate the stale
    // interval so a failed/aborted fused sequence can never leak an
    // older interval into the timing authority.
    lastFusedIntervalValid_ = false;

    // DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001: reset the sampled-slot
    // cursor for this fused layer. The POOL reset must be recorded on
    // the command buffer only AFTER vkBeginCommandBuffer (below) —
    // recording into a non-recording command buffer is undefined
    // behavior and killed the warmup run (log froze right after range
    // pinning with no crash output). The reset is emitted with the
    // existing reusableFusedQuery_ reset inside the recording.
    // Stale meta entries from any un-collected sequence are discarded
    // with the pool reset so meta.size() can never exceed the ticks
    // vector in the accumulator (out-of-bounds read guard).
    q4kParityNext_ = 0;
    q4kParityMeta_.clear();

    if(vkResetCommandBuffer(reusableFusedCmd_,0)!=VK_SUCCESS)
        return false;
    VkCommandBufferBeginInfo bi{};
    bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if(vkBeginCommandBuffer(reusableFusedCmd_,&bi)!=VK_SUCCESS)
        return false;

    prevPipelineType_ = kPipelineNone;

    if(q4kParityQuery_)
        vkCmdResetQueryPool(reusableFusedCmd_, q4kParityQuery_,
                            0, q4kParityCapacity_ * 3u);

    if(reusableFusedQuery_){
        vkCmdResetQueryPool(reusableFusedCmd_,reusableFusedQuery_,0,2);
        vkCmdWriteTimestamp(
            reusableFusedCmd_,VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
            reusableFusedQuery_,0);
    }

    fusedCmd_=reusableFusedCmd_;
    fusedQuery_=reusableFusedQuery_;
    fused_ = true;
    fusedHostSubmitNs_=0;
    return true;
}

bool VulkanCompute::EndFusedLayer() {
    if (!fused_) return false;
    VkCommandBuffer cmd = fusedCmd_;
    VkQueryPool q = fusedQuery_;
    fused_ = false;
    fusedCmd_ = VK_NULL_HANDLE;
    fusedQuery_ = VK_NULL_HANDLE;

    if(q)
        vkCmdWriteTimestamp(cmd,VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,q,1);
    if(vkEndCommandBuffer(cmd)!=VK_SUCCESS) return false;
    if(vkResetFences(device_,1,&reusableFusedFence_)!=VK_SUCCESS)
        return false;

    VkSubmitInfo si{};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount=1;
    si.pCommandBuffers=&cmd;

    const uint64_t submitNs=nowNs();
    if(vkQueueSubmit(queue_,1,&si,reusableFusedFence_)!=VK_SUCCESS)
        return false;
    ++queueSubmitCount_;
    const uint64_t fusedWaitTimeoutNs = 30000000000ULL; // 30 seconds
    VkResult waitRes = vkWaitForFences(
            device_,1,&reusableFusedFence_,VK_TRUE,fusedWaitTimeoutNs);
    if(waitRes==VK_TIMEOUT){
        std::fprintf(stderr,"[GPU] EndFusedLayer vkWaitForFences TIMEOUT after 30s\n");
        std::fflush(stderr);
        return false;
    }
    if(waitRes!=VK_SUCCESS) return false;
    const uint64_t completeNs=nowNs();

    GpuWorkInterval wi{};
    if(finalizeInterval(
            q,submitNs,completeNs,workEpoch_,0,
            GpuWorkKind::ModelCompute,wi))
        recordInterval(wi);
    // DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001: expose the finalized
    // interval to the caller (post-fence; no new synchronization).
    lastFusedInterval_ = wi;
    lastFusedIntervalValid_ = true;
    // DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001: collect this fused layer's
    // sampled Q4K timestamp pairs now that the fence is signaled.
    accumulateQ4kParitySamples();
    return true;
}

bool VulkanCompute::FlushWeightComputes() {
    if (fused_) return true;
    return device_ && vkQueueWaitIdle(queue_) == VK_SUCCESS;
}

bool VulkanCompute::DispatchRmsNorm(
    DeviceBuf& input, DeviceBuf& weight, DeviceBuf& output,
    uint32_t n, float eps)
{
    OpsPush p{}; p.op=OP_RMSNORM; p.n=n; p.f0=eps;
    return n && dispatchOps(input,weight,output,output,p,(n+63u)/64u);
}

bool VulkanCompute::DispatchResidualAdd(
    DeviceBuf& a, DeviceBuf& b, DeviceBuf& out, uint32_t n)
{
    OpsPush p{}; p.op=OP_RESIDUAL; p.n=n;
    return n && dispatchOps(a,b,out,out,p,(n+63u)/64u);
}

bool VulkanCompute::DispatchSwiGLU(
    DeviceBuf& gate, DeviceBuf& up, DeviceBuf& out, uint32_t n)
{
    OpsPush p{}; p.op=OP_SWIGLU; p.n=n;
    return n && dispatchOps(gate,up,out,out,p,(n+63u)/64u);
}

bool VulkanCompute::DispatchRope(
    DeviceBuf& q, DeviceBuf& k, uint32_t headDim,
    uint32_t heads, uint32_t kvHeads, uint32_t pos, float theta)
{
    if (!headDim || (headDim & 1u) || !heads || !kvHeads || theta <= 0.0f)
        return false;
    OpsPush p{};
    p.op=OP_ROPE; p.p0=headDim; p.p1=heads; p.p2=kvHeads; p.p3=pos; p.f0=theta;
    const uint32_t pairs = (heads+kvHeads)*(headDim/2u);
    p.n = pairs;
    return dispatchOps(q,k,q,k,p,(pairs+63u)/64u);
}

bool VulkanCompute::AppendKV(
    DeviceBuf& k, DeviceBuf& v, uint32_t kvDim,
    uint32_t pos, uint32_t layer)
{
    // Layer-split slots map absolute layers onto a sized K/V region whose
    // slot 0 is absolute layer kvLayerBase_.
    const uint32_t relLayer =
        layer >= kvLayerBase_ ? layer - kvLayerBase_ : 0u;
    if (relLayer >= kvArenaLayers_) return false;
    if (!k || !v || kvDim != kvDim_ || pos >= maxSeq_)
        return false;
    const VkDeviceSize bytes = static_cast<VkDeviceSize>(kvDim)*sizeof(float);
    const uint64_t elemOff =
        (static_cast<uint64_t>(relLayer)*maxSeq_ + pos)*kvDim_;
    const VkDeviceSize dstOff =
        static_cast<VkDeviceSize>(elemOff*sizeof(float));
    if (dstOff + bytes > arenaKCache_.size ||
        dstOff + bytes > arenaVCache_.size)
        return false;

    VkCommandBuffer cmd = fusedCmd_;
    VkQueryPool query = fusedQuery_;
    const bool own = !fused_;
    if (own && !beginCommand(cmd,query,true)) return false;

    if (!recordCopy(cmd,k,arenaKCache_,bytes,0,dstOff) ||
        !recordCopy(cmd,v,arenaVCache_,bytes,0,dstOff))
        return false;

    if (!own) return true;
    return endSubmitWait(cmd,query,GpuWorkKind::ModelCompute,
                         bytes*2,workEpoch_,nullptr);
}

bool VulkanCompute::DispatchAttnDecode(
    DeviceBuf& q, DeviceBuf& kCache, DeviceBuf& vCache,
    DeviceBuf& out, uint32_t headDim,
    uint32_t heads, uint32_t kvHeads,
    uint32_t seqLen, float scale, uint32_t layer)
{
    // Layer-relative addressing mirrors AppendKV (kvLayerBase_ offset).
    const uint32_t relLayer =
        layer >= kvLayerBase_ ? layer - kvLayerBase_ : 0u;
    if (relLayer >= kvArenaLayers_) return false;
    if (!headDim || !heads || !kvHeads || heads%kvHeads ||
        !seqLen || seqLen>maxSeq_) return false;

    uint64_t base = static_cast<uint64_t>(relLayer)*maxSeq_*kvDim_;
    if (base > std::numeric_limits<uint32_t>::max()) return false;

    OpsPush p{};
    p.op=OP_ATTN;
    p.n=heads*headDim;
    p.p0=headDim; p.p1=heads; p.p2=kvHeads; p.p3=seqLen;
    p.p4=kvDim_; p.p5=static_cast<uint32_t>(base); p.f0=scale;
    return dispatchOps(q,kCache,vCache,out,p,(p.n+63u)/64u);
}

void VulkanCompute::clearRecordedQ4K() {
    for(auto& kv:recordedQ4K_) {
        auto& r=kv.second;
        if(r.fence) vkDestroyFence(device_,r.fence,nullptr);
        if(r.cmd&&commandPool_)
            vkFreeCommandBuffers(device_,commandPool_,1,&r.cmd);
    }
    recordedQ4K_.clear();
}

bool VulkanCompute::SubmitRecordedResidentQ4K(
    const GpuWeightView& weight,DeviceBuf& input,DeviceBuf& output,
    uint32_t batch,uint64_t epoch)
{
    if(!weight.valid()||weight.type!=12||!input||!output||
       !batch||batch>4||fused_)
        return false;
    DeviceBuf* wb=nullptr;
    if(!ensureWeightQuant(
            weight.type,weight.data,weight.bytes,wb))
        return false;
    const Q4KBatchTile tile=SelectQ4KBatchTile(
        weight.data,weight.bytes,input,output,
        weight.rows,weight.cols,batch);
    const uint32_t tileN=(uint32_t)tile;
    RecordedQ4KKey key{
        wb->buffer,input.buffer,output.buffer,
        weight.rows,weight.cols,batch,tileN};
    auto it=recordedQ4K_.find(key);
    if(it==recordedQ4K_.end()) {
        RecordedQ4K r{};
        VkCommandBufferAllocateInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool=commandPool_;
        ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount=1;
        if(vkAllocateCommandBuffers(device_,&ai,&r.cmd)!=VK_SUCCESS)
            return false;
        VkCommandBufferBeginInfo bi{};
        bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        bi.flags=VK_COMMAND_BUFFER_USAGE_SIMULTANEOUS_USE_BIT;
        if(vkBeginCommandBuffer(r.cmd,&bi)!=VK_SUCCESS) return false;
        r.set=getQuantDescriptor(*wb,input,output);
        if(r.set==VK_NULL_HANDLE) return false;
        VkPipeline pipe=tile==Q4KBatchTile::Eight
            ? qBatch8RowPipeline_:qBatch4RowPipeline_;
        VkPipelineLayout layout=tile==Q4KBatchTile::Eight
            ? qBatch8RowPipelineLayout_:qBatch4RowPipelineLayout_;
        vkCmdBindPipeline(
            r.cmd,VK_PIPELINE_BIND_POINT_COMPUTE,pipe);
        vkCmdBindDescriptorSets(
            r.cmd,VK_PIPELINE_BIND_POINT_COMPUTE,layout,
            0,1,&r.set,0,nullptr);
        QBatchPush p{};
        p.type=12;p.rows=weight.rows;p.cols=weight.cols;
        p.weightBytes=(uint32_t)weight.bytes;p.batch=batch;
        vkCmdPushConstants(
            r.cmd,layout,VK_SHADER_STAGE_COMPUTE_BIT,
            0,sizeof(p),&p);
        vkCmdDispatch(
            r.cmd,
            (weight.rows+(tileN-1u))/tileN,1,1);
        recordComputeBarrier(r.cmd);
        if(vkEndCommandBuffer(r.cmd)!=VK_SUCCESS) return false;
        VkFenceCreateInfo fi{};
        fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        if(vkCreateFence(device_,&fi,nullptr,&r.fence)!=VK_SUCCESS)
            return false;
        it=recordedQ4K_.emplace(key,r).first;
        ++recordedQ4KBuilds_;
    }
    auto& r=it->second;
    if(vkWaitForFences(device_,1,&r.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    if(vkResetFences(device_,1,&r.fence)!=VK_SUCCESS) return false;
    VkSubmitInfo si{};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount=1;
    si.pCommandBuffers=&r.cmd;
    if(vkQueueSubmit(queue_,1,&si,r.fence)!=VK_SUCCESS) return false;
    if(vkWaitForFences(device_,1,&r.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    ++recordedQ4KSubmits_;
    ++queueSubmitCount_;
    SetWorkEpoch(epoch);
    return true;
}
void VulkanCompute::clearRecordedGroups() {
    for(auto& kv:recordedGroups_) {
        auto& r=kv.second;
        if(r.fence) vkDestroyFence(device_,r.fence,nullptr);
        if(r.cmd&&commandPool_)
            vkFreeCommandBuffers(device_,commandPool_,1,&r.cmd);
    }
    recordedGroups_.clear();
}

static bool deep2RecordedGroupAsyncEnabled() noexcept {
    const char* e=std::getenv("DEEP2_RECORDED_GROUP_ASYNC");
    return e && *e && *e!='0';
}

bool VulkanCompute::SubmitRecordedResidentGroupQ4K(
    const GpuWeightView* weights,size_t weightCount,
    uint32_t cols,uint32_t batch,uint64_t epoch)
{
    if(!weights||weightCount<2||weightCount>3||
       !residentBatchInput_||!batch||batch>4)
        return false;
    if(!EnsureResidentGroupOutputs(weights,weightCount,batch))
        return false;

    DeviceBuf* wb[3]{};
    RecordedGroupKey key{};
    key.input=residentBatchInput_.buffer;
    key.cols=cols;key.batch=batch;key.count=(uint32_t)weightCount;
    for(size_t i=0;i<weightCount;++i) {
        if(!weights[i].valid()||weights[i].type!=12||
           weights[i].cols!=cols||!PinWeightView(weights[i])||
           !ensureWeightQuant(
               weights[i].type,weights[i].data,weights[i].bytes,wb[i]))
            return false;
        key.weight[i]=wb[i]->buffer;
        key.output[i]=residentGroupOutputs_[i].buffer;
        key.rows[i]=weights[i].rows;
    }

    auto it=recordedGroups_.find(key);
    if(it==recordedGroups_.end()) {
        RecordedGroup r{};
        VkCommandBufferAllocateInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool=commandPool_;
        ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount=1;
        if(vkAllocateCommandBuffers(device_,&ai,&r.cmd)!=VK_SUCCESS)
            return false;
        VkCommandBufferBeginInfo bi{};
        bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        bi.flags=VK_COMMAND_BUFFER_USAGE_SIMULTANEOUS_USE_BIT;
        if(vkBeginCommandBuffer(r.cmd,&bi)!=VK_SUCCESS) return false;

        for(size_t i=0;i<weightCount;++i) {
            const Q4KBatchTile tile=SelectQ4KBatchTile(
                weights[i].data,weights[i].bytes,
                residentBatchInput_,residentGroupOutputs_[i],
                weights[i].rows,cols,batch);
            VkPipeline pipe=tile==Q4KBatchTile::Eight
                ? qBatch8RowPipeline_:qBatch4RowPipeline_;
            VkPipelineLayout layout=tile==Q4KBatchTile::Eight
                ? qBatch8RowPipelineLayout_:qBatch4RowPipelineLayout_;
            r.set[i]=getQuantDescriptor(
                *wb[i],residentBatchInput_,residentGroupOutputs_[i]);
            if(r.set[i]==VK_NULL_HANDLE) return false;
            vkCmdBindPipeline(
                r.cmd,VK_PIPELINE_BIND_POINT_COMPUTE,pipe);
            vkCmdBindDescriptorSets(
                r.cmd,VK_PIPELINE_BIND_POINT_COMPUTE,layout,
                0,1,&r.set[i],0,nullptr);
            QBatchPush p{};
            p.type=12;p.rows=weights[i].rows;p.cols=cols;
            p.weightBytes=(uint32_t)weights[i].bytes;p.batch=batch;
            vkCmdPushConstants(
                r.cmd,layout,VK_SHADER_STAGE_COMPUTE_BIT,
                0,sizeof(p),&p);
            const uint32_t tileN=(uint32_t)tile;
            vkCmdDispatch(
                r.cmd,(weights[i].rows+tileN-1u)/tileN,1,1);
            recordComputeBarrier(r.cmd);
        }
        if(vkEndCommandBuffer(r.cmd)!=VK_SUCCESS) return false;
        VkFenceCreateInfo fi{};
        fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        fi.flags=VK_FENCE_CREATE_SIGNALED_BIT;
        if(vkCreateFence(device_,&fi,nullptr,&r.fence)!=VK_SUCCESS)
            return false;
        it=recordedGroups_.emplace(key,r).first;
        ++recordedGroupBuilds_;
    }

    auto& r=it->second;

    // Timeline fast path. The command buffer was recorded with
    // VK_COMMAND_BUFFER_USAGE_SIMULTANEOUS_USE_BIT in Batch 15, so no host
    // completion wait is needed merely to submit the next immutable group.
    // Same-queue ordering preserves transformer dependency order. The exposed
    // last signal can be consumed by a cross-queue dependent stage.
    if(deep2RecordedGroupAsyncEnabled() && TimelineSemaphoreEnabled()) {
        const uint64_t signal=NextTimelineValue();
        const uint64_t wait=recordedGroupLastSignal_;
        if(!SubmitTimelineCommand(
                r.cmd,queue_,wait,signal,VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT))
            return false;
        recordedGroupLastSignal_=signal;
        ++recordedGroupAsyncSubmits_;
        ++recordedGroupSubmits_;
        SetWorkEpoch(epoch);
        return true;
    }

    ++recordedGroupSyncWaits_;
    if(vkWaitForFences(device_,1,&r.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    if(vkResetFences(device_,1,&r.fence)!=VK_SUCCESS) return false;
    VkSubmitInfo si{};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount=1;si.pCommandBuffers=&r.cmd;
    if(vkQueueSubmit(queue_,1,&si,r.fence)!=VK_SUCCESS) return false;
    if(vkWaitForFences(device_,1,&r.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    ++recordedGroupSubmits_;
    ++queueSubmitCount_;
    SetWorkEpoch(epoch);
    return true;
}
void VulkanCompute::clearWeightCache() {
    clearRecordedGroups();
    // Recorded commands reference resident weight buffers.
    // Drop command cache before any unpinned weight buffers are destroyed.
    clearRecordedQ4K();
    for (auto it = weightCache_.begin(); it != weightCache_.end();) {
        if (it->second.pinned) { ++it; continue; }
        weightCacheBytes_ -= it->second.bytes;
        destroyBuffer(it->second.buffer);
        it = weightCache_.erase(it);
    }
}

const VulkanCompute::PeerHandoffCaps&
VulkanCompute::PeerHandoffCapability() const {
    if (peerHandoffCapsProbed_) return peerHandoffCaps_;
    peerHandoffCapsProbed_ = true;
    peerHandoffCaps_ = PeerHandoffCaps{};

    if (!physical_) return peerHandoffCaps_;

    // 1. Device extensions.
    uint32_t extCount = 0;
    if (vkEnumerateDeviceExtensionProperties(
            physical_, nullptr, &extCount, nullptr) == VK_SUCCESS &&
        extCount > 0) {
        std::vector<VkExtensionProperties> ext(extCount);
        if (vkEnumerateDeviceExtensionProperties(
                physical_, nullptr, &extCount, ext.data()) == VK_SUCCESS) {
            for (const auto& e : ext) {
                const std::string name(e.extensionName);
                if (name == "VK_KHR_external_memory")
                    peerHandoffCaps_.externalMemoryExtension = true;
                else if (name == "VK_KHR_external_memory_win32")
                    peerHandoffCaps_.win32 = true;
                else if (name == "VK_KHR_external_semaphore_win32")
                    peerHandoffCaps_.externalSemaphore = true;
                else if (name == "VK_KHR_external_semaphore")
                    peerHandoffCaps_.externalSemaphore = true;
                else if (name == "VK_EXT_external_memory_host")
                    peerHandoffCaps_.externalMemoryHostSupported = true;
            }
        }
    }

    // B5_HOST_IMPORT_PROBE_001: query VkPhysicalDeviceExternalMemoryHostPropertiesEXT
    if (peerHandoffCaps_.externalMemoryHostSupported) {
        VkPhysicalDeviceExternalMemoryHostPropertiesEXT hostProps{
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_MEMORY_HOST_PROPERTIES_EXT
        };
        VkPhysicalDeviceProperties2 p2{
            VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2
        };
        p2.pNext = &hostProps;
        auto fpGetProps2 = reinterpret_cast<PFN_vkGetPhysicalDeviceProperties2>(
            vkGetInstanceProcAddr(instance_, "vkGetPhysicalDeviceProperties2"));
        if (fpGetProps2) {
            fpGetProps2(physical_, &p2);
            peerHandoffCaps_.minImportedHostPointerAlignment =
                hostProps.minImportedHostPointerAlignment;
        }

        // NOTE: vkGetMemoryHostPointerPropertiesEXT requires the extension to
        // be enabled at device creation. We have added it to the enabled list
        // below (haveExternalMemoryHost), so on fresh instances the device
        // function pointer will be valid.  The honest probe still reports
        // physical-device capability here; the actual import test is done by
        // TestSharedHostImport() after device creation.
        peerHandoffCaps_.hostImportable = false;
        peerHandoffCaps_.hostImportableMemoryTypeBits = 0;
    }
    // B5_SHARED_HOST_IMPORT_001: test actual host pointer import on this device.
    // Must be called after device creation because it uses device-level functions.
    if (!peerHandoffCapsProbed_) {
        peerHandoffCapsProbed_ = true;
    }
    if (!peerHandoffCaps_.externalMemoryExtension || !peerHandoffCaps_.win32)
        return peerHandoffCaps_;

    // 2. Handle-type exportability/importability. The probe asks the device
    // whether an exportable storage buffer of the given Windows handle type
    // is supported at all; unsupported types stay false (fail closed — no
    // fabricated peer support).
    auto probeHandle = [&](VkExternalMemoryHandleTypeFlagBits htype) -> bool {
        VkExternalBufferProperties props{};
        props.sType = VK_STRUCTURE_TYPE_EXTERNAL_BUFFER_PROPERTIES;
        VkPhysicalDeviceExternalBufferInfo info{};
        info.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_BUFFER_INFO;
        info.flags = 0;
        info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
                     VK_BUFFER_USAGE_TRANSFER_DST_BIT;
        info.handleType = htype;
        auto fp = reinterpret_cast<PFN_vkGetPhysicalDeviceExternalBufferProperties>(
            vkGetInstanceProcAddr(instance_,
                "vkGetPhysicalDeviceExternalBufferProperties"));
        if (!fp) return false;
        fp(physical_, &info, &props);
        return props.externalMemoryProperties.externalMemoryFeatures != 0;
    };

    peerHandoffCaps_.omtHandle = probeHandle(
        VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_WIN32_BIT);
    peerHandoffCaps_.d3d12Handle = probeHandle(
        VK_EXTERNAL_MEMORY_HANDLE_TYPE_D3D12_RESOURCE_BIT);

    peerHandoffCaps_.externalMemoryApiSupported =
        peerHandoffCaps_.omtHandle || peerHandoffCaps_.d3d12Handle;

    // 3. B5.2a device-group authority. Cross-physical-device OPAQUE_WIN32
    // import is spec-restricted to the SAME underlying physical device, so
    // the API-surface flags above CANNOT license a peer handoff between the
    // two discrete GPUs. The native mechanism is ONE logical
    // VkPhysicalDeviceGroup device spanning both. Probe the instance-level
    // group enumeration: both GPUs must appear in the SAME group, and the
    // group must report subset allocation + we require peer COPY features
    // (checked per-heap at bind time; group presence gates the verdict).
    {
        auto fpGroups = reinterpret_cast<PFN_vkEnumeratePhysicalDeviceGroups>(
            vkGetInstanceProcAddr(instance_,
                "vkEnumeratePhysicalDeviceGroups"));
        if (fpGroups) {
            uint32_t groupCount = 0;
            if (fpGroups(instance_, &groupCount, nullptr) == VK_SUCCESS &&
                groupCount > 0) {
                std::vector<VkPhysicalDeviceGroupProperties> groups(
                    groupCount, VkPhysicalDeviceGroupProperties{});
                groups[0].sType =
                    VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_GROUP_PROPERTIES;
                for (size_t i = 1; i < groups.size(); ++i)
                    groups[i].sType =
                        VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_GROUP_PROPERTIES;
                if (fpGroups(instance_, &groupCount, groups.data()) ==
                    VK_SUCCESS) {
                    peerHandoffCaps_.groupCount = groupCount;
                    for (const auto& g : groups) {
                        bool hasSelf = false;
                        for (uint32_t i = 0; i < g.physicalDeviceCount; ++i)
                            if (g.physicalDevices[i] == physical_)
                                hasSelf = true;
                        if (hasSelf) {
                            peerHandoffCaps_.subsetAllocation =
                                g.subsetAllocation != VK_FALSE;
                            if (g.physicalDeviceCount > 1) {
                                peerHandoffCaps_.sameDeviceGroup = true;
                                peerHandoffCaps_.deviceGroupSupported = true;
                            }
                        }
                    }
                }
            }
        }
    }

    // Honest verdict: peer handoff is only supported through a device-group
    // logical device. (Peer COPY src/dst features are verified per-heap at
    // bind time when a group device is actually created.)
    peerHandoffCaps_.peerHandoffSupported =
        peerHandoffCaps_.sameDeviceGroup;
    return peerHandoffCaps_;
}

bool VulkanCompute::PinWeightView(const GpuWeightView& view) {
    if (!view.valid()) return false;
    DeviceBuf* b = nullptr;
    if (view.type == 0) {
        const uint64_t key = view.key ? view.key : (uint64_t)(uintptr_t)view.data;
        if (!ensureWeightF32((const float*)view.data, key, view.bytes, b))
            return false;
    } else {
        if (!ensureWeightQuant(view.type, view.data, view.bytes, b))
            return false;
    }
    const uint64_t key = view.key
        ? view.key
        : ((uint64_t)(uintptr_t)view.data ^
           ((uint64_t)view.bytes << 1) ^
           ((uint64_t)(uint32_t)view.type << 48));
    auto it = weightCache_.find(key);
    if (it == weightCache_.end()) {
        for (auto jt = weightCache_.begin(); jt != weightCache_.end(); ++jt) {
            if (&jt->second.buffer == b || jt->second.buffer.buffer == b->buffer) {
                it = jt; break;
            }
        }
    }
    if (it == weightCache_.end()) return false;
    if (!it->second.pinned) {
        it->second.pinned = true;
        pinnedWeightBytes_ += it->second.bytes;
        ++pinnedWeightEntries_;
    }
    return true;
}

void VulkanCompute::UnpinAllWeights() {
    for (auto& kv : weightCache_) kv.second.pinned = false;
    pinnedWeightBytes_ = 0;
    pinnedWeightEntries_ = 0;
}

bool VulkanCompute::evictWeightCacheUntil(size_t incomingBytes) {
    if (weightBudgetBytes_ && incomingBytes > weightBudgetBytes_) return false;

    while (weightBudgetBytes_ && weightCacheBytes_ + incomingBytes > weightBudgetBytes_) {
        auto victim = weightCache_.end();
        for (auto it = weightCache_.begin(); it != weightCache_.end(); ++it) {
            if (it->second.pinned) continue;
            if (victim == weightCache_.end() ||
                it->second.lastUse < victim->second.lastUse) {
                victim = it;
            }
        }
        if (victim == weightCache_.end()) return false;

        const size_t bytes = victim->second.bytes;
        destroyBuffer(victim->second.buffer);
        weightCache_.erase(victim);
        weightCacheBytes_ = bytes <= weightCacheBytes_
            ? weightCacheBytes_ - bytes : 0;
    }

    if (memoryBudgetAvailable_) {
        while (!checkLiveHeapAdmission(incomingBytes)) {
            auto victim = weightCache_.end();
            for (auto it = weightCache_.begin(); it != weightCache_.end(); ++it) {
                if (it->second.pinned) continue;
                if (victim == weightCache_.end() ||
                    it->second.lastUse < victim->second.lastUse) {
                    victim = it;
                }
            }
            if (victim == weightCache_.end()) return false;

            const size_t bytes = victim->second.bytes;
            destroyBuffer(victim->second.buffer);
            weightCache_.erase(victim);
            weightCacheBytes_ = bytes <= weightCacheBytes_
                ? weightCacheBytes_ - bytes : 0;
        }
    }

    return true;
}

bool VulkanCompute::ensureWeightF32(
    const float* weights, uint64_t key, size_t bytes, DeviceBuf*& out)
{
    out = nullptr;
    // DEEP2_DIRECT_RESIDENT_DISPATCH_001: certification — the resident
    // hot path must never reach admission. Any hit here while a resident
    // dispatch is active is a lookup violation.
    if (residentDispatchDepth_) {
        ++residentLookupViolations_;
#ifdef _DEBUG
        std::fprintf(stderr,
            "[RESIDENT_LOOKUP_VIOLATION] ensureWeightF32 depth=%u key=%llu\n",
            residentDispatchDepth_,
            static_cast<unsigned long long>(key));
#endif
    }
    auto it = weightCache_.find(key);
    if (it != weightCache_.end()) {
        ++weightHits_;
        it->second.lastUse = weightUseClock_++;
        out = &it->second.buffer;
        return true;
    }
    if (!weights || !bytes) return false;
    if (weightBudgetBytes_ && weightCacheBytes_ + bytes > weightBudgetBytes_) {
        fprintf(stderr, "[WEIGHT_BUDGET_BLOCK] key=%llu cache=%zu incoming=%zu budget=%zu\n",
                static_cast<unsigned long long>(key), weightCacheBytes_, bytes, weightBudgetBytes_);
        return false;
    }
    if (weightBudgetBytes_ && bytes > weightBudgetBytes_) return false;
    if (!evictWeightCacheUntil(bytes)) return false;
    if (!checkLiveHeapAdmission(bytes)) {
        fprintf(stderr, "[WEIGHT_BUDGET_BLOCK] key=%llu live_headroom_insufficient need=%zu\n",
                static_cast<unsigned long long>(key), bytes);
        return false;
    }

    WeightCacheEntry e{};
    size_t padded = (bytes+3u)&~size_t(3u);
    if (!createBuffer(padded,
                      VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
                      VK_BUFFER_USAGE_TRANSFER_DST_BIT |
                      VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,e.buffer))
        return false;
    if (!uploadToBuffer(e.buffer,weights,bytes)) {
        destroyBuffer(e.buffer);
        return false;
    }
    e.bytes=bytes; e.type=0; e.lastUse=weightUseClock_++;
    auto ins = weightCache_.emplace(key,std::move(e)).first;
    weightCacheBytes_ += bytes;
    ++weightUploads_;
    out=&ins->second.buffer;
    return true;
}

bool VulkanCompute::ensureWeightQuant(
    int type, const void* weights, size_t bytes, DeviceBuf*& out)
{
    // DEEP2_DIRECT_RESIDENT_DISPATCH_001: certification counter — see
    // ensureWeightF32.
    if (residentDispatchDepth_) {
        ++residentLookupViolations_;
#ifdef _DEBUG
        std::fprintf(stderr,
            "[RESIDENT_LOOKUP_VIOLATION] ensureWeightQuant depth=%u type=%d\n",
            residentDispatchDepth_, type);
#endif
    }
    const uint64_t key=quantWeightKey(weights,bytes,type);
    auto it=weightCache_.find(key);
    if(it!=weightCache_.end()){
        ++weightHits_;
        it->second.lastUse = weightUseClock_++;
        out=&it->second.buffer;
        return true;
    }
    if(!weights||!bytes) {
        fprintf(stderr,"[EWB_Q4K] FAIL1 weights=%p bytes=%zu\n",weights,bytes);
        return false;
    }
    if(weightBudgetBytes_ && weightCacheBytes_ + bytes > weightBudgetBytes_) {
        fprintf(stderr,"[WEIGHT_BUDGET_BLOCK] key=%llu cache=%zu incoming=%zu budget=%zu\n",
                static_cast<unsigned long long>(key), weightCacheBytes_, bytes, weightBudgetBytes_);
        return false;
    }
    if(weightBudgetBytes_ && bytes>weightBudgetBytes_) {
        fprintf(stderr,"[EWB_Q4K] FAIL2 budget=%zu bytes=%zu\n",weightBudgetBytes_,bytes);
        return false;
    }

    size_t headroom_before = deviceLocalHeapHeadroom();
    bool evict_ok = evictWeightCacheUntil(bytes);
    if(!evict_ok) {
        size_t headroom_after = deviceLocalHeapHeadroom();
        fprintf(stderr,
            "Q4K_ADMISSION_FAIL"
            " stage=EVICT_EXHAUSTED"
            " request=%zu"
            " cacheBytes=%zu"
            " cacheEntries=%zu"
            " headroom_before=%zu"
            " headroom_after=%zu"
            " weightBudget=%zu"
            " memoryBudget=%d\n",
            bytes, weightCacheBytes_, weightCache_.size(), headroom_before, headroom_after,
            weightBudgetBytes_, (int)memoryBudgetAvailable_);
        return false;
    }
    if (!checkLiveHeapAdmission(bytes)) {
        size_t headroom_after = deviceLocalHeapHeadroom();
        fprintf(stderr,
            "Q4K_ADMISSION_FAIL"
            " stage=LIVE_HEADROOM"
            " request=%zu"
            " cacheBytes=%zu"
            " cacheEntries=%zu"
            " headroom_before=%zu"
            " headroom_after=%zu"
            " weightBudget=%zu"
            " memoryBudget=%d\n",
            bytes, weightCacheBytes_, weightCache_.size(), headroom_before, headroom_after,
            weightBudgetBytes_, (int)memoryBudgetAvailable_);
        fprintf(stderr, "[WEIGHT_BUDGET_BLOCK] key=%llu live_headroom_insufficient need=%zu\n",
                static_cast<unsigned long long>(key), bytes);
        return false;
    }

    WeightCacheEntry e{};
    size_t padded=(bytes+3u)&~size_t(3u);
    if(!createBuffer(padded,
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
        VK_BUFFER_USAGE_TRANSFER_DST_BIT |
        VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,e.buffer)) {
        fprintf(stderr,"[EWB_Q4K] FAIL4 createBuffer padded=%zu\n",padded);
        return false;
    }

    std::vector<unsigned char> tmp(padded,0);
    std::memcpy(tmp.data(),weights,bytes);
    if(!uploadToBuffer(e.buffer,tmp.data(),padded)){
        fprintf(stderr,"[EWB_Q4K] FAIL5 uploadToBuffer padded=%zu\n",padded);
        destroyBuffer(e.buffer); return false;
    }
    e.bytes=bytes; e.type=type; e.lastUse=weightUseClock_++;

    auto ins=weightCache_.emplace(key,std::move(e)).first;
    weightCacheBytes_+=bytes;
    ++weightUploads_;
    out=&ins->second.buffer;
    return true;
}

bool VulkanCompute::DispatchGemvDevice(
    const float* weights, uint64_t key,
    DeviceBuf& input, DeviceBuf& output,
    uint32_t rows, uint32_t cols)
{
    if(!weights||!rows||!cols||rows*sizeof(float)>output.size ||
       cols*sizeof(float)>input.size) return false;
    size_t count=0;
    if(mulOverflow(rows,cols,count) ||
       count>std::numeric_limits<size_t>::max()/sizeof(float)) return false;

    DeviceBuf* w=nullptr;
    if(!ensureWeightF32(weights,key,count*sizeof(float),w)) return false;
    OpsPush p{}; p.op=OP_GEMV_F32; p.n=rows; p.p0=cols;
    bool ok=dispatchOps(*w,input,output,output,p,(rows+63u)/64u);
    if(ok) ++gemvSuccess_;
    return ok;
}

bool VulkanCompute::DispatchGemvQuant(
    int type,const void* weights,size_t weightBytes,
    DeviceBuf& input,DeviceBuf& output,uint32_t rows,uint32_t cols)
{
    if(type!=8 && type!=10 && type!=12 && type!=14) return false;
    if(!weights||!weightBytes||!rows||!cols||
       rows*sizeof(float)>output.size||cols*sizeof(float)>input.size)
        return false;

    DeviceBuf* w=nullptr;
    if(!ensureWeightQuant(type,weights,weightBytes,w)) return false;
    QPush p{};
    p.type=static_cast<uint32_t>(type);
    p.rows=rows; p.cols=cols;
    if(weightBytes>std::numeric_limits<uint32_t>::max()) return false;
    p.weightBytes=static_cast<uint32_t>(weightBytes);
    bool ok=dispatchQuant(*w,input,output,p);
    if(ok) ++gemvSuccess_;
    return ok;
}

bool VulkanCompute::DispatchGemvQ4KBatch(
    const void* weights,size_t weightBytes,
    DeviceBuf& inputBatch,DeviceBuf& outputBatch,
    uint32_t rows,uint32_t cols,uint32_t batch)
{
    if(rows>=4 && qBatch4RowPipeline_) {
        const Q4KBatchTile tile=SelectQ4KBatchTile(
            weights,weightBytes,inputBatch,outputBatch,
            rows,cols,batch);
        if(tile==Q4KBatchTile::Eight && rows>=8 && qBatch8RowPipeline_)
            return DispatchGemvQ4KBatch8Row(
                weights,weightBytes,inputBatch,outputBatch,
                rows,cols,batch);
        return DispatchGemvQ4KBatch4Row(
            weights,weightBytes,inputBatch,outputBatch,
            rows,cols,batch);
    }
    if(!qBatchPipeline_||!weights||!weightBytes||
       !rows||!cols||batch==0||batch>4)
        return false;
    if(inputBatch.size < (size_t)batch*cols*sizeof(float) ||
       outputBatch.size < (size_t)batch*rows*sizeof(float))
        return false;

    DeviceBuf* w=nullptr;
    if(!ensureWeightQuant(12,weights,weightBytes,w)) return false;

    VkCommandBuffer cmd=fusedCmd_;
    VkQueryPool query=fusedQuery_;
    const bool own=!fused_;
    if(own){
        if(!beginCommand(cmd,query,true)) return false;
    }

    VkDescriptorSet set=getQuantDescriptor(*w,inputBatch,outputBatch);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,qBatchPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,qBatchPipelineLayout_,
        0,1,&set,0,nullptr);
    QBatchPush p{};
    p.rows=rows;p.cols=cols;p.weightBytes=(uint32_t)weightBytes;p.batch=batch;
    vkCmdPushConstants(
        cmd,qBatchPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    vkCmdDispatch(cmd,rows,1,1);
    recordComputeBarrier(cmd);
    if(!own) return true;
    const bool ok=endSubmitWait(
        cmd,query,GpuWorkKind::ModelCompute,
        weightBytes,workEpoch_,nullptr);
    if(ok) ++gemvSuccess_;
    return ok;
}

bool VulkanCompute::RunWeightHostBatchQ4K(
    const GpuWeightView& weight,
    const float* inputBatch,float* outputBatch,
    uint32_t batch,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weight.valid()||weight.type!=12||!inputBatch||!outputBatch||
       batch==0||batch>4||!initialized_) {
        fprintf(stderr,"[RWHB_Q4K] FAIL1 valid=%d type=%d in=%p out=%p batch=%u init=%d\n",
            (int)weight.valid(),weight.type,(const void*)inputBatch,(void*)outputBatch,batch,(int)initialized_);
        return false;
    }

    SetWorkEpoch(epoch);
    const size_t inCount=(size_t)batch*weight.cols;
    const size_t outCount=(size_t)batch*weight.rows;
    if(!EnsureScratch(70,inCount)||!EnsureScratch(71,outCount)) {
        fprintf(stderr,"[RWHB_Q4K] FAIL2 scratch70=%d scratch71=%d inCount=%zu outCount=%zu\n",
            (int)EnsureScratch(70,inCount),(int)EnsureScratch(71,outCount),inCount,outCount);
        return false;
    }
    DeviceBuf& in=Scratch(70);
    DeviceBuf& out=Scratch(71);

    DeviceBuf* resident=nullptr;
    if(!ensureWeightQuant(
            weight.type,weight.data,weight.bytes,resident)) {
        fprintf(stderr,"[RWHB_Q4K] FAIL3 ensureWeightQuant type=%d bytes=%zu\n",
            weight.type,weight.bytes);
        return false;
    }

    const size_t inBytes=inCount*sizeof(float);
    const size_t outBytes=outCount*sizeof(float);
    DeviceBuf* upStage=nullptr;
    DeviceBuf* downStage=nullptr;
    void* upMap=nullptr;
    void* downMap=nullptr;
    if(!ensureMappedStaging(true,inBytes,upStage,upMap)||
       !ensureMappedStaging(false,outBytes,downStage,downMap)) {
        fprintf(stderr,"[RWHB_Q4K] FAIL4 up=%p down=%p inBytes=%zu outBytes=%zu\n",
            (void*)upStage,(void*)downStage,inBytes,outBytes);
        return false;
    }
    std::memcpy(upMap,inputBatch,inBytes);

    if(!BeginFusedLayer()) {
        fprintf(stderr,"[RWHB_Q4K] FAIL5 BeginFusedLayer\n");
        return false;
    }
    auto abort=[&]{
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    };
    if(!recordCopy(fusedCmd_,*upStage,in,inBytes)) {
        fprintf(stderr,"[RWHB_Q4K] FAIL6 recordCopy up\n");
        return abort();
    }
    if(!DispatchGemvQ4KBatch(
            weight.data,weight.bytes,in,out,
            weight.rows,weight.cols,batch)) {
        fprintf(stderr,"[RWHB_Q4K] FAIL7 DispatchGemvQ4KBatch rows=%u cols=%u batch=%u\n",
            weight.rows,weight.cols,batch);
        return abort();
    }
    if(!recordCopy(fusedCmd_,out,*downStage,outBytes)) {
        fprintf(stderr,"[RWHB_Q4K] FAIL8 recordCopy down\n");
        return abort();
    }
    if(!EndFusedLayer()) {
        fprintf(stderr,"[RWHB_Q4K] FAIL9 EndFusedLayer\n");
        return false;
    }

    std::memcpy(outputBatch,downMap,outBytes);
    return true;
}

bool VulkanCompute::RunWeightGroupHostBatchQ4K(
    const GpuWeightView* weights,float* const* outputs,size_t weightCount,
    const float* inputBatch,uint32_t batch,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weights||!outputs||!inputBatch||weightCount<2||weightCount>3||
       !batch||batch>4) return false;
    const uint32_t cols=weights[0].cols;
    if(!cols) return false;
    for(size_t i=0;i<weightCount;++i)
        if(!weights[i].valid()||weights[i].type!=12||
           weights[i].cols!=cols||!outputs[i])
            return false;

    SetWorkEpoch(epoch);
    const size_t inCount=(size_t)batch*cols;
    if(!EnsureScratch(110,inCount)) return false;
    auto& in=Scratch(110);
    DeviceBuf* us=nullptr;void* um=nullptr;
    const size_t inBytes=inCount*sizeof(float);
    if(!ensureMappedStaging(true,inBytes,us,um)) return false;
    std::memcpy(um,inputBatch,inBytes);

    size_t totalOutBytes=0;
    size_t offsets[3]{};
    for(size_t i=0;i<weightCount;++i) {
        offsets[i]=totalOutBytes;
        const size_t b=(size_t)batch*weights[i].rows*sizeof(float);
        if(totalOutBytes>SIZE_MAX-b) return false;
        totalOutBytes+=b;
        if(!EnsureScratch(111u+(unsigned)i,(size_t)batch*weights[i].rows))
            return false;
    }
    DeviceBuf* ds=nullptr;void* dm=nullptr;
    if(!ensureMappedStaging(false,totalOutBytes,ds,dm)) return false;

    if(!BeginFusedLayer()) return false;
    auto abort=[&]{if(FusedRecording())(void)EndFusedLayer();return false;};
    if(!recordCopy(fusedCmd_,*us,in,inBytes)) return abort();
    for(size_t i=0;i<weightCount;++i) {
        auto& out=Scratch(111u+(unsigned)i);
        if(!DispatchGemvQ4KBatch(
                weights[i].data,weights[i].bytes,in,out,
                weights[i].rows,weights[i].cols,batch))
            return abort();
        const size_t b=(size_t)batch*weights[i].rows*sizeof(float);
        if(!recordCopy(
                fusedCmd_,out,*ds,b,0,(VkDeviceSize)offsets[i]))
            return abort();
    }
    if(!EndFusedLayer()) return false;
    for(size_t i=0;i<weightCount;++i) {
        const size_t b=(size_t)batch*weights[i].rows*sizeof(float);
        std::memcpy(outputs[i],(const uint8_t*)dm+offsets[i],b);
    }
    return true;
}

bool VulkanCompute::PrefetchWeight(
    const void* weights,size_t bytes,uint32_t& slot)
{
    slot=0;
    if(!weights||!bytes) return false;
    PrefetchEntry e{};
    const size_t padded=(bytes+3u)&~size_t(3u);
    if(!createBuffer(padded,
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
        VK_BUFFER_USAGE_TRANSFER_DST_BIT |
        VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,e.buffer))
        return false;
    std::vector<unsigned char> tmp(padded,0);
    std::memcpy(tmp.data(),weights,bytes);
    if(!uploadToBuffer(e.buffer,tmp.data(),padded)){
        destroyBuffer(e.buffer); return false;
    }
    e.bytes=bytes; e.valid=true;
    prefetch_.push_back(std::move(e));
    slot=static_cast<uint32_t>(prefetch_.size()-1);
    ++weightUploads_;
    return true;
}

bool VulkanCompute::SubmitGemvPrefetch(
    uint32_t slot,DeviceBuf& input,DeviceBuf& output,
    uint32_t rows,uint32_t cols,size_t packedBytes,int quantType)
{
    if(slot>=prefetch_.size()||!prefetch_[slot].valid) return false;
    auto& e=prefetch_[slot];
    if(packedBytes && quantType) {
        if(quantType!=8&&quantType!=10&&quantType!=12&&quantType!=14) return false;
        QPush p{};
        p.type=static_cast<uint32_t>(quantType);
        p.rows=rows;p.cols=cols;
        if(e.bytes>std::numeric_limits<uint32_t>::max()) return false;
        p.weightBytes=static_cast<uint32_t>(e.bytes);
        bool ok=dispatchQuant(e.buffer,input,output,p);
        if(ok) ++gemvSuccess_;
        return ok;
    }
    OpsPush p{};p.op=OP_GEMV_F32;p.n=rows;p.p0=cols;
    bool ok=dispatchOps(e.buffer,input,output,output,p,(rows+63u)/64u);
    if(ok) ++gemvSuccess_;
    return ok;
}

bool VulkanCompute::WaitWeightCompute(uint32_t) {
    return !fused_ ? (vkQueueWaitIdle(queue_)==VK_SUCCESS) : true;
}

bool VulkanCompute::WeightPrefetchActive() const noexcept {
    const char* e=std::getenv("DEEP2_WEIGHT_PREFETCH");
    return e && e[0] && e[0]!='0';
}

bool VulkanCompute::EnsureScratch(unsigned index, size_t floatCount) {
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!initialized_ || floatCount == 0 ||
        floatCount > std::numeric_limits<size_t>::max()/sizeof(float))
        return false;
    if (scratch_.size() <= index) scratch_.resize(index + 1);
    DeviceBuf& b = scratch_[index];
    const size_t bytes = floatCount * sizeof(float);
    if (b && b.size >= bytes) return true;
    destroyBuffer(b);
    return createBuffer(
        bytes,
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
        VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
        VK_BUFFER_USAGE_TRANSFER_DST_BIT,
        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
        b);
}

VulkanCompute::DeviceBuf& VulkanCompute::Scratch(unsigned index) {
    if (scratch_.size() <= index) scratch_.resize(index + 1);
    return scratch_[index];
}

bool VulkanCompute::UploadVector(
    DeviceBuf& dst, const float* src, size_t count)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!src || count == 0 ||
        count > std::numeric_limits<size_t>::max()/sizeof(float))
        return false;
    return uploadToBuffer(dst, src, count*sizeof(float));
}

bool VulkanCompute::DownloadVector(
    const DeviceBuf& src, float* dst, size_t count)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!dst || count == 0 ||
        count > std::numeric_limits<size_t>::max()/sizeof(float))
        return false;
    return downloadFromBuffer(src, dst, count*sizeof(float));
}

bool VulkanCompute::CopyVector(
    DeviceBuf& src, DeviceBuf& dst, size_t count,
    size_t srcFloatOffset, size_t dstFloatOffset)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!count ||
        count > std::numeric_limits<size_t>::max()/sizeof(float) ||
        srcFloatOffset > std::numeric_limits<size_t>::max()/sizeof(float) ||
        dstFloatOffset > std::numeric_limits<size_t>::max()/sizeof(float))
        return false;

    const VkDeviceSize bytes = static_cast<VkDeviceSize>(count*sizeof(float));
    const VkDeviceSize so =
        static_cast<VkDeviceSize>(srcFloatOffset*sizeof(float));
    const VkDeviceSize doff =
        static_cast<VkDeviceSize>(dstFloatOffset*sizeof(float));

    VkCommandBuffer cmd{};
    VkQueryPool query{};
    return beginCommand(cmd,query,true) &&
           recordCopy(cmd,src,dst,bytes,so,doff) &&
           endSubmitWait(cmd,query,GpuWorkKind::ModelTransfer,
                         bytes,workEpoch_,nullptr);
}

bool VulkanCompute::DispatchWeight(
    const GpuWeightView& weight, DeviceBuf& input, DeviceBuf& output)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!weight.valid()) {
        std::fprintf(stderr,"[DW] FAIL weight.valid()=0\n"); std::fflush(stderr);
        return false;
    }
    if (static_cast<size_t>(weight.cols)*sizeof(float) > input.size ||
        static_cast<size_t>(weight.rows)*sizeof(float) > output.size) {
        std::fprintf(stderr,"[DW] FAIL size mismatch w.cols=%u w.rows=%u in.size=%zu out.size=%zu\n",
                     weight.cols, weight.rows, (size_t)input.size, (size_t)output.size); std::fflush(stderr);
        return false;
    }

    if (weight.type == 0) {
        const uint64_t key = weight.key
            ? weight.key
            : static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(weight.data));
        return DispatchGemvDevice(
            static_cast<const float*>(weight.data),key,
            input,output,weight.rows,weight.cols);
    }

    bool ok = DispatchGemvQuant(
        weight.type,weight.data,weight.bytes,
        input,output,weight.rows,weight.cols);
    if(!ok) {
        std::fprintf(stderr,"[DW] DispatchGemvQuant failed type=%d bytes=%zu rows=%u cols=%u\n",
                     weight.type, weight.bytes, weight.rows, weight.cols); std::fflush(stderr);
    }
    return ok;
}

bool VulkanCompute::RunExpertFFN(
    const GpuWeightView& gate,
    const GpuWeightView& up,
    const GpuWeightView& down,
    const float* input, float* output,
    uint32_t hidden, uint32_t intermediate,
    uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!input || !output || !hidden || !intermediate ||
        gate.rows != intermediate || gate.cols != hidden ||
        up.rows != intermediate || up.cols != hidden ||
        down.rows != hidden || down.cols != intermediate)
        return false;

    SetWorkEpoch(epoch);
    if (!EnsureScratch(0,hidden) ||
        !EnsureScratch(1,intermediate) ||
        !EnsureScratch(2,intermediate) ||
        !EnsureScratch(3,intermediate) ||
        !EnsureScratch(4,hidden))
        return false;

    DeviceBuf& x = Scratch(0);
    DeviceBuf& g = Scratch(1);
    DeviceBuf& u = Scratch(2);
    DeviceBuf& act = Scratch(3);
    DeviceBuf& y = Scratch(4);

    if (!UploadVector(x,input,hidden)) return false;
    if (!DispatchWeight(gate,x,g)) return false;
    if (!DispatchWeight(up,x,u)) return false;
    if (!DispatchSwiGLU(g,u,act,intermediate)) return false;
    if (!DispatchWeight(down,act,y)) return false;
    return DownloadVector(y,output,hidden);
}

void VulkanCompute::ResetMLACache() {
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    destroyBuffer(mlaKCache_);
    destroyBuffer(mlaVCache_);
    mlaCacheHeads_=0;
    mlaCacheKeyLen_=0;
    mlaCacheValueLen_=0;
    mlaCacheLayers_=0;
    mlaCacheCapacity_=0;
    mlaCacheMaxSeq_=0;
}

bool VulkanCompute::RunMLAAttentionHost(
    const float* q, const float* k, const float* v,
    float* output,
    uint32_t heads, uint32_t keyLen, uint32_t valueLen,
    uint32_t layer, uint32_t pos,
    uint32_t layers, uint32_t maxSeq,
    float scale, uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!initialized_ || !opsPipeline_ ||
        !q || !k || !v || !output ||
        !heads || !keyLen || !valueLen ||
        !layers || !maxSeq || layer>=layers || pos>=maxSeq ||
        !(scale>0.0f) || !std::isfinite(scale))
        return false;

    const bool shapeChanged =
        mlaCacheHeads_!=heads ||
        mlaCacheKeyLen_!=keyLen ||
        mlaCacheValueLen_!=valueLen ||
        mlaCacheLayers_!=layers ||
        mlaCacheMaxSeq_!=maxSeq;
    if (shapeChanged) ResetMLACache();

    auto checkedMul=[](uint64_t a,uint64_t b,uint64_t& out)->bool{
        if(a && b>std::numeric_limits<uint64_t>::max()/a) return false;
        out=a*b; return true;
    };

    if (mlaCacheCapacity_ <= pos) {
        uint32_t newCap = mlaCacheCapacity_ ? mlaCacheCapacity_ : 16u;
        while (newCap <= pos) {
            if (newCap > maxSeq/2u) { newCap=maxSeq; break; }
            newCap*=2u;
        }
        newCap=std::min(newCap,maxSeq);
        if(newCap<=pos) return false;

        uint64_t kElems=0,vElems=0,tmp=0;
        if(!checkedMul(layers,newCap,tmp) ||
           !checkedMul(tmp,heads,tmp) ||
           !checkedMul(tmp,keyLen,kElems) ||
           !checkedMul(layers,newCap,tmp) ||
           !checkedMul(tmp,heads,tmp) ||
           !checkedMul(tmp,valueLen,vElems))
            return false;
        if(kElems>std::numeric_limits<VkDeviceSize>::max()/sizeof(float) ||
           vElems>std::numeric_limits<VkDeviceSize>::max()/sizeof(float))
            return false;

        DeviceBuf newK{},newV{};
        const VkBufferUsageFlags usage =
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
            VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
            VK_BUFFER_USAGE_TRANSFER_DST_BIT;
        if(!createBuffer(kElems*sizeof(float),usage,
                         VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,newK) ||
           !createBuffer(vElems*sizeof(float),usage,
                         VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,newV)) {
            destroyBuffer(newK);destroyBuffer(newV);return false;
        }

        if(mlaKCache_ && mlaVCache_ && mlaCacheCapacity_) {
            VkCommandBuffer cmd{};
            VkQueryPool query{};
            if(!beginCommand(cmd,query,true)) {
                destroyBuffer(newK);destroyBuffer(newV);return false;
            }
            for(uint32_t l=0;l<layers;++l){
                const uint64_t oldKBase=
                    static_cast<uint64_t>(l)*mlaCacheCapacity_*heads*keyLen;
                const uint64_t newKBase=
                    static_cast<uint64_t>(l)*newCap*heads*keyLen;
                const uint64_t oldVBase=
                    static_cast<uint64_t>(l)*mlaCacheCapacity_*heads*valueLen;
                const uint64_t newVBase=
                    static_cast<uint64_t>(l)*newCap*heads*valueLen;
                const uint64_t copyK=
                    static_cast<uint64_t>(mlaCacheCapacity_)*heads*keyLen;
                const uint64_t copyV=
                    static_cast<uint64_t>(mlaCacheCapacity_)*heads*valueLen;
                if(!recordCopy(cmd,mlaKCache_,newK,copyK*sizeof(float),
                               oldKBase*sizeof(float),newKBase*sizeof(float)) ||
                   !recordCopy(cmd,mlaVCache_,newV,copyV*sizeof(float),
                               oldVBase*sizeof(float),newVBase*sizeof(float))) {
                    destroyBuffer(newK);destroyBuffer(newV);return false;
                }
            }
            if(!endSubmitWait(cmd,query,GpuWorkKind::ModelTransfer,
                              0,epoch,nullptr)) {
                destroyBuffer(newK);destroyBuffer(newV);return false;
            }
        }

        destroyBuffer(mlaKCache_);
        destroyBuffer(mlaVCache_);
        mlaKCache_=newK;
        mlaVCache_=newV;
        mlaCacheHeads_=heads;
        mlaCacheKeyLen_=keyLen;
        mlaCacheValueLen_=valueLen;
        mlaCacheLayers_=layers;
        mlaCacheCapacity_=newCap;
        mlaCacheMaxSeq_=maxSeq;
    } else if (mlaCacheCapacity_ && mlaCacheHeads_==0) {
        return false;
    }

    // Upload the single query/key/value vectors for this position.
    const size_t qElems=(size_t)heads*keyLen;
    const size_t vElems=(size_t)heads*valueLen;
    if(!EnsureScratch(40,qElems)||
       !EnsureScratch(41,(size_t)layers*heads*keyLen)||
       !EnsureScratch(42,(size_t)layers*heads*valueLen)||
       !EnsureScratch(43,qElems))
        return false;
    DeviceBuf& qBuf=Scratch(40);
    DeviceBuf& kSlice=Scratch(41);
    DeviceBuf& vSlice=Scratch(42);
    DeviceBuf& outBuf=Scratch(43);
    if(!UploadVector(qBuf,q,qElems*sizeof(float))||
       !UploadVector(kSlice,k,qElems*sizeof(float))||
       !UploadVector(vSlice,v,vElems*sizeof(float)))
        return false;

    // Copy the K/V slice into the device cache at (layer, pos).
    {
        const uint64_t kBase=(uint64_t)layer*mlaCacheCapacity_*heads*keyLen+pos*heads*keyLen;
        const uint64_t vBase=(uint64_t)layer*mlaCacheCapacity_*heads*valueLen+pos*heads*valueLen;
        VkCommandBuffer cmd{};
        VkQueryPool query{};
        if(!beginCommand(cmd,query,true)) return false;
        if(!recordCopy(cmd,kSlice,mlaKCache_,(VkDeviceSize)(heads*keyLen*sizeof(float)),
                       0,(VkDeviceSize)(kBase*sizeof(float)))||
           !recordCopy(cmd,vSlice,mlaVCache_,(VkDeviceSize)(heads*valueLen*sizeof(float)),
                       0,(VkDeviceSize)(vBase*sizeof(float))))
            return false;
        recordComputeBarrier(cmd);
        if(!endSubmitWait(cmd,query,GpuWorkKind::ModelTransfer,
                          (heads*(keyLen+valueLen))*sizeof(float),
                          epoch,nullptr))
            return false;
    }

    // Dispatch attention: q . cached_K^T -> softmax -> . cached_V -> output.
    OpsPush push{};
    push.op=OP_MLA_ATTN;
    push.n=pos+1;
    push.p0=heads;
    push.p1=keyLen;
    push.p2=valueLen;
    push.p3=layer;
    push.f0=scale;
    if(!dispatchOps(qBuf,mlaKCache_,mlaVCache_,outBuf,push,
                    (pos+1)*heads,GpuWorkKind::ModelCompute))
        return false;

    return DownloadVector(outBuf,output,qElems*sizeof(float));
}

bool VulkanCompute::RunWeightHostRoundTrip(
    const GpuWeightView& weight,
    const float* input,
    float* output,
    uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weight.valid()||!input||!output||!initialized_)
        return false;

    // PARITY: dual-row lane tag (dispatches inside this round-trip).
    SetQ4kLaneTag(kQ4kLaneDual);
    struct LaneTagRestore {
        VulkanCompute* self; uint32_t prev;
        ~LaneTagRestore(){ self->SetQ4kLaneTag(prev); }
    } laneRestore{this, q4kLane_};

    SetWorkEpoch(epoch);
    if(!EnsureScratch(60,weight.cols)||
       !EnsureScratch(61,weight.rows))
        return false;
    DeviceBuf& in=Scratch(60);
    DeviceBuf& out=Scratch(61);

    DeviceBuf* resident=nullptr;
    if(weight.type==0){
        const uint64_t key=weight.key
            ? weight.key
            : static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(weight.data));
        if(!ensureWeightF32(
                static_cast<const float*>(weight.data),key,
                weight.bytes,resident))
            return false;
    }else{
        if(!ensureWeightQuant(
                weight.type,weight.data,weight.bytes,resident))
            return false;
    }

    const size_t inBytes=
        static_cast<size_t>(weight.cols)*sizeof(float);
    const size_t outBytes=
        static_cast<size_t>(weight.rows)*sizeof(float);

    DeviceBuf* upStage=nullptr;
    DeviceBuf* downStage=nullptr;
    void* upMap=nullptr;
    void* downMap=nullptr;
    if(!ensureMappedStaging(true,inBytes,upStage,upMap)||
       !ensureMappedStaging(false,outBytes,downStage,downMap))
        return false;
    std::memcpy(upMap,input,inBytes);

    if(!BeginFusedLayer()) return false;
    auto abort=[&]{
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    };

    // BeginFusedLayer made fusedCmd_ active, so DispatchWeight records only.
    if(!recordCopy(fusedCmd_,*upStage,in,inBytes))
        return abort();
    if(!DispatchWeight(weight,in,out))
        return abort();
    if(!recordCopy(fusedCmd_,out,*downStage,outBytes))
        return abort();
    if(!EndFusedLayer())
        return false;

    std::memcpy(output,downMap,outBytes);

    // DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001: accumulate the interval
    // EndFusedLayer finalized (timestamp queries, post-fence) into the
    // dense-row timing authority. No new synchronization point.
    if (lastFusedIntervalValid_)
        RecordDenseRowGpuInterval(lastFusedInterval_, /*isGroup=*/false);
    return true;
}

bool VulkanCompute::RunWeightGroupHostRoundTrip(
    const GpuWeightView* weights,
    float* const* outputs,
    size_t count,
    const float* input,
    uint32_t inputCount,
    uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weights||!outputs||!input||count<2||count>3||!inputCount)
        return false;

    // PARITY: dual-row lane tag (dispatches inside this group round-trip).
    SetQ4kLaneTag(kQ4kLaneDual);
    struct LaneTagRestore {
        VulkanCompute* self; uint32_t prev;
        ~LaneTagRestore(){ self->SetQ4kLaneTag(prev); }
    } laneRestore{this, q4kLane_};

    SetWorkEpoch(epoch);
    if(!EnsureScratch(62,inputCount)) return false;
    DeviceBuf& in=Scratch(62);

    size_t totalOutBytes=0;
    size_t offsets[3]{};
    DeviceBuf* resident[3]{};

    for(size_t i=0;i<count;++i){
        const auto& w=weights[i];
        if(!w.valid()||w.cols!=inputCount||!outputs[i])
            return false;
        if(!EnsureScratch(63u+(unsigned)i,w.rows))
            return false;

        offsets[i]=totalOutBytes;
        const size_t b=static_cast<size_t>(w.rows)*sizeof(float);
        if(totalOutBytes>std::numeric_limits<size_t>::max()-b)
            return false;
        totalOutBytes+=b;

        if(w.type==0){
            const uint64_t key=w.key
                ? w.key
                : static_cast<uint64_t>(
                    reinterpret_cast<uintptr_t>(w.data));
            if(!ensureWeightF32(
                    static_cast<const float*>(w.data),key,
                    w.bytes,resident[i]))
                return false;
        }else{
            if(!ensureWeightQuant(
                    w.type,w.data,w.bytes,resident[i]))
                return false;
        }
    }

    const size_t inBytes=static_cast<size_t>(inputCount)*sizeof(float);
    DeviceBuf* upStage=nullptr;
    DeviceBuf* downStage=nullptr;
    void* upMap=nullptr;
    void* downMap=nullptr;
    if(!ensureMappedStaging(true,inBytes,upStage,upMap)||
       !ensureMappedStaging(false,totalOutBytes,downStage,downMap))
        return false;
    std::memcpy(upMap,input,inBytes);

    if(!BeginFusedLayer()) return false;
    auto abort=[&]{
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    };
    if(!recordCopy(fusedCmd_,*upStage,in,inBytes))
        return abort();

    for(size_t i=0;i<count;++i){
        DeviceBuf& out=Scratch(63u+(unsigned)i);
        if(!DispatchWeight(weights[i],in,out))
            return abort();
        const VkDeviceSize b=
            static_cast<VkDeviceSize>(weights[i].rows)*sizeof(float);
        if(!recordCopy(
                fusedCmd_,out,*downStage,b,0,
                static_cast<VkDeviceSize>(offsets[i])))
            return abort();
    }
    if(!EndFusedLayer()) return false;

    for(size_t i=0;i<count;++i){
        std::memcpy(
            outputs[i],
            static_cast<const uint8_t*>(downMap)+offsets[i],
            static_cast<size_t>(weights[i].rows)*sizeof(float));
    }

    // DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001 (group lane): same
    // post-fence interval accumulation as the single lane.
    if (lastFusedIntervalValid_)
        RecordDenseRowGpuInterval(lastFusedInterval_, /*isGroup=*/true);
    return true;
}

bool VulkanCompute::DispatchWeightResident(
    const GpuWeightView& weight,
    DeviceBuf& residentWeight,
    DeviceBuf& input, DeviceBuf& output)
{
    // DEEP2_DIRECT_RESIDENT_DISPATCH_001: once residency is resolved the
    // dispatch binds the resident DeviceBuf directly. There is NO route
    // from this function into ensureWeightF32/ensureWeightQuant — the
    // meta is used only for geometry/type push constants.
    ResidentDispatchGuard guard(this);
    ++residentDirectDispatches_;

    if (weight.rows == 0 || weight.cols == 0)
        return false;
    if (!residentWeight ||
        residentWeight.buffer == VK_NULL_HANDLE)
        return false;
    if (residentWeight.size < weight.bytes)
        return false;
    if (static_cast<size_t>(weight.cols)*sizeof(float) > input.size ||
        static_cast<size_t>(weight.rows)*sizeof(float) > output.size)
        return false;

    if (weight.type == 0) {
        return DispatchGemvF32Resident(
            residentWeight, input, output,
            weight.rows, weight.cols);
    }

    if (weight.bytes > std::numeric_limits<uint32_t>::max())
        return false;

    QPush p{};
    p.type = static_cast<uint32_t>(weight.type);
    p.rows = weight.rows;
    p.cols = weight.cols;
    p.weightBytes = static_cast<uint32_t>(weight.bytes);
    const bool ok = dispatchQuant(residentWeight, input, output, p);
    if (ok) ++gemvSuccess_;
    return ok;
}

bool VulkanCompute::DispatchGemvF32Resident(
    DeviceBuf& residentWeight, DeviceBuf& input, DeviceBuf& output,
    uint32_t rows, uint32_t cols)
{
    // Admission-free F32 mirror of the quant resident dispatch.
    ResidentDispatchGuard guard(this);
    if (!residentWeight || !rows || !cols)
        return false;
    if (static_cast<size_t>(rows)*static_cast<size_t>(cols)*sizeof(float) >
        static_cast<size_t>(residentWeight.size))
        return false;
    OpsPush p{};
    p.op = OP_GEMV_F32;
    p.n = rows;
    p.p0 = cols;
    const bool ok = dispatchOps(
        residentWeight, input, output, output, p, (rows+63u)/64u);
    if (ok) ++gemvSuccess_;
    return ok;
}

bool VulkanCompute::DispatchQuantRowsResident(
    const GpuWeightView& meta, DeviceBuf& target,
    uint32_t rowBase, uint32_t rowCount,
    DeviceBuf& input, DeviceBuf& output)
{
    // DEEP2_COLD_ROW_RACE_001: ranged dispatch into a (partially)
    // promoted whole-tensor target. Must run inside a fused layer so the
    // only synchronization is the layer's terminal fence.
    ResidentDispatchGuard guard(this);
    if (!meta.valid() || !target || !input || !output || !rowCount)
        return false;
    const size_t rowBytes = QuantPackedRowBytes(meta.type, meta.cols);
    if (!rowBytes || meta.bytes < rowBytes) return false;
    const uint64_t rowsPerSlice = meta.bytes / rowBytes;
    if (rowBase + rowCount > rowsPerSlice) return false;
    if (static_cast<size_t>(meta.cols)*sizeof(float) > input.size)
        return false;
    if (static_cast<size_t>(rowCount)*sizeof(float) > output.size)
        return false;

    // Reuse the existing single-row quant GEMV shader by binding a
    // byte RANGE of the target as the weight storage buffer so the
    // shader's row indexing starts at rowBase.
    return recordQuantRowsResident(
        fusedCmd_, meta, target, rowBase, rowCount, input, output);
}

bool VulkanCompute::recordQuantRowsResident(
    VkCommandBuffer cmd, const GpuWeightView& meta, DeviceBuf& target,
    uint32_t rowBase, uint32_t rowCount,
    DeviceBuf& input, DeviceBuf& output)
{
    if (cmd == VK_NULL_HANDLE || !qPipeline_) return false;
    const size_t rowBytes = QuantPackedRowBytes(meta.type, meta.cols);
    if (!rowBytes) return false;
    const VkDescriptorSet set = getQuantDescriptorRange(
        target,
        static_cast<VkDeviceSize>(rowBase)*static_cast<VkDeviceSize>(rowBytes),
        static_cast<VkDeviceSize>(rowCount)*static_cast<VkDeviceSize>(rowBytes),
        input, output);
    if (set == VK_NULL_HANDLE) return false;

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, qPipeline_);
    vkCmdBindDescriptorSets(
        cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
        qPipelineLayout_, 0, 1, &set, 0, nullptr);
    QPush push{};
    push.type = static_cast<uint32_t>(meta.type);
    push.rows = rowCount;
    push.cols = meta.cols;
    push.weightBytes = static_cast<uint32_t>(rowCount*rowBytes);
    vkCmdPushConstants(
        cmd, qPipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT,
        0, sizeof(push), &push);
    vkCmdDispatch(cmd, rowCount, 1, 1);
    recordComputeBarrier(cmd);
    ++residentDirectDispatches_;
    return true;
}

size_t VulkanCompute::QuantPackedRowBytes(int type, uint32_t cols) noexcept
{
    // TRAP-5: the one authoritative packed-row stride. Any call site
    // needing "bytes of packed weights per row" goes through this.
    if (cols == 0) return 0;
    if (type == 0) {
        if (cols > std::numeric_limits<uint32_t>::max()/sizeof(float))
            return 0;
        return static_cast<size_t>(cols)*sizeof(float);
    }
    const QuantTypeDesc* desc = LookupQuantType(static_cast<uint32_t>(type));
    if (!desc || !desc->isQuantized || !desc->blockElements)
        return 0;
    if (cols % desc->blockElements != 0)
        return 0;
    const size_t blocksPerRow = cols / desc->blockElements;
    if (blocksPerRow > std::numeric_limits<size_t>::max()/desc->blockBytes)
        return 0;
    return blocksPerRow * desc->blockBytes;
}

VulkanCompute::ResidentHotHandle* VulkanCompute::GetHotHandle(uint64_t weightKey)
{
    // Handle nodes are pointer-stable: unordered_map nodes do not move on
    // rehash and entries are only erased in cleanup().
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    auto it = hotHandles_.find(weightKey);
    if (it != hotHandles_.end())
        return &it->second;
    // ResidentHotHandle holds a std::atomic (non-movable): construct the
    // node in place instead of emplacing a temporary.
    return &hotHandles_.try_emplace(weightKey).first->second;
}

VulkanCompute::ResidentWeight* VulkanCompute::AcquireHotView(
    ResidentHotHandle* handle)
{
    if (!handle) return nullptr;
    ResidentWeight* v = handle->view.load(std::memory_order_acquire);
    if (v == ResidentHotHandle::Promoting() ||
        v == ResidentHotHandle::Failed() ||
        !v) {
        return nullptr;
    }
    // Reader registration. The publisher never frees while readers hold
    // the count above zero (see RetireResidentObject).
    residentReaderCount_.fetch_add(1, std::memory_order_acq_rel);
    ++rcuHotAcquires_;
    return v;
}

void VulkanCompute::ReleaseHotView() noexcept
{
    residentReaderCount_.fetch_sub(1, std::memory_order_release);
}

bool VulkanCompute::TryBeginHotPromotion(ResidentHotHandle* handle)
{
    if (!handle) return false;
    ResidentWeight* expected = nullptr;
    return handle->view.compare_exchange_strong(
        expected, ResidentHotHandle::Promoting(),
        std::memory_order_acq_rel, std::memory_order_acquire);
}

void VulkanCompute::PublishHotView(
    ResidentHotHandle* handle, ResidentWeight* view)
{
    if (!handle || !view) return;
    // Publication is a release store; the object is fully constructed and
    // its device buffer is complete before this point.
    handle->view.store(view, std::memory_order_release);
    ++rcuPublishes_;
}

void VulkanCompute::FailHotView(ResidentHotHandle* handle)
{
    if (!handle) return;
    ResidentWeight* expected = ResidentHotHandle::Promoting();
    handle->view.compare_exchange_strong(
        expected, ResidentHotHandle::Failed(),
        std::memory_order_acq_rel, std::memory_order_relaxed);
}

bool VulkanCompute::RunWeightResidentHot(
    const GpuWeightView& weight, DeviceBuf* residentWeight,
    const float* input, float* output,
    uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weight.valid()||!residentWeight||!input||!output||!initialized_)
        return false;

    SetQ4kLaneTag(kQ4kLaneDual);
    struct LaneTagRestore {
        VulkanCompute* self; uint32_t prev;
        ~LaneTagRestore(){ self->SetQ4kLaneTag(prev); }
    } laneRestore{this, q4kLane_};

    SetWorkEpoch(epoch);
    if(!EnsureScratch(60,weight.cols)||
       !EnsureScratch(61,weight.rows))
        return false;
    DeviceBuf& in=Scratch(60);
    DeviceBuf& out=Scratch(61);

    const size_t inBytes=static_cast<size_t>(weight.cols)*sizeof(float);
    const size_t outBytes=static_cast<size_t>(weight.rows)*sizeof(float);

    DeviceBuf* upStage=nullptr;
    DeviceBuf* downStage=nullptr;
    void* upMap=nullptr;
    void* downMap=nullptr;
    if(!ensureMappedStaging(true,inBytes,upStage,upMap)||
       !ensureMappedStaging(false,outBytes,downStage,downMap))
        return false;
    std::memcpy(upMap,input,inBytes);

    if(!BeginFusedLayer()) return false;
    auto abort=[&]{
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    };

    if(!recordCopy(fusedCmd_,*upStage,in,inBytes))
        return abort();
    // DEEP2_DIRECT_RESIDENT_DISPATCH_001: the resolved resident buffer is
    // bound directly — no re-entry into weightCache_ admission (the old
    // code validated residentWeight and then routed through DispatchWeight,
    // which re-looked the weight up).
    if(!DispatchWeightResident(weight,*residentWeight,in,out))
        return abort();
    if(!recordCopy(fusedCmd_,out,*downStage,outBytes))
        return abort();
    if(!EndFusedLayer())
        return false;

    std::memcpy(output,downMap,outBytes);

    if(lastFusedIntervalValid_)
        RecordDenseRowGpuInterval(lastFusedInterval_, /*isGroup=*/false);
    return true;
}

bool VulkanCompute::RunWeightGroupResidentHot(
    const GpuWeightView* weights, DeviceBuf* const* residentWeights,
    float* const* outputs, size_t count,
    const float* input, uint32_t inputCount,
    uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weights||!residentWeights||!outputs||!input||count<2||count>3||!inputCount)
        return false;

    SetQ4kLaneTag(kQ4kLaneDual);
    struct LaneTagRestore {
        VulkanCompute* self; uint32_t prev;
        ~LaneTagRestore(){ self->SetQ4kLaneTag(prev); }
    } laneRestore{this, q4kLane_};

    SetWorkEpoch(epoch);
    if(!EnsureScratch(62,inputCount)) return false;
    DeviceBuf& in=Scratch(62);

    size_t totalOutBytes=0;
    size_t offsets[3]{};
    for(size_t i=0;i<count;++i){
        if(!weights[i].valid()||weights[i].cols!=inputCount||!outputs[i])
            return false;
        if(!EnsureScratch(63u+(unsigned)i,weights[i].rows))
            return false;
        offsets[i]=totalOutBytes;
        const size_t b=static_cast<size_t>(weights[i].rows)*sizeof(float);
        if(totalOutBytes>std::numeric_limits<size_t>::max()-b)
            return false;
        totalOutBytes+=b;
    }

    const size_t inBytes=static_cast<size_t>(inputCount)*sizeof(float);
    DeviceBuf* upStage=nullptr;
    DeviceBuf* downStage=nullptr;
    void* upMap=nullptr;
    void* downMap=nullptr;
    if(!ensureMappedStaging(true,inBytes,upStage,upMap)||
       !ensureMappedStaging(false,totalOutBytes,downStage,downMap))
        return false;
    std::memcpy(upMap,input,inBytes);

    if(!BeginFusedLayer()) return false;
    auto abort=[&]{
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    };
    if(!recordCopy(fusedCmd_,*upStage,in,inBytes))
        return abort();

    for(size_t i=0;i<count;++i){
        DeviceBuf& out=Scratch(63u+(unsigned)i);
        if(!DispatchWeight(weights[i],in,out))
            return abort();
        const VkDeviceSize b=
            static_cast<VkDeviceSize>(weights[i].rows)*sizeof(float);
        if(!recordCopy(
                fusedCmd_,out,*downStage,b,0,
                static_cast<VkDeviceSize>(offsets[i])))
            return abort();
    }
    if(!EndFusedLayer()) return false;

    for(size_t i=0;i<count;++i){
        std::memcpy(
            outputs[i],
            static_cast<const uint8_t*>(downMap)+offsets[i],
            static_cast<size_t>(weights[i].rows)*sizeof(float));
    }

    if(lastFusedIntervalValid_)
        RecordDenseRowGpuInterval(lastFusedInterval_, /*isGroup=*/true);
    return true;
}

bool VulkanCompute::BeginLayerResidencyLease(uint32_t layerIndex) {
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(layerIndex == currentLayerLease_)
        return true;
    // End any previous lease to avoid double-pinning.
    if(currentLayerLease_ != ~0u)
        UnpinAllWeights();
    currentLayerLease_ = layerIndex;
    layerLeaseEpoch_   = weightUseClock_++;
    return true;
}

bool VulkanCompute::EndLayerResidencyLease(uint32_t layerIndex) {
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(currentLayerLease_ != layerIndex)
        return true;
    UnpinAllWeights();
    currentLayerLease_ = ~0u;
    return true;
}

// ============================================================================
// DEEP2_COLD_ROW_RACE_001 + DEEP2_HOT_LANE_CONTEXT_001 implementation
// ============================================================================

bool VulkanCompute::SubmitMaterialRangeAsync(
    DeviceBuf& target, VkDeviceSize targetOffset,
    const void* src, size_t bytes, uint64_t epoch,
    MaterialTicket& t)
{
    t = {};
    if (!initialized_ || !target || !src || !bytes ||
        targetOffset + bytes > target.size)
        return false;

    // Reuse the shared upload staging (mapped, geometric-growth). The copy
    // into staging happens on the calling thread; the device copy into the
    // promotion target is what gets fenced.
    DeviceBuf* staging = nullptr;
    void* mapped = nullptr;
    if (!ensureMappedStaging(true, bytes, staging, mapped))
        return false;
    std::memcpy(mapped, src, bytes);

    if (!beginCommand(t.cmd, t.query, true) ||
        !recordCopy(t.cmd, *staging, target, bytes, 0, targetOffset)) {
        return false;
    }
    if (t.query)
        vkCmdWriteTimestamp(
            t.cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, t.query, 1);
    if (vkEndCommandBuffer(t.cmd) != VK_SUCCESS)
        return false;

    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    if (vkCreateFence(device_, &fi, nullptr, &t.fence) != VK_SUCCESS)
        return false;

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &t.cmd;

    t.hostSubmitNs = nowNs();
    if (vkQueueSubmit(queue_, 1, &si, t.fence) != VK_SUCCESS) {
        vkDestroyFence(device_, t.fence, nullptr);
        t.fence = VK_NULL_HANDLE;
        return false;
    }
    ++queueSubmitCount_;

    t.epoch = epoch;
    t.bytes = bytes;
    t.generation = deviceGeneration_;
    t.submitted = true;
    return true;
}

bool VulkanCompute::PollMaterialUpload(MaterialTicket& t)
{
    if (!t.submitted || !t.fence)
        return false;
    return vkGetFenceStatus(device_, t.fence) == VK_SUCCESS;
}

bool VulkanCompute::PublishCompletedPrime(
    MaterialTicket& t, int type, uint64_t cacheKey,
    uint64_t hotWeightKey, GpuWorkInterval* interval)
{
    if (!t.submitted || !t.fence || !t.target)
        return false;

    // Final blocking wait (the poll variant calls this only after the
    // fence is already signaled, so this is instant).
    if (!PollMaterialUpload(t)) {
        VkResult wait =
            vkWaitForFences(device_, 1, &t.fence, VK_TRUE, UINT64_MAX);
        if (wait != VK_SUCCESS)
            return false;
    }
    const uint64_t done = nowNs();

    // TRAP-4: stale generation can never poison the current residency.
    if (t.generation != deviceGeneration_) {
        ++rcuStaleRejects_;
        if (t.fence) vkDestroyFence(device_, t.fence, nullptr);
        if (t.query) vkDestroyQueryPool(device_, t.query, nullptr);
        if (t.cmd) vkFreeCommandBuffers(device_, commandPool_, 1, &t.cmd);
        destroyBuffer(t.target);
        t = {};
        return false;
    }

    GpuWorkInterval wi{};
    finalizeInterval(t.query, t.hostSubmitNs, done, t.epoch, t.bytes,
                     GpuWorkKind::ModelTransfer, wi);
    recordInterval(wi);
    if (interval) *interval = wi;

    // Destroy transfer ticket objects; the target buffer ownership moves
    // to the heap-stable ResidentWeight.
    if (t.fence) vkDestroyFence(device_, t.fence, nullptr);
    if (t.query) vkDestroyQueryPool(device_, t.query, nullptr);
    if (t.cmd) vkFreeCommandBuffers(device_, commandPool_, 1, &t.cmd);
    t.fence = VK_NULL_HANDLE;
    t.cmd = VK_NULL_HANDLE;
    t.query = VK_NULL_HANDLE;

    if (hotWeightKey) {
        // RCU publication path: ownership goes to a heap-stable
        // ResidentWeight, published lock-free. weightCache_ is NOT the
        // publication authority.
        ResidentHotHandle* handle = GetHotHandle(hotWeightKey);
        if (!handle) {
            destroyBuffer(t.target);
            t = {};
            return false;
        }
        // LRU eviction first (pointer removal before retirement).
        if (!EvictResidentObjectsFor(t.bytes)) {
            FailHotView(handle);
            destroyBuffer(t.target);
            t = {};
            return false;
        }

        auto obj = std::make_unique<ResidentWeight>();
        obj->buffer = t.target;
        t.target = {};
        obj->key = hotWeightKey;
        obj->generation = deviceGeneration_;
        obj->bytes = t.bytes;
        obj->type = type;
        obj->handle = handle;

        PublishHotView(handle, obj.get());
        residentObjectBytes_ += obj->bytes;
        residentObjects_.push_back(std::move(obj));
        ++coldRacePromotionsCompleted_;
        t = {};
        return true;
    }

    // Legacy cache-commit path (CommitWeightPrime semantics).
    const uint64_t key = type == 0
        ? cacheKey
        : quantWeightKey(
              reinterpret_cast<const void*>(
                  static_cast<uintptr_t>(cacheKey)),
              t.bytes, type);
    if (!key) {
        destroyBuffer(t.target);
        t = {};
        return false;
    }
    auto old = weightCache_.find(key);
    if (old != weightCache_.end()) {
        weightCacheBytes_ -= old->second.bytes;
        destroyBuffer(old->second.buffer);
        weightCache_.erase(old);
    }
    WeightCacheEntry e{};
    e.buffer = t.target;
    e.bytes = t.bytes;
    e.type = type;
    t.target = {};
    weightCacheBytes_ += e.bytes;
    weightCache_.emplace(key, std::move(e));
    ++weightUploads_;
    t = {};
    return true;
}

bool VulkanCompute::EvictResidentObjectsFor(size_t incomingBytes)
{
    // Called under apiMu_. Removes hot pointers FIRST, then waits for
    // reader grace, then destroys. Pinned-cache-style budget: residents
    // share the same weightBudgetBytes_ envelope as weightCache_.
    if (weightBudgetBytes_ &&
        incomingBytes > weightBudgetBytes_)
        return false;

    auto totalResidentBytes = [&]() -> size_t {
        return residentObjectBytes_;
    };

    while (weightBudgetBytes_ &&
           weightCacheBytes_ + residentObjectBytes_ + incomingBytes >
               weightBudgetBytes_) {
        if (residentObjects_.empty())
            return false;
        // LRU: front of vector is oldest.
        ResidentWeight* victim = residentObjects_.front().get();
        ResidentHotHandle* handle = victim->handle;
        // Pointer removal first (atomic exchange); new readers see null.
        if (handle) {
            ResidentWeight* expected = victim;
            handle->view.compare_exchange_strong(
                expected, nullptr,
                std::memory_order_acq_rel, std::memory_order_relaxed);
        }
        residentObjectBytes_ -= victim->bytes;
        RetireResidentObject(std::move(residentObjects_.front()));
        residentObjects_.erase(residentObjects_.begin());
    }
    (void)totalResidentBytes;
    return true;
}

void VulkanCompute::RetireResidentObject(std::unique_ptr<ResidentWeight> obj)
{
    // Called under apiMu_ with the hot pointer already removed. Wait for
    // the RCU reader grace period: every in-flight AcquireHotView holder
    // must release before the buffer may be destroyed.
    while (residentReaderCount_.load(std::memory_order_acquire) != 0) {
        std::this_thread::yield();
    }
    destroyBuffer(obj->buffer);
}

void VulkanCompute::ReclaimAllResidents()
{
    // cleanup()-only: device idle, no readers possible; drop everything.
    for (auto& kv : hotHandles_)
        kv.second.view.store(nullptr, std::memory_order_release);
    hotHandles_.clear();
    for (auto& obj : residentObjects_) {
        destroyBuffer(obj->buffer);
        obj.reset();
    }
    residentObjects_.clear();
    residentObjectBytes_ = 0;
}

bool VulkanCompute::RunCpuQuantRowsFull(
    const GpuWeightView& weight,
    const float* input, float* output)
{
    // CPU-only Q4_K GEMV straight from immutable GGUF bytes via the
    // registry's AVX512-backed kernel table.
    if (!weight.valid() || !input || !output)
        return false;
    if (weight.type == 0) {
        // F32: naive dot products (rare path).
        const float* w = static_cast<const float*>(weight.data);
        for (uint32_t r = 0; r < weight.rows; ++r) {
            float acc = 0.0f;
            const float* row = w + static_cast<size_t>(r)*weight.cols;
            for (uint32_t c = 0; c < weight.cols; ++c)
                acc += row[c]*input[c];
            output[r] = acc;
        }
        return true;
    }
    GEMVKernelFn kernel =
        QuantKernelRegistry::Instance().GetGEMV(weight.type);
    if (!kernel) return false;
    kernel(static_cast<const uint8_t*>(weight.data),
           input, output,
           weight.rows, weight.cols);
    return true;
}

bool VulkanCompute::RunWeightColdRowRace(
    const GpuWeightView& weight,
    const float* input, float* output,
    uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!weight.valid() || !input || !output || !initialized_)
        return false;
    const size_t rowBytes =
        QuantPackedRowBytes(weight.type, weight.cols);
    if (!rowBytes || weight.bytes < rowBytes)
        return false;
    const uint64_t rowsPerSlice = weight.bytes / rowBytes;
    if (rowsPerSlice == 0 || rowsPerSlice > UINT32_MAX)
        return false;
    const uint32_t totalRows = static_cast<uint32_t>(rowsPerSlice);
    if (totalRows < 2)
        return RunCpuQuantRowsFull(weight, input, output);

    ++coldRaceCalls_;

    // ---- Promotion target: ONE complete whole-tensor allocation. ----
    DeviceBuf target{};
    const size_t padded = (weight.bytes + 3u) & ~size_t(3u);
    if (!createBuffer(padded,
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
            VK_BUFFER_USAGE_TRANSFER_DST_BIT |
            VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, target)) {
        ++coldRaceCpuOnlyCalls_;
        return RunCpuQuantRowsFull(weight, input, output);
    }

    GEMVKernelFn cpuKernel = weight.type == 0
        ? nullptr
        : QuantKernelRegistry::Instance().GetGEMV(weight.type);

    const uint32_t chunkRows = 64; // coarse chunks (autotune later)
    const size_t inBytes =
        static_cast<size_t>(weight.cols)*sizeof(float);

    // Scratch: input activation (device) + full-row output (device).
    if (!EnsureScratch(170, weight.cols) ||
        !EnsureScratch(171, totalRows)) {
        destroyBuffer(target);
        ++coldRaceCpuOnlyCalls_;
        return RunCpuQuantRowsFull(weight, input, output);
    }
    DeviceBuf& inBuf = Scratch(170);
    DeviceBuf& outBuf = Scratch(171);

    DeviceBuf* upStage = nullptr;
    DeviceBuf* downStage = nullptr;
    void* upMap = nullptr;
    void* downMap = nullptr;
    if (!ensureMappedStaging(true, inBytes, upStage, upMap) ||
        !ensureMappedStaging(
            false,
            static_cast<size_t>(totalRows)*sizeof(float),
            downStage, downMap)) {
        destroyBuffer(target);
        ++coldRaceCpuOnlyCalls_;
        return RunCpuQuantRowsFull(weight, input, output);
    }
    std::memcpy(upMap, input, inBytes);

    // Upload the input ONCE (fenced) before racing.
    {
        VkCommandBuffer cmd{};
        VkQueryPool query{};
        if (!beginCommand(cmd, query, true) ||
            !recordCopy(cmd, *upStage, inBuf, inBytes) ||
            !endSubmitWait(cmd, query, GpuWorkKind::ModelTransfer,
                           inBytes, epoch, nullptr)) {
            destroyBuffer(target);
            return RunCpuQuantRowsFull(weight, input, output);
        }
    }

    // Race frontiers. gpuLo: next unclaimed row from the head (GPU owns
    // [0, gpuLo)). cpuHi: next unclaimed row from the tail (CPU owns
    // [cpuHi, totalRows)). Frontiers meeting ends the current-token work
    // with no merge and no duplicate rows.
    std::atomic<uint32_t> gpuLo{0};
    std::atomic<uint32_t> cpuHi{totalRows};
    // TRAP-3: residency completeness is tracked SEPARATELY from output
    // ownership. uploadedRows == contiguous GPU-head rows present in the
    // target buffer; RCU publish requires uploadedRows == totalRows.
    uint32_t uploadedRows = 0;
    uint32_t gpuComputed = 0;
    uint32_t cpuComputed = 0;
    bool raceOk = true;

    MaterialTicket rangeTicket{};

    while (raceOk) {
        const uint32_t lo = gpuLo.load(std::memory_order_acquire);
        const uint32_t hi = cpuHi.load(std::memory_order_acquire);
        if (lo >= hi) break;

        // ---- GPU claims a head chunk (claim BEFORE compute/upload so
        // the CPU can never duplicate these rows). ----
        const uint32_t gpuCount = std::min(chunkRows, hi - lo);
        uint32_t expectedLo = lo;
        if (!gpuLo.compare_exchange_strong(
                expectedLo, lo + gpuCount, std::memory_order_acq_rel))
            continue;

        // Submit the range upload (PCIe DMA in flight).
        if (!SubmitMaterialRangeAsync(
                target,
                static_cast<VkDeviceSize>(lo)*rowBytes,
                static_cast<const uint8_t*>(weight.data) +
                    static_cast<size_t>(lo)*rowBytes,
                static_cast<size_t>(gpuCount)*rowBytes,
                epoch, rangeTicket)) {
            gpuLo.store(lo, std::memory_order_release); // unclaim
            raceOk = false;
            break;
        }
        ++coldRaceRangeSubmits_;
        coldRaceRangeBytes_ += static_cast<uint64_t>(gpuCount)*rowBytes;

        // ---- CPU tail chunk WHILE the range upload is in flight. ----
        while (cpuKernel && raceOk) {
            const uint32_t hi2 = cpuHi.load(std::memory_order_acquire);
            const uint32_t lo2 = gpuLo.load(std::memory_order_acquire);
            const uint32_t avail = hi2 > lo2 ? hi2 - lo2 : 0;
            if (avail == 0) break;
            const uint32_t cpuCount = std::min(chunkRows, avail);
            const uint32_t begin = hi2 - cpuCount;
            uint32_t expectedHi = hi2;
            if (!cpuHi.compare_exchange_strong(
                    expectedHi, begin, std::memory_order_acq_rel))
                continue;

            // The CPU kernel ACCUMULATES (y[r] += dot); zero the rows
            // first so exactly-once computation yields the true dot.
            for (uint32_t r = 0; r < cpuCount; ++r)
                output[begin + r] = 0.0f;
            const uint8_t* wRows =
                static_cast<const uint8_t*>(weight.data) +
                static_cast<size_t>(begin)*rowBytes;
            cpuKernel(wRows, input, output + begin,
                      cpuCount, weight.cols);
            cpuComputed += cpuCount;
            coldRaceCpuRows_ += cpuCount;

            if (begin <= lo + gpuCount) break; // frontiers met
        }

        // ---- Wait for the range upload, then GPU-compute the chunk.
        // The fence also guarantees the shared upload staging is idle
        // before the next range submit. ----
        (void)vkWaitForFences(
            device_, 1, &rangeTicket.fence, VK_TRUE, UINT64_MAX);
        uploadedRows = lo + gpuCount;
        vkDestroyFence(device_, rangeTicket.fence, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &rangeTicket.cmd);
        if (rangeTicket.query)
            vkDestroyQueryPool(device_, rangeTicket.query, nullptr);
        rangeTicket = {};

        VkCommandBuffer gcmd{};
        VkQueryPool gquery{};
        if (!beginCommand(gcmd, gquery, true) ||
            !recordQuantRowsResident(
                gcmd, weight, target, lo, gpuCount, inBuf, outBuf)) {
            raceOk = false;
            break;
        }
        // Shader wrote chunk rows [0..gpuCount) at the START of outBuf;
        // copy them to the download staging at their final row offset.
        if (!recordCopy(
                gcmd, outBuf, *downStage,
                static_cast<VkDeviceSize>(gpuCount)*sizeof(float),
                0,
                static_cast<VkDeviceSize>(lo)*sizeof(float)) ||
            !endSubmitWait(gcmd, gquery, GpuWorkKind::ModelCompute,
                           static_cast<uint64_t>(gpuCount)*rowBytes,
                           epoch, nullptr)) {
            raceOk = false;
            break;
        }
        gpuComputed += gpuCount;
        coldRaceGpuRows_ += gpuCount;
    }

    // ---- Merge: only the GPU-owned head rows come from the download
    // staging; the CPU already wrote its tail rows into final output.
    // (Copying the whole buffer would clobber CPU results.) ----
    const uint32_t gpuHeadRows = gpuComputed;
    if (gpuHeadRows > 0) {
        // endSubmitWait above guarantees the staging content is final.
        std::memcpy(
            output, downMap,
            static_cast<size_t>(gpuHeadRows)*sizeof(float));
    }

    const uint32_t computedTotal = gpuComputed + cpuComputed;
    if (computedTotal < totalRows) {
        // Frontiers met with a gap only on CAS failure paths; finish on
        // CPU so COLD_RACE_UNCOMPUTED_ROWS can never ship silently.
        const uint32_t missing = totalRows - computedTotal;
        coldRaceUncomputedRows_ += missing;
        // Zero + compute the full missing span via the CPU kernel.
        // (The claim frontiers may have diverged under CAS retries; the
        // simple correct recovery is a full CPU pass over rows missing
        // from both counters.)
        // Track claimed spans instead: recompute ownership exactly.
        // gpuComputed is contiguous [0,g); cpuComputed is contiguous
        // [g, totalRows) when the race ran cleanly, so missing rows
        // only occur on the aborted-race path handled below.
        if (!raceOk) {
            // Aborted race: rows outside the GPU head may be partially
            // computed by the CPU. A conservative full CPU pass over the
            // tail guarantees correctness (duplicates in ABORTED runs
            // are re-zeroed first).
            for (uint32_t r = gpuComputed; r < totalRows; ++r)
                output[r] = 0.0f;
            if (cpuKernel) {
                cpuKernel(
                    static_cast<const uint8_t*>(weight.data) +
                        static_cast<size_t>(gpuComputed)*rowBytes,
                    input, output + gpuComputed,
                    totalRows - gpuComputed, weight.cols);
            } else if (weight.type == 0) {
                const float* w = static_cast<const float*>(weight.data);
                for (uint32_t r = gpuComputed; r < totalRows; ++r) {
                    float acc = 0.0f;
                    const float* row =
                        w + static_cast<size_t>(r)*weight.cols;
                    for (uint32_t c = 0; c < weight.cols; ++c)
                        acc += row[c]*input[c];
                    output[r] = acc;
                }
            }
        }
    }

    // ---- TRAP-3: promotion completeness. Rows the CPU computed for the
    // current token still must reach the target before RCU publish. ----
    if (raceOk && uploadedRows < totalRows) {
        const uint32_t base = uploadedRows;
        const uint32_t remaining = totalRows - base;
        MaterialTicket tailTicket{};
        if (!SubmitMaterialRangeAsync(
                target,
                static_cast<VkDeviceSize>(base)*rowBytes,
                static_cast<const uint8_t*>(weight.data) +
                    static_cast<size_t>(base)*rowBytes,
                static_cast<size_t>(remaining)*rowBytes,
                epoch, tailTicket)) {
            if (tailTicket.submitted) {
                (void)vkWaitForFences(
                    device_, 1, &tailTicket.fence, VK_TRUE, UINT64_MAX);
                vkDestroyFence(device_, tailTicket.fence, nullptr);
                vkFreeCommandBuffers(
                    device_, commandPool_, 1, &tailTicket.cmd);
                if (tailTicket.query)
                    vkDestroyQueryPool(
                        device_, tailTicket.query, nullptr);
            }
            destroyBuffer(target);
            return true; // current-token output complete; no publish
        }
        (void)vkWaitForFences(
            device_, 1, &tailTicket.fence, VK_TRUE, UINT64_MAX);
        vkDestroyFence(device_, tailTicket.fence, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &tailTicket.cmd);
        if (tailTicket.query)
            vkDestroyQueryPool(device_, tailTicket.query, nullptr);
        ++coldRaceRangeSubmits_;
        coldRaceRangeBytes_ +=
            static_cast<uint64_t>(remaining)*rowBytes;
        uploadedRows = totalRows;
    }

    if (!raceOk) {
        destroyBuffer(target);
        return true; // output was recovered on CPU above
    }

    // ---- Full-weight residency proof → heap-stable ResidentWeight
    // object → lock-free RCU publish (weightCache_ is NOT the authority).
    // ----
    (void)PublishResidentTarget(target, weight.type, weight.key);
    return true;
}

bool VulkanCompute::RunWeightAutoHot(
    const GpuWeightView& weight,
    const float* input, float* output,
    uint64_t epoch)
{
    if (!weight.valid() || !input || !output)
        return false;

    // 1) RCU hot view: one acquire load; zero map/mutex/admission.
    ResidentHotHandle* handle = GetHotHandle(weight.key);
    if (!handle) return false;
    ResidentWeight* hot = AcquireHotView(handle);
    if (hot) {
        // Direct resident dispatch on the lock-free lane if prepared and
        // owned; otherwise the locked compatibility API.
        bool dispatched = false;
        if (hotLane_.initialized &&
            hotLane_.ownerThreadId == hotLaneCurrentThreadId()) {
            dispatched = RunWeightResidentHotDirect(
                hotLane_, weight, hot->buffer, input, output, epoch);
        }
        if (!dispatched) {
            std::lock_guard<std::recursive_mutex> lock(apiMu_);
            dispatched = RunWeightResidentHot(
                weight, &hot->buffer, input, output, epoch);
        }
        // Exactly one release per successful AcquireHotView.
        ReleaseHotView();
        return dispatched;
    }

    // 2) Cold miss → compute-on-miss race (promotion behind execution).
    return RunWeightColdRowRace(weight, input, output, epoch);
}

bool VulkanCompute::PublishResidentTarget(
    DeviceBuf& target, int type, uint64_t hotWeightKey)
{
    // FinalizeWeightPrime shape: transfer the completed promotion target
    // directly into a heap-stable ResidentWeight and RCU-publish it.
    // weightCache_ never becomes the publication authority. Assumes the
    // caller holds apiMu_ and the transfer fence has completed.
    if (!target || !hotWeightKey)
        return false;

    ResidentHotHandle* handle = GetHotHandle(hotWeightKey);
    if (!handle) {
        destroyBuffer(target);
        return false;
    }

    // LRU eviction first (pointer removal before retirement).
    if (!EvictResidentObjectsFor(target.size)) {
        FailHotView(handle);
        destroyBuffer(target);
        return false;
    }

    auto obj = std::make_unique<ResidentWeight>();
    obj->buffer = target;
    obj->key = hotWeightKey;
    obj->generation = deviceGeneration_;
    obj->bytes = target.size;
    obj->type = type;
    obj->handle = handle;

    PublishHotView(handle, obj.get());
    residentObjectBytes_ += obj->bytes;
    residentObjects_.push_back(std::move(obj));
    ++coldRacePromotionsCompleted_;
    return true;
}

uint32_t VulkanCompute::hotLaneCurrentThreadId() noexcept
{
#ifdef _WIN32
    return static_cast<uint32_t>(GetCurrentThreadId());
#else
    return 0;
#endif
}

bool VulkanCompute::PrepareHotLane(size_t maxInputFloats,
                                   size_t maxOutputFloats,
                                   size_t maxGroupOutputFloats)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (!initialized_) return false;

    auto mk = [&](DeviceBuf& b, size_t floats) -> bool {
        if (!floats || floats > SIZE_MAX/sizeof(float))
            return false;
        return createBuffer(
            floats*sizeof(float),
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
            VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
            VK_BUFFER_USAGE_TRANSFER_DST_BIT,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, b);
    };

    if (!mk(hotLane_.input, maxInputFloats) ||
        !mk(hotLane_.output, maxOutputFloats)) {
        ResetHotLane();
        return false;
    }
    for (int i = 0; i < 3; ++i) {
        if (!mk(hotLane_.groupOutput[i], maxGroupOutputFloats)) {
            ResetHotLane();
            return false;
        }
    }

    // Persistent mapped staging owned by the lane.
    const size_t upBytes = maxInputFloats*sizeof(float);
    const size_t downBytes = maxOutputFloats*sizeof(float);
    if (!createBuffer(upBytes,
            VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
            VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
            hotLane_.upStaging) ||
        vkMapMemory(device_, hotLane_.upStaging.memory, 0, upBytes, 0,
                    &hotLane_.upMapped) != VK_SUCCESS) {
        ResetHotLane();
        return false;
    }
    if (!createBuffer(downBytes,
            VK_BUFFER_USAGE_TRANSFER_DST_BIT,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
            VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
            hotLane_.downStaging) ||
        vkMapMemory(device_, hotLane_.downStaging.memory, 0, downBytes, 0,
                    &hotLane_.downMapped) != VK_SUCCESS) {
        ResetHotLane();
        return false;
    }
    hotLane_.upCapacity = upBytes;
    hotLane_.downCapacity = downBytes;

    // Lane-owned command buffer + fence + query pool.
    VkCommandBufferAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool = commandPool_;
    ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = 1;
    if (vkAllocateCommandBuffers(
            device_, &ai, &hotLane_.cmd) != VK_SUCCESS) {
        ResetHotLane();
        return false;
    }
    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    if (vkCreateFence(
            device_, &fi, nullptr, &hotLane_.fence) != VK_SUCCESS) {
        ResetHotLane();
        return false;
    }
    if (timestampValidBits_) {
        VkQueryPoolCreateInfo qi{};
        qi.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        qi.queryType = VK_QUERY_TYPE_TIMESTAMP;
        qi.queryCount = 2;
        if (vkCreateQueryPool(
                device_, &qi, nullptr, &hotLane_.query) != VK_SUCCESS) {
            ResetHotLane();
            return false;
        }
    }

    hotLane_.gpuOrdinal = requestedOrdinal_;
    hotLane_.generation = deviceGeneration_;
    hotLane_.ownerThreadId = hotLaneCurrentThreadId();
    hotLane_.initialized = true;
    return true;
}

void VulkanCompute::ResetHotLane()
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if (hotLane_.upMapped && hotLane_.upStaging.memory)
        vkUnmapMemory(device_, hotLane_.upStaging.memory);
    if (hotLane_.downMapped && hotLane_.downStaging.memory)
        vkUnmapMemory(device_, hotLane_.downStaging.memory);
    destroyBuffer(hotLane_.upStaging);
    destroyBuffer(hotLane_.downStaging);
    destroyBuffer(hotLane_.input);
    destroyBuffer(hotLane_.output);
    for (auto& b : hotLane_.groupOutput) destroyBuffer(b);
    if (hotLane_.fence) vkDestroyFence(device_, hotLane_.fence, nullptr);
    if (hotLane_.query)
        vkDestroyQueryPool(device_, hotLane_.query, nullptr);
    if (hotLane_.cmd && commandPool_)
        vkFreeCommandBuffers(
            device_, commandPool_, 1, &hotLane_.cmd);
    hotLane_ = {};
}

bool VulkanCompute::RunWeightResidentHotDirect(
    HotLaneContext& lane,
    const GpuWeightView& meta,
    DeviceBuf& residentWeight,
    const float* input, float* output,
    uint64_t epoch)
{
    // ZERO apiMu_ acquisition. Owner-thread confined.
    if (!lane.initialized) return false;
    if (lane.ownerThreadId != hotLaneCurrentThreadId()) {
        ++laneOwnerViolations_;
        return false;
    }
    if (!meta.valid() || !input || !output)
        return false;

    const size_t inBytes =
        static_cast<size_t>(meta.cols)*sizeof(float);
    const size_t outBytes =
        static_cast<size_t>(meta.rows)*sizeof(float);
    if (lane.input.size < inBytes || lane.output.size < outBytes)
        return false;
    if (lane.upCapacity < inBytes || lane.downCapacity < outBytes)
        return false;

    lane.epoch = epoch;
    lane.q4kLaneTag = kQ4kLaneDual;

    std::memcpy(lane.upMapped, input, inBytes);

    if (vkResetCommandBuffer(lane.cmd, 0) != VK_SUCCESS)
        return false;
    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(lane.cmd, &bi) != VK_SUCCESS)
        return false;

    if (lane.query) {
        vkCmdResetQueryPool(lane.cmd, lane.query, 0, 2);
        vkCmdWriteTimestamp(
            lane.cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
            lane.query, 0);
    }

    if (!recordCopy(
            lane.cmd, lane.upStaging, lane.input, inBytes) ||
        !DispatchWeightResidentLane(
            lane, meta, residentWeight,
            lane.input, lane.output)) {
        (void)vkEndCommandBuffer(lane.cmd);
        return false;
    }
    if (!recordCopy(
            lane.cmd, lane.output, lane.downStaging, outBytes)) {
        (void)vkEndCommandBuffer(lane.cmd);
        return false;
    }

    if (lane.query)
        vkCmdWriteTimestamp(
            lane.cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT,
            lane.query, 1);
    if (vkEndCommandBuffer(lane.cmd) != VK_SUCCESS)
        return false;
    if (vkResetFences(device_, 1, &lane.fence) != VK_SUCCESS)
        return false;

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &lane.cmd;
    if (vkQueueSubmit(queue_, 1, &si, lane.fence) != VK_SUCCESS)
        return false;
    ++lane.submits;
    if (vkWaitForFences(
            device_, 1, &lane.fence, VK_TRUE, UINT64_MAX) != VK_SUCCESS)
        return false;

    std::memcpy(output, lane.downMapped, outBytes);
    ++lane.residentDispatches;
    return true;
}

bool VulkanCompute::DispatchWeightResidentLane(
    HotLaneContext& lane,
    const GpuWeightView& meta,
    DeviceBuf& residentWeight,
    DeviceBuf& input, DeviceBuf& output)
{
    // Lane-local dispatch: no shared epoch/lanetag mutation, no mutex.
    // Uses the per-submit range descriptor (never cached; freed after the
    // fence wait in RunWeightResidentHotDirect's caller context).
    if (meta.rows == 0 || meta.cols == 0)
        return false;
    if (!residentWeight || residentWeight.size < meta.bytes)
        return false;
    if (static_cast<size_t>(meta.cols)*sizeof(float) > input.size ||
        static_cast<size_t>(meta.rows)*sizeof(float) > output.size)
        return false;

    if (meta.type == 0) {
        OpsPush p{};
        p.op = OP_GEMV_F32;
        p.n = meta.rows;
        p.p0 = meta.cols;
        const VkDescriptorSet set = getOpsDescriptor(
            residentWeight, input, output, output);
        if (set == VK_NULL_HANDLE) return false;
        vkCmdBindPipeline(
            lane.cmd, VK_PIPELINE_BIND_POINT_COMPUTE, opsPipeline_);
        vkCmdBindDescriptorSets(
            lane.cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
            opsPipelineLayout_, 0, 1, &set, 0, nullptr);
        vkCmdPushConstants(
            lane.cmd, opsPipelineLayout_,
            VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(p), &p);
        vkCmdDispatch(lane.cmd, (meta.rows+63u)/64u, 1, 1);
        recordComputeBarrier(lane.cmd);
        ++residentDirectDispatches_;
        ++lane.residentDispatches;
        return true;
    }

    if (meta.bytes > std::numeric_limits<uint32_t>::max())
        return false;
    const size_t rowBytes = QuantPackedRowBytes(meta.type, meta.cols);
    if (!rowBytes) return false;

    const VkDescriptorSet set = getQuantDescriptorRange(
        residentWeight, 0,
        static_cast<VkDeviceSize>(meta.bytes),
        input, output);
    if (set == VK_NULL_HANDLE) return false;
    lane.lastSet = set;
    vkCmdBindPipeline(
        lane.cmd, VK_PIPELINE_BIND_POINT_COMPUTE, qPipeline_);
    vkCmdBindDescriptorSets(
        lane.cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
        qPipelineLayout_, 0, 1, &set, 0, nullptr);
    QPush push{};
    push.type = static_cast<uint32_t>(meta.type);
    push.rows = meta.rows;
    push.cols = meta.cols;
    push.weightBytes = static_cast<uint32_t>(meta.bytes);
    vkCmdPushConstants(
        lane.cmd, qPipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT,
        0, sizeof(push), &push);
    vkCmdDispatch(lane.cmd, meta.rows, 1, 1);
    recordComputeBarrier(lane.cmd);
    ++residentDirectDispatches_;
    ++lane.residentDispatches;
    return true;
}

VulkanCompute::HotResidencyStats
VulkanCompute::HotResidencyStatsReport() const noexcept
{
    HotResidencyStats s{};
    s.residentDirectDispatches = residentDirectDispatches_;
    s.residentLookupViolations = residentLookupViolations_;
    s.rcuHotAcquires = rcuHotAcquires_;
    s.rcuPublishes = rcuPublishes_;
    s.rcuStaleRejects = rcuStaleRejects_;
    s.coldRaceCalls = coldRaceCalls_;
    s.coldRaceCpuOnlyCalls = coldRaceCpuOnlyCalls_;
    s.coldRaceGpuRows = coldRaceGpuRows_;
    s.coldRaceCpuRows = coldRaceCpuRows_;
    s.coldRaceDuplicateRows = coldRaceDuplicateRows_;
    s.coldRaceUncomputedRows = coldRaceUncomputedRows_;
    s.coldRaceRangeSubmits = coldRaceRangeSubmits_;
    s.coldRaceRangeBytes = coldRaceRangeBytes_;
    s.coldRacePromotionsCompleted = coldRacePromotionsCompleted_;
    s.laneOwnerViolations = laneOwnerViolations_;
    s.laneResidentDispatches = hotLane_.residentDispatches;
    s.laneSubmits = hotLane_.submits;
    return s;
}

void VulkanCompute::ResetSpecBatchArena() {
    for(auto& a:specArenas_) {
        destroyBuffer(a.hidden); destroyBuffer(a.norm);
        destroyBuffer(a.q);      destroyBuffer(a.k);
        destroyBuffer(a.v);      destroyBuffer(a.attn);
        destroyBuffer(a.proj);   destroyBuffer(a.gate);
        destroyBuffer(a.up);     destroyBuffer(a.act);
        destroyBuffer(a.down);   destroyBuffer(a.tmp);
        a={};
    }
    specArenaIndex_=0;
}

bool VulkanCompute::EnsureSpecBatchArena(
    uint32_t hidden,uint32_t kvWidth,uint32_t intermediate,uint32_t batch)
{
    if(!hidden||!kvWidth||!intermediate||!batch||batch>4) return false;
    if(specArenas_[0].valid()&&specArenas_[1].valid()&&
       specArenas_[0].hiddenWidth>=hidden&&
       specArenas_[0].kvWidth>=kvWidth&&
       specArenas_[0].intermediate>=intermediate&&
       specArenas_[0].batchCapacity>=batch)
        return true;

    ResetSpecBatchArena();
    auto mk=[&](DeviceBuf& b,uint64_t floats)->bool {
        if(!floats||floats>SIZE_MAX/sizeof(float)) return false;
        return createBuffer(
            (size_t)floats*sizeof(float),
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
            VK_BUFFER_USAGE_TRANSFER_SRC_BIT|
            VK_BUFFER_USAGE_TRANSFER_DST_BIT,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,b);
    };
    const uint64_t B=batch;
    for(auto& a:specArenas_) {
        if(!mk(a.hidden,B*hidden) ||
           !mk(a.norm,B*hidden)   ||
           !mk(a.q,B*hidden)      ||
           !mk(a.k,B*kvWidth)     ||
           !mk(a.v,B*kvWidth)     ||
           !mk(a.attn,B*hidden)   ||
           !mk(a.proj,B*hidden)   ||
           !mk(a.gate,B*intermediate) ||
           !mk(a.up,B*intermediate)   ||
           !mk(a.act,B*intermediate)  ||
           !mk(a.down,B*hidden)   ||
           !mk(a.tmp,B*std::max(hidden,intermediate))) {
            ResetSpecBatchArena();
            return false;
        }
        a.hiddenWidth=hidden;a.kvWidth=kvWidth;
        a.intermediate=intermediate;a.batchCapacity=batch;
    }
    return true;
}

bool VulkanCompute::UploadSpecHidden(
    const float* src,uint32_t hidden,uint32_t batch)
{
    if(!src||!EnsureSpecBatchArena(
            hidden,SpecArena().kvWidth?SpecArena().kvWidth:hidden,
            SpecArena().intermediate?SpecArena().intermediate:hidden*4,batch))
        return false;
    return uploadToBuffer(
        SpecArena().hidden,src,(size_t)hidden*batch*sizeof(float));
}

bool VulkanCompute::DownloadSpecHidden(
    float* dst,uint32_t hidden,uint32_t batch)
{
    if(!dst||!SpecArena().hidden||
       hidden>SpecArena().hiddenWidth||batch>SpecArena().batchCapacity)
        return false;
    return downloadFromBuffer(
        SpecArena().hidden,dst,(size_t)hidden*batch*sizeof(float));
}
bool VulkanCompute::EnsureResidentBatchInput(
    uint32_t cols,uint32_t batch)
{
    if(!cols||!batch||batch>4) return false;
    if(residentBatchInput_ &&
       residentBatchCols_>=cols &&
       residentBatchCapacity_>=batch)
        return true;

    destroyBuffer(residentBatchInput_);
    residentBatchCols_=0;
    residentBatchCapacity_=0;
    const uint64_t elems=(uint64_t)cols*batch;
    if(elems>SIZE_MAX/sizeof(float)) return false;
    if(!createBuffer(
            (size_t)elems*sizeof(float),
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
            VK_BUFFER_USAGE_TRANSFER_SRC_BIT|
            VK_BUFFER_USAGE_TRANSFER_DST_BIT,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
            residentBatchInput_))
        return false;
    residentBatchCols_=cols;
    residentBatchCapacity_=batch;
    return true;
}

bool VulkanCompute::UploadResidentBatchInput(
    const float* input,uint32_t cols,uint32_t batch,uint64_t epoch)
{
    if(!input||!EnsureResidentBatchInput(cols,batch)) return false;
    SetWorkEpoch(epoch);
    const size_t bytes=(size_t)cols*batch*sizeof(float);
    if(!uploadToBuffer(residentBatchInput_,input,bytes)) return false;
    ++residentBatchInputUploads_;
    return true;
}
bool VulkanCompute::EnsureResidentGroupOutputs(
    const GpuWeightView* weights,size_t weightCount,uint32_t batch)
{
    if(!weights||weightCount<2||weightCount>3||!batch||batch>4)
        return false;
    for(size_t i=0;i<weightCount;++i) {
        if(!weights[i].valid()) return false;
        const size_t need=(size_t)weights[i].rows*batch;
        if(residentGroupOutputs_[i] &&
           residentGroupOutputFloats_[i]>=need)
            continue;
        destroyBuffer(residentGroupOutputs_[i]);
        residentGroupOutputFloats_[i]=0;
        if(!createBuffer(
                need*sizeof(float),
                VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
                VK_BUFFER_USAGE_TRANSFER_SRC_BIT|
                VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
                residentGroupOutputs_[i]))
            return false;
        residentGroupOutputFloats_[i]=need;
        ++residentGroupOutputReallocs_;
    }
    return true;
}
bool VulkanCompute::EnsureResidentFullOutput(
    uint32_t rows,uint32_t batch)
{
    if(!rows||!batch||batch>4) return false;
    if(residentFullOutput_&&
       residentFullOutputRows_>=rows&&
       residentFullOutputBatch_>=batch)
        return true;
    destroyBuffer(residentFullOutput_);
    residentFullOutputRows_=residentFullOutputBatch_=0;
    const uint64_t elems=(uint64_t)rows*batch;
    if(elems>SIZE_MAX/sizeof(float)) return false;
    if(!createBuffer(
            (size_t)elems*sizeof(float),
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
            VK_BUFFER_USAGE_TRANSFER_SRC_BIT|
            VK_BUFFER_USAGE_TRANSFER_DST_BIT,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,
            residentFullOutput_))
        return false;
    residentFullOutputRows_=rows;
    residentFullOutputBatch_=batch;
    return true;
}

bool VulkanCompute::CopyDeviceSliceIntoFullOutput(
    DeviceBuf& src,uint32_t srcRows,uint32_t rowBegin,
    uint32_t fullRows,uint32_t batch)
{
    if(!src||!srcRows||!fullRows||!batch||batch>4||
       rowBegin>fullRows||srcRows>fullRows-rowBegin||
       !EnsureResidentFullOutput(fullRows,batch))
        return false;
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    const VkDeviceSize rowBytes=(VkDeviceSize)srcRows*sizeof(float);
    for(uint32_t b=0;b<batch;++b) {
        const VkDeviceSize so=(VkDeviceSize)b*rowBytes;
        const VkDeviceSize doff=
            ((VkDeviceSize)b*fullRows+rowBegin)*sizeof(float);
        if(!recordCopy(
                cmd,src,residentFullOutput_,rowBytes,so,doff))
            return false;
    }
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelTransfer,
            (uint64_t)rowBytes*batch,workEpoch_,nullptr))
        return false;
    residentFullOutputCopies_+=batch;
    return true;
}
void VulkanCompute::ResetDownloadRing() {
    for(auto& s:downloadRing_) {
        if(s.inFlight&&s.fence)
            (void)vkWaitForFences(device_,1,&s.fence,VK_TRUE,UINT64_MAX);
        if(s.mapped&&s.staging.memory)
            vkUnmapMemory(device_,s.staging.memory);
        if(s.fence) vkDestroyFence(device_,s.fence,nullptr);
        destroyBuffer(s.staging);
        s={};
        if(s.cmd&&transferCommandPool_)
            vkFreeCommandBuffers(
                device_,transferCommandPool_,1,&s.cmd);
    }
    downloadRingHead_=0;
}

bool VulkanCompute::EnsureDownloadRing(size_t bytes) {
    if(!bytes) return false;
    bool good=true;
    for(const auto& s:downloadRing_)
        good=good&&s.staging&&s.capacity>=bytes&&s.mapped&&s.fence;
    if(good) return true;
    ResetDownloadRing();
    for(auto& s:downloadRing_) {
        if(!createBuffer(
                bytes,VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|
                VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,s.staging))
            return false;
        if(vkMapMemory(
                device_,s.staging.memory,0,bytes,0,&s.mapped)!=VK_SUCCESS)
            return false;
        VkFenceCreateInfo fi{};
        fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        fi.flags=VK_FENCE_CREATE_SIGNALED_BIT;
        if(vkCreateFence(device_,&fi,nullptr,&s.fence)!=VK_SUCCESS)
            return false;
        VkCommandBufferAllocateInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool=transferCommandPool_
            ? transferCommandPool_:commandPool_;
        ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount=1;
        if(vkAllocateCommandBuffers(device_,&ai,&s.cmd)!=VK_SUCCESS)
            return false;
        s.capacity=bytes;
    }
    return true;
}

bool VulkanCompute::SubmitDownloadRing(
    DeviceBuf& src,size_t bytes,uint32_t& slotOut)
{
    if(!src||!bytes||bytes>src.size||!EnsureDownloadRing(bytes))
        return false;
    const uint32_t idx=downloadRingHead_++%3u;
    auto& s=downloadRing_[idx];
    if(vkWaitForFences(device_,1,&s.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    if(vkResetFences(device_,1,&s.fence)!=VK_SUCCESS) return false;

    if(vkResetCommandBuffer(s.cmd,0)!=VK_SUCCESS) return false;
    VkCommandBufferBeginInfo bi{};
    bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if(vkBeginCommandBuffer(s.cmd,&bi)!=VK_SUCCESS) return false;
    if(!recordCopy(s.cmd,src,s.staging,bytes)) return false;
    if(vkEndCommandBuffer(s.cmd)!=VK_SUCCESS) return false;
    VkSubmitInfo si{};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount=1;si.pCommandBuffers=&s.cmd;
    VkQueue tq=transferQueue_?transferQueue_:queue_;
    if(vkQueueSubmit(tq,1,&si,s.fence)!=VK_SUCCESS) return false;
    s.bytes=bytes;s.inFlight=true;
    slotOut=idx;
    ++downloadRingSubmits_;
    ++transferQueueSubmits_;
    ++queueSubmitCount_;
    return true;
}

bool VulkanCompute::WaitDownloadRing(
    uint32_t idx,void* dst,size_t bytes)
{
    if(idx>=3||!dst) return false;
    auto& s=downloadRing_[idx];
    if(!s.inFlight||bytes>s.bytes) return false;
    const auto a=std::chrono::steady_clock::now();
    if(vkWaitForFences(device_,1,&s.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    const auto b=std::chrono::steady_clock::now();
    downloadRingWaitNs_+=(uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(b-a).count();
    std::memcpy(dst,s.mapped,bytes);
    s.inFlight=false;
    return true;
}
bool VulkanCompute::CaptureVerifiedHidden(
    DeviceBuf& hiddenBatch,uint32_t tokenIndex,
    uint32_t hiddenWidth,uint32_t batch)
{
    if(!hiddenBatch||!hiddenWidth||!batch||tokenIndex>=batch) return false;
    const size_t bytes=(size_t)hiddenWidth*sizeof(float);
    if(!verifiedHidden_||verifiedHiddenWidth_<hiddenWidth) {
        destroyBuffer(verifiedHidden_);
        if(!createBuffer(
                bytes,VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
                VK_BUFFER_USAGE_TRANSFER_SRC_BIT|
                VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,verifiedHidden_))
            return false;
        verifiedHiddenWidth_=hiddenWidth;
    }
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    const VkDeviceSize src=(VkDeviceSize)tokenIndex*bytes;
    if(!recordCopy(cmd,hiddenBatch,verifiedHidden_,bytes,src,0))
        return false;
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelTransfer,
            bytes,workEpoch_,nullptr))
        return false;
    ++verifiedHiddenHandoffs_;
    return true;
}

bool VulkanCompute::RestoreVerifiedHiddenToArena(uint32_t hiddenWidth) {
    if(!verifiedHidden_||hiddenWidth>verifiedHiddenWidth_||
       !SpecArena().hidden)
        return false;
    const size_t bytes=(size_t)hiddenWidth*sizeof(float);
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    if(!recordCopy(cmd,verifiedHidden_,SpecArena().hidden,bytes,0,0))
        return false;
    return endSubmitWait(
        cmd,query,GpuWorkKind::ModelTransfer,
        bytes,workEpoch_,nullptr);
}

bool VulkanCompute::DownloadVerifiedHidden(
    float* dst,uint32_t hiddenWidth)
{
    if(!dst||!verifiedHidden_||hiddenWidth>verifiedHiddenWidth_) return false;
    return downloadFromBuffer(
        verifiedHidden_,dst,(size_t)hiddenWidth*sizeof(float));
}
void VulkanCompute::cleanup() {
    if (device_) vkDeviceWaitIdle(device_);
    ResetDownloadRing();
    ResetAsyncCmdRing();

    clearRecordedQ4K();
    clearRecordedGroups();

    ResetSpecBatchArena();

    ResetSpecKvMirror();
    ResetResidentBatchInput();
    ResetResidentGroupOutputs();
    ResetResidentFullOutput();

    // DEEP2_HOT_LANE_CONTEXT_001 / DEEP2_RCU_RESIDENCY_HANDLES_001:
    // device idle — drop the lock-free lane and every heap-stable
    // resident object without reader-grace spinning.
    ResetHotLane();
    ReclaimAllResidents();
    ++deviceGeneration_; // stale async promotions can never publish

    if(device_ && reusableFusedFence_)
        vkDestroyFence(device_,reusableFusedFence_,nullptr);
    if(device_ && reusableFusedQuery_)
        vkDestroyQueryPool(device_,reusableFusedQuery_,nullptr);
    if(device_ && reusableFusedCmd_ && commandPool_)
        vkFreeCommandBuffers(device_,commandPool_,1,&reusableFusedCmd_);
    reusableFusedFence_=VK_NULL_HANDLE;
    reusableFusedQuery_=VK_NULL_HANDLE;
    reusableFusedCmd_=VK_NULL_HANDLE;

    if (device_ && uploadMapped_ && uploadStaging_.memory)
        vkUnmapMemory(device_, uploadStaging_.memory);
    if (device_ && downloadMapped_ && downloadStaging_.memory)
        vkUnmapMemory(device_, downloadStaging_.memory);
    uploadMapped_ = downloadMapped_ = nullptr;
    destroyBuffer(uploadStaging_);
    destroyBuffer(downloadStaging_);
    uploadStagingBytes_ = downloadStagingBytes_ = 0;

    for (auto& e : prefetch_) destroyBuffer(e.buffer);

    prefetch_.clear();
    clearWeightCache();
    opsDescriptorCache_.clear();
    quantDescriptorCache_.clear();

    for (auto& b : scratch_) destroyBuffer(b);
    scratch_.clear();
    destroyBuffer(mlaKCache_);
    destroyBuffer(mlaVCache_);
    mlaCacheHeads_=mlaCacheKeyLen_=mlaCacheValueLen_=0;
    mlaCacheLayers_=mlaCacheCapacity_=mlaCacheMaxSeq_=0;

    auto kill=[&](DeviceBuf& b){destroyBuffer(b);};
    kill(arenaHidden_);kill(arenaAttnW_);kill(arenaFfnW_);kill(arenaNormed_);
    kill(arenaQ_);kill(arenaK_);kill(arenaV_);kill(arenaAttn_);
    kill(arenaResidual_);kill(arenaGate_);kill(arenaUp_);kill(arenaFFNAct_);
    kill(arenaDown_);kill(arenaKCache_);kill(arenaVCache_);

    if(device_ && opsPipeline_) vkDestroyPipeline(device_,opsPipeline_,nullptr);
    if(device_ && qPipeline_) vkDestroyPipeline(device_,qPipeline_,nullptr);
    if(device_ && qBatchPipeline_)
        vkDestroyPipeline(device_,qBatchPipeline_,nullptr);
    if(device_ && qBatch4RowPipeline_)
        vkDestroyPipeline(device_,qBatch4RowPipeline_,nullptr);
    if(device_ && qBatch8RowPipeline_)
        vkDestroyPipeline(device_,qBatch8RowPipeline_,nullptr);
    if(device_ && argmaxPipeline_)
        vkDestroyPipeline(device_,argmaxPipeline_,nullptr);
    if(device_ && specOpsPipeline_)
        vkDestroyPipeline(device_,specOpsPipeline_,nullptr);
    if(device_ && specAttnPipeline_)
        vkDestroyPipeline(device_,specAttnPipeline_,nullptr);
    if(device_ && specAcceptPipeline_)
        vkDestroyPipeline(device_,specAcceptPipeline_,nullptr);
    if(device_ && opsPipelineLayout_) vkDestroyPipelineLayout(device_,opsPipelineLayout_,nullptr);
    if(device_ && qPipelineLayout_) vkDestroyPipelineLayout(device_,qPipelineLayout_,nullptr);
    if(device_ && qBatchPipelineLayout_)
        vkDestroyPipelineLayout(device_,qBatchPipelineLayout_,nullptr);
    if(device_ && qBatch4RowPipelineLayout_)
        vkDestroyPipelineLayout(
            device_,qBatch4RowPipelineLayout_,nullptr);
    if(device_ && qBatch8RowPipelineLayout_)
        vkDestroyPipelineLayout(
            device_,qBatch8RowPipelineLayout_,nullptr);

    if(device_ && argmaxPipelineLayout_)
        vkDestroyPipelineLayout(device_,argmaxPipelineLayout_,nullptr);
    if(device_ && specOpsPipelineLayout_)
        vkDestroyPipelineLayout(device_,specOpsPipelineLayout_,nullptr);
    if(device_ && specAttnPipelineLayout_)
        vkDestroyPipelineLayout(device_,specAttnPipelineLayout_,nullptr);
    if(device_ && specAcceptPipelineLayout_)
        vkDestroyPipelineLayout(device_,specAcceptPipelineLayout_,nullptr);

    if(device_ && opsSetLayout_) vkDestroyDescriptorSetLayout(device_,opsSetLayout_,nullptr);
    if(device_ && qSetLayout_) vkDestroyDescriptorSetLayout(device_,qSetLayout_,nullptr);
    if(device_ && descriptorPool_) vkDestroyDescriptorPool(device_,descriptorPool_,nullptr);
    if(device_ && commandPool_) vkDestroyCommandPool(device_,commandPool_,nullptr);
    if(device_) vkDestroyDevice(device_,nullptr);
    if(instance_) vkDestroyInstance(instance_,nullptr);

    instance_=VK_NULL_HANDLE;physical_=VK_NULL_HANDLE;device_=VK_NULL_HANDLE;
    queue_=VK_NULL_HANDLE;commandPool_=VK_NULL_HANDLE;descriptorPool_=VK_NULL_HANDLE;
    opsSetLayout_=qSetLayout_=VK_NULL_HANDLE;
    opsPipelineLayout_=qPipelineLayout_=VK_NULL_HANDLE;
    opsPipeline_=qPipeline_=qBatchPipeline_=VK_NULL_HANDLE;
    qBatchPipelineLayout_=VK_NULL_HANDLE;

    fpGetCalibrated_=nullptr;
    calibratedAvailable_=false;
    initialized_=false;
    fused_=false;
    fusedCmd_=VK_NULL_HANDLE;
    fusedQuery_=VK_NULL_HANDLE;
    hidden_=intermediate_=heads_=kvHeads_=headDim_=maxSeq_=layers_=kvDim_=0;
    weightBudgetBytes_=weightCacheBytes_=0;
}

bool VulkanCompute::SpecBatchRmsNorm(
    DeviceBuf& input,DeviceBuf& weight,DeviceBuf& output,
    uint32_t width,uint32_t batch,float eps)
{
    if(!input||!weight||!output||!width||!batch||batch>4) return false;
    SpecOpsPush p{};p.op=0;p.width=width;p.batch=batch;p.eps=eps;
    return dispatchSpecOps(input,weight,output,SpecArena().tmp,p);
}

bool VulkanCompute::SpecBatchSwiGLU(
    DeviceBuf& gate,DeviceBuf& up,DeviceBuf& output,
    uint32_t width,uint32_t batch)
{
    if(!gate||!up||!output||!width||!batch||batch>4) return false;
    SpecOpsPush p{};p.op=1;p.width=width;p.batch=batch;
    return dispatchSpecOps(gate,up,output,SpecArena().tmp,p);
}

bool VulkanCompute::SpecBatchResidual(
    DeviceBuf& a,DeviceBuf& b,DeviceBuf& output,
    uint32_t width,uint32_t batch)
{
    if(!a||!b||!output||!width||!batch||batch>4) return false;
    SpecOpsPush p{};p.op=2;p.width=width;p.batch=batch;
    return dispatchSpecOps(a,b,output,SpecArena().tmp,p);
}
bool VulkanCompute::ReduceHostPartialInto(
    DeviceBuf& primary,const float* partial,uint32_t count)
{
    if(!primary||!partial||!count) return false;
    if(!EnsureScratch(120,count)) return false;
    auto& incoming=Scratch(120);
    if(!UploadVector(incoming,partial,count)) return false;
    OpsPush p{};
    p.op=3; // existing OP_RESIDUAL
    p.n=count;
    return dispatchOps(
        primary,incoming,SpecArena().tmp,SpecArena().tmp,
        p,(count+63u)/64u,GpuWorkKind::ModelCompute);
}

void VulkanCompute::ResetResidentBatchInput() {
    destroyBuffer(residentBatchInput_);
    residentBatchInput_={};
    residentBatchCols_=residentBatchCapacity_=0;
}

bool VulkanCompute::RunWeightGroupResidentInputQ4K(
    const GpuWeightView* weights,float* const* outputs,size_t weightCount,
    uint32_t cols,uint32_t batch,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weights||!outputs||weightCount<2||weightCount>3||
       !residentBatchInput_||cols>residentBatchCols_||
       batch>residentBatchCapacity_||!batch)
        return false;
    SetWorkEpoch(epoch);

    size_t totalBytes=0, offsets[3]{};
    for(size_t i=0;i<weightCount;++i) {
        if(!weights[i].valid()||weights[i].type!=12||
           weights[i].cols!=cols||!outputs[i])
            return false;
        if(!PinWeightView(weights[i])) return false;
        offsets[i]=totalBytes;
        totalBytes+=(size_t)batch*weights[i].rows*sizeof(float);
        if(!EnsureScratch(
                130u+(unsigned)i,
                (size_t)batch*weights[i].rows))
            return false;
    }
    DeviceBuf* ds=nullptr;void* dm=nullptr;
    if(!ensureMappedStaging(false,totalBytes,ds,dm)) return false;
    if(!BeginFusedLayer()) return false;
    auto abort=[&]{
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    };
    for(size_t i=0;i<weightCount;++i) {
        auto& out=Scratch(130u+(unsigned)i);
        if(!DispatchGemvQ4KBatch(
                weights[i].data,weights[i].bytes,
                residentBatchInput_,out,
                weights[i].rows,cols,batch))
            return abort();
        const size_t bytes=(size_t)batch*weights[i].rows*sizeof(float);
        if(!recordCopy(
                fusedCmd_,out,*ds,bytes,0,(VkDeviceSize)offsets[i]))
            return abort();
    }
    if(!EndFusedLayer()) return false;
    for(size_t i=0;i<weightCount;++i) {
        const size_t bytes=(size_t)batch*weights[i].rows*sizeof(float);
        std::memcpy(outputs[i],(const uint8_t*)dm+offsets[i],bytes);
    }
    return true;
}
bool VulkanCompute::SubmitDownloadAsync(
    DeviceBuf& src,size_t bytes,DownloadTicket& t)
{
    if(t.active||!src||!bytes||bytes>src.size) return false;
    if(!createBuffer(
            bytes,VK_BUFFER_USAGE_TRANSFER_DST_BIT,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT|
            VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,t.staging))
        return false;
    if(vkMapMemory(
            device_,t.staging.memory,0,bytes,0,&t.mapped)!=VK_SUCCESS) {
        destroyBuffer(t.staging);return false;
    }
    if(!beginCommand(t.cmd,t.query,true)||
       !recordCopy(t.cmd,src,t.staging,bytes)) {
        CancelDownloadTicket(t);return false;
    }
    if(vkEndCommandBuffer(t.cmd)!=VK_SUCCESS) {
        CancelDownloadTicket(t);return false;
    }
    VkFenceCreateInfo fi{};
    fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    if(vkCreateFence(device_,&fi,nullptr,&t.fence)!=VK_SUCCESS) {
        CancelDownloadTicket(t);return false;
    }
    VkSubmitInfo si{};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount=1;si.pCommandBuffers=&t.cmd;
    if(vkQueueSubmit(queue_,1,&si,t.fence)!=VK_SUCCESS) {
        CancelDownloadTicket(t);return false;
    }
    t.bytes=bytes;t.active=true;
    return true;
}

bool VulkanCompute::WaitDownloadAsync(
    DownloadTicket& t,void* dst,size_t bytes)
{
    if(!t.active||!dst||bytes>t.bytes) return false;
    if(vkWaitForFences(device_,1,&t.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    std::memcpy(dst,t.mapped,bytes);
    CancelDownloadTicket(t);
    return true;
}

void VulkanCompute::CancelDownloadTicket(DownloadTicket& t) {
    if(t.mapped&&t.staging.memory) vkUnmapMemory(device_,t.staging.memory);
    if(t.fence) vkDestroyFence(device_,t.fence,nullptr);
    if(t.cmd&&commandPool_) vkFreeCommandBuffers(device_,commandPool_,1,&t.cmd);
    if(t.query) vkDestroyQueryPool(device_,t.query,nullptr);
    destroyBuffer(t.staging);
    t={};
}

void VulkanCompute::ResetResidentGroupOutputs() {
    for(auto& b:residentGroupOutputs_) destroyBuffer(b);
    for(auto& n:residentGroupOutputFloats_) n=0;
}

bool VulkanCompute::RunWeightGroupResidentInputQ4KSingleReturn(
    const GpuWeightView* weights,float* contiguousOutput,
    size_t* outputOffsets,size_t weightCount,
    uint32_t cols,uint32_t batch,uint64_t epoch)
{
    std::lock_guard<std::recursive_mutex> lock(apiMu_);
    if(!weights||!contiguousOutput||!outputOffsets||
       weightCount<2||weightCount>3||!batch||batch>4||
       !residentBatchInput_)
        return false;
    if(!EnsureResidentGroupOutputs(weights,weightCount,batch))
        return false;

    size_t totalBytes=0;
    for(size_t i=0;i<weightCount;++i) {
        if(!PinWeightView(weights[i])||weights[i].cols!=cols)
            return false;
        outputOffsets[i]=totalBytes/sizeof(float);
        totalBytes+=(size_t)batch*weights[i].rows*sizeof(float);
    }

    DeviceBuf* ds=nullptr;void* dm=nullptr;
    if(!ensureMappedStaging(false,totalBytes,ds,dm)) return false;
    if(!BeginFusedLayer()) return false;
    auto abort=[&]{
        if(FusedRecording()) (void)EndFusedLayer();
        return false;
    };

    size_t byteOffset=0;
    for(size_t i=0;i<weightCount;++i) {
        auto& out=residentGroupOutputs_[i];
        if(!DispatchGemvQ4KBatch(
                weights[i].data,weights[i].bytes,
                residentBatchInput_,out,
                weights[i].rows,cols,batch))
            return abort();
        const size_t bytes=(size_t)batch*weights[i].rows*sizeof(float);
        if(!recordCopy(
                fusedCmd_,out,*ds,bytes,0,(VkDeviceSize)byteOffset))
            return abort();
        byteOffset+=bytes;
    }
    if(!EndFusedLayer()) return false;
    std::memcpy(contiguousOutput,dm,totalBytes);
    return true;
}
bool VulkanCompute::AppendSpecKvFromDevice(
    uint32_t layer,uint32_t start,uint32_t count,
    DeviceBuf& kTokenMajor,DeviceBuf& vTokenMajor)
{
    if(layer>=specKMirror_.size()||!count||
       !kTokenMajor||!vTokenMajor||
       start>specKvCapacity_||count>specKvCapacity_-start)
        return false;

    // Device source is token-major [token][kvHead][headDim].
    // Mirror is head-major [kvHead][capacity][headDim].
    // Use small device copies per head/token; no host materialization.
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    const VkDeviceSize hdBytes=(VkDeviceSize)specKvHeadDim_*sizeof(float);
    for(uint32_t t=0;t<count;++t) {
        for(uint32_t h=0;h<specKvHeads_;++h) {
            const VkDeviceSize src=
                ((VkDeviceSize)t*specKvHeads_+h)*hdBytes;
            const VkDeviceSize dst=
                ((VkDeviceSize)h*specKvCapacity_+start+t)*hdBytes;
            if(!recordCopy(
                    cmd,kTokenMajor,specKMirror_[layer],
                    hdBytes,src,dst)||
               !recordCopy(
                    cmd,vTokenMajor,specVMirror_[layer],
                    hdBytes,src,dst))
                return false;
        }
    }
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelTransfer,
            (uint64_t)count*specKvHeads_*hdBytes*2,
            workEpoch_,nullptr))
        return false;
    directSpecKvAppends_+=count;
    return true;
}

void VulkanCompute::ResetResidentFullOutput() {
    destroyBuffer(residentFullOutput_);
    residentFullOutput_={};
    residentFullOutputRows_=residentFullOutputBatch_=0;
}

bool VulkanCompute::ImportHostRowsIntoFullOutput(
    const float* rows,uint32_t rowCount,uint32_t rowBegin,
    uint32_t fullRows,uint32_t batch)
{
    if(!rows||!rowCount||!fullRows||!batch||batch>4||
       rowBegin>fullRows||rowCount>fullRows-rowBegin||
       !EnsureResidentFullOutput(fullRows,batch))
        return false;
    const size_t slab=(size_t)rowCount*batch;
    DeviceBuf* staging=nullptr;
    void* mapped=nullptr;
    if(!ensureMappedStaging(
            true,slab*sizeof(float),staging,mapped))
        return false;
    std::memcpy(mapped,rows,slab*sizeof(float));
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    const VkDeviceSize rowBytes=(VkDeviceSize)rowCount*sizeof(float);
    for(uint32_t b=0;b<batch;++b) {
        const VkDeviceSize so=(VkDeviceSize)b*rowBytes;
        const VkDeviceSize doff=
            ((VkDeviceSize)b*fullRows+rowBegin)*sizeof(float);
        if(!recordCopy(
                cmd,*staging,residentFullOutput_,rowBytes,so,doff))
            return false;
    }
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelTransfer,
            slab*sizeof(float),workEpoch_,nullptr))
        return false;
    secondaryImportBytes_+=slab*sizeof(float);
    return true;
}
bool VulkanCompute::DownloadResidentFullOutput(
    float* dst,uint32_t rows,uint32_t batch)
{
    if(!dst||!residentFullOutput_||
       rows>residentFullOutputRows_||
       batch>residentFullOutputBatch_)
        return false;
    const size_t bytes=(size_t)rows*batch*sizeof(float);
    if(!downloadFromBuffer(residentFullOutput_,dst,bytes))
        return false;
    fullOutputBoundaryBytes_+=bytes;
    return true;
}
bool VulkanCompute::BeginSpecLayerGraph(uint64_t epoch) {
    if(specLayerGraphActive_||fused_) return false;
    SetWorkEpoch(epoch);
    if(!BeginFusedLayer()) return false;
    specLayerGraphActive_=true;
    return true;
}

bool VulkanCompute::EndSpecLayerGraph() {
    if(!specLayerGraphActive_) return false;
    const bool ok=EndFusedLayer();
    specLayerGraphActive_=false;
    if(ok) ++specLayerGraphSubmits_;
    return ok;
}
void VulkanCompute::ResetAsyncCmdRing() {
    for(auto& s:asyncCmdRing_) {
        if(s.inFlight&&s.fence)
            (void)vkWaitForFences(device_,1,&s.fence,VK_TRUE,UINT64_MAX);
        if(s.fence) vkDestroyFence(device_,s.fence,nullptr);
        if(s.cmd&&commandPool_)
            vkFreeCommandBuffers(device_,commandPool_,1,&s.cmd);
        s={};
    }
    asyncCmdRingHead_=0;
}

bool VulkanCompute::EnsureAsyncCmdRing() {
    bool good=true;
    for(const auto& s:asyncCmdRing_)
        good=good&&s.cmd&&s.fence;
    if(good) return true;
    ResetAsyncCmdRing();
    for(auto& s:asyncCmdRing_) {
        VkCommandBufferAllocateInfo ai{};
        ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
        ai.commandPool=commandPool_;
        ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        ai.commandBufferCount=1;
        if(vkAllocateCommandBuffers(device_,&ai,&s.cmd)!=VK_SUCCESS)
            return false;
        VkFenceCreateInfo fi{};
        fi.sType=VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
        fi.flags=VK_FENCE_CREATE_SIGNALED_BIT;
        if(vkCreateFence(device_,&fi,nullptr,&s.fence)!=VK_SUCCESS)
            return false;
    }
    return true;
}
bool VulkanCompute::BeginQ4KResidentAsync(
    const GpuWeightView& weight,DeviceBuf& input,DeviceBuf& output,
    uint32_t batch,uint64_t epoch,Q4KAsyncTicket& t)
{
    if(t.active||!weight.valid()||weight.type!=12||!input||!output||
       !batch||batch>4||fused_)
        return false;
    DeviceBuf* wb=nullptr;
    if(!ensureWeightQuant(weight.type,weight.data,weight.bytes,wb))
        return false;

    Q4KBatchTile tile=SelectQ4KBatchTile(
        weight.data,weight.bytes,input,output,
        weight.rows,weight.cols,batch);
    VkPipeline pipe=tile==Q4KBatchTile::Eight
        ? qBatch8RowPipeline_:qBatch4RowPipeline_;
    VkPipelineLayout layout=tile==Q4KBatchTile::Eight
        ? qBatch8RowPipelineLayout_:qBatch4RowPipelineLayout_;
    if(!pipe||!layout) return false;

    if(!EnsureAsyncCmdRing()) return false;
    auto& slot=asyncCmdRing_[asyncCmdRingHead_++%4u];
    if(vkWaitForFences(device_,1,&slot.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    if(vkResetFences(device_,1,&slot.fence)!=VK_SUCCESS) return false;
    if(vkResetCommandBuffer(slot.cmd,0)!=VK_SUCCESS) return false;
    t.cmd=slot.cmd;
    t.fence=slot.fence;
    slot.inFlight=true;
    ++asyncCmdRingReuses_;

    VkCommandBufferBeginInfo bi{};
    bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if(vkBeginCommandBuffer(t.cmd,&bi)!=VK_SUCCESS) {
        CancelQ4KAsync(t); return false;
    }
    VkDescriptorSet set=getQuantDescriptor(*wb,input,output);
    if(set==VK_NULL_HANDLE) {
        CancelQ4KAsync(t); return false;
    }
    vkCmdBindPipeline(t.cmd,VK_PIPELINE_BIND_POINT_COMPUTE,pipe);
    vkCmdBindDescriptorSets(
        t.cmd,VK_PIPELINE_BIND_POINT_COMPUTE,layout,
        0,1,&set,0,nullptr);
    QBatchPush p{};
    p.type=12;p.rows=weight.rows;p.cols=weight.cols;
    p.weightBytes=(uint32_t)weight.bytes;p.batch=batch;
    vkCmdPushConstants(
        t.cmd,layout,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(p),&p);
    const uint32_t tileN=(uint32_t)tile;
    vkCmdDispatch(t.cmd,(weight.rows+tileN-1u)/tileN,1,1);
    recordComputeBarrier(t.cmd);
    if(vkEndCommandBuffer(t.cmd)!=VK_SUCCESS) {
        CancelQ4KAsync(t); return false;
    }
    VkSubmitInfo si{};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount=1;
    si.pCommandBuffers=&t.cmd;
    const auto now=std::chrono::steady_clock::now();
    if(vkQueueSubmit(queue_,1,&si,t.fence)!=VK_SUCCESS) {
        CancelQ4KAsync(t); return false;
    }
    t.submitNs=(uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(now.time_since_epoch()).count();
    t.weightBytes=weight.bytes;
    t.active=true;
    ++q4kAsyncSubmits_;
    ++queueSubmitCount_;
    SetWorkEpoch(epoch);
    return true;
}

bool VulkanCompute::WaitQ4KResidentAsync(
    Q4KAsyncTicket& t,uint64_t* gpuNs)
{
    if(!t.active) return false;
    const auto w0=std::chrono::steady_clock::now();
    if(vkWaitForFences(device_,1,&t.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    const auto w1=std::chrono::steady_clock::now();
    q4kAsyncWaitNs_+=(uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(w1-w0).count();
    t.completeNs=(uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(w1.time_since_epoch()).count();
    if(gpuNs) *gpuNs=t.completeNs>t.submitNs
        ? t.completeNs-t.submitNs:0;
    CancelQ4KAsync(t);
    return true;
}

void VulkanCompute::CancelQ4KAsync(Q4KAsyncTicket& t) {
    // Ring owns cmd/fence. Locate and release logical in-flight state only.
    for(auto& s:asyncCmdRing_) {
        if(s.cmd==t.cmd&&s.fence==t.fence) {
            s.inFlight=false;
            break;
        }
    }
    if(t.query) vkDestroyQueryPool(device_,t.query,nullptr);
    t={};
}
bool VulkanCompute::SubmitQ4KThenDownloadTimeline(
    const GpuWeightView& weight,DeviceBuf& input,DeviceBuf& output,
    uint32_t batch,uint64_t epoch,TimelineTicket& ticket)
{
    ticket={};
    if(!TimelineSemaphoreEnabled()||!weight.valid()||weight.type!=12||
       !input||!output||!batch||batch>4)
        return false;

    DeviceBuf* wb=nullptr;
    if(!ensureWeightQuant(weight.type,weight.data,weight.bytes,wb))
        return false;
    const Q4KBatchTile tile=SelectQ4KBatchTile(
        weight.data,weight.bytes,input,output,
        weight.rows,weight.cols,batch);
    VkPipeline pipe=tile==Q4KBatchTile::Eight
        ? qBatch8RowPipeline_:qBatch4RowPipeline_;
    VkPipelineLayout layout=tile==Q4KBatchTile::Eight
        ? qBatch8RowPipelineLayout_:qBatch4RowPipelineLayout_;
    if(!pipe||!layout) return false;

    // Compute command.
    VkCommandBuffer ccmd{};
    VkCommandBufferAllocateInfo cai{};
    cai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    cai.commandPool=commandPool_;
    cai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount=1;
    if(vkAllocateCommandBuffers(device_,&cai,&ccmd)!=VK_SUCCESS) return false;
    VkCommandBufferBeginInfo bi{};
    bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if(vkBeginCommandBuffer(ccmd,&bi)!=VK_SUCCESS) return false;
    VkDescriptorSet set=getQuantDescriptor(*wb,input,output);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(ccmd,VK_PIPELINE_BIND_POINT_COMPUTE,pipe);
    vkCmdBindDescriptorSets(
        ccmd,VK_PIPELINE_BIND_POINT_COMPUTE,layout,0,1,&set,0,nullptr);
    QBatchPush p{};
    p.type=12;p.rows=weight.rows;p.cols=weight.cols;
    p.weightBytes=(uint32_t)weight.bytes;p.batch=batch;
    vkCmdPushConstants(
        ccmd,layout,VK_SHADER_STAGE_COMPUTE_BIT,0,sizeof(p),&p);
    const uint32_t tileN=(uint32_t)tile;
    vkCmdDispatch(ccmd,(weight.rows+tileN-1u)/tileN,1,1);
    recordComputeBarrier(ccmd);
    if(vkEndCommandBuffer(ccmd)!=VK_SUCCESS) return false;

    const size_t bytes=(size_t)batch*weight.rows*sizeof(float);
    if(!EnsureDownloadRing(bytes)) return false;
    const uint32_t slot=downloadRingHead_++%3u;
    auto& rs=downloadRing_[slot];
    if(vkWaitForFences(device_,1,&rs.fence,VK_TRUE,UINT64_MAX)!=VK_SUCCESS)
        return false;
    if(vkResetFences(device_,1,&rs.fence)!=VK_SUCCESS) return false;
    if(vkResetCommandBuffer(rs.cmd,0)!=VK_SUCCESS) return false;
    if(vkBeginCommandBuffer(rs.cmd,&bi)!=VK_SUCCESS) return false;
    if(!recordCopy(rs.cmd,output,rs.staging,bytes)) return false;
    if(vkEndCommandBuffer(rs.cmd)!=VK_SUCCESS) return false;

    const uint64_t computeValue=NextTimelineValue();
    const uint64_t transferValue=NextTimelineValue();
    VkTimelineSemaphoreSubmitInfo ctsi{};
    ctsi.sType=VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
    ctsi.signalSemaphoreValueCount=1;
    ctsi.pSignalSemaphoreValues=&computeValue;
    VkSubmitInfo csi{};
    csi.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    csi.pNext=&ctsi;
    csi.commandBufferCount=1;csi.pCommandBuffers=&ccmd;
    csi.signalSemaphoreCount=1;csi.pSignalSemaphores=&timelineSemaphore_;
    if(vkQueueSubmit(queue_,1,&csi,VK_NULL_HANDLE)!=VK_SUCCESS) return false;
    ++timelineSignals_;++queueSubmitCount_;

    VkPipelineStageFlags waitStage=VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkTimelineSemaphoreSubmitInfo ttsi{};
    ttsi.sType=VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
    ttsi.waitSemaphoreValueCount=1;
    ttsi.pWaitSemaphoreValues=&computeValue;
    ttsi.signalSemaphoreValueCount=1;
    ttsi.pSignalSemaphoreValues=&transferValue;
    VkSubmitInfo tsi{};
    tsi.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    tsi.pNext=&ttsi;
    tsi.waitSemaphoreCount=1;tsi.pWaitSemaphores=&timelineSemaphore_;
    tsi.pWaitDstStageMask=&waitStage;
    tsi.commandBufferCount=1;tsi.pCommandBuffers=&rs.cmd;
    tsi.signalSemaphoreCount=1;tsi.pSignalSemaphores=&timelineSemaphore_;
    VkQueue tq=transferQueue_?transferQueue_:queue_;
    if(vkQueueSubmit(tq,1,&tsi,rs.fence)!=VK_SUCCESS) return false;
    ++timelineSignals_;++transferQueueSubmits_;++queueSubmitCount_;

    rs.bytes=bytes;rs.inFlight=true;
    ticket.computeDone=computeValue;
    ticket.transferDone=transferValue;
    ticket.ringSlot=slot;
    ticket.bytes=bytes;
    ticket.active=true;
    ++timelineComputeTransferChains_;
    SetWorkEpoch(epoch);
    return true;
}

bool VulkanCompute::WaitTimelineDownload(
    TimelineTicket& t,void* dst,size_t bytes)
{
    if(!t.active||!dst||bytes>t.bytes||t.ringSlot>=3) return false;
    if(!WaitTimelineValue(t.transferDone)) return false;
    auto& rs=downloadRing_[t.ringSlot];
    std::memcpy(dst,rs.mapped,bytes);
    rs.inFlight=false;
    t={};
    return true;
}

bool VulkanCompute::RunSpecAcceptPrefix(
    const uint32_t* target,const uint32_t* proposal,
    uint32_t count,SpecAcceptResult& result)
{
    result={};
    if(!target||!proposal||!count||count>4||!specAcceptPipeline_)
        return false;
    if(!EnsureScratch(160,count)||!EnsureScratch(161,count)||
       !EnsureScratch(162,3)||!EnsureScratch(163,1))
        return false;
    auto& t=Scratch(160);auto& p=Scratch(161);
    auto& o=Scratch(162);auto& d=Scratch(163);
    if(!uploadToBuffer(t,target,count*sizeof(uint32_t))||
       !uploadToBuffer(p,proposal,count*sizeof(uint32_t)))
        return false;
    specAcceptInputUploadBytes_ +=
        (uint64_t)count*sizeof(uint32_t)*2ull;
    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getOpsDescriptor(t,p,o,d);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAcceptPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAcceptPipelineLayout_,
        0,1,&set,0,nullptr);
    vkCmdPushConstants(
        cmd,specAcceptPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(count),&count);
    vkCmdDispatch(cmd,1,1,1);
    recordComputeBarrier(cmd);
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelCompute,0,workEpoch_,nullptr))
        return false;
    uint32_t h[3]{};
    if(!downloadFromBuffer(o,h,3*sizeof(uint32_t))) return false;
    result.accepted=h[0];
    result.replacement=h[1];
    result.bonus=h[2];
    ++specAcceptGpuOps_;
    return true;
}

bool VulkanCompute::RunSpecAcceptPrefixResident(
    DeviceBuf& targetIds,DeviceBuf& proposalIds,
    uint32_t count,SpecAcceptResult& result)
{
    result={};
    if(!targetIds||!proposalIds||!count||count>4||!specAcceptPipeline_)
        return false;
    if(!EnsureScratch(162,3)||!EnsureScratch(163,1))
        return false;
    auto& o=Scratch(162);
    auto& d=Scratch(163);

    VkCommandBuffer cmd{};
    VkQueryPool query{};
    if(!beginCommand(cmd,query,true)) return false;
    VkDescriptorSet set=getOpsDescriptor(targetIds,proposalIds,o,d);
    if(set==VK_NULL_HANDLE) return false;
    vkCmdBindPipeline(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAcceptPipeline_);
    vkCmdBindDescriptorSets(
        cmd,VK_PIPELINE_BIND_POINT_COMPUTE,specAcceptPipelineLayout_,
        0,1,&set,0,nullptr);
    vkCmdPushConstants(
        cmd,specAcceptPipelineLayout_,VK_SHADER_STAGE_COMPUTE_BIT,
        0,sizeof(count),&count);
    vkCmdDispatch(cmd,1,1,1);
    recordComputeBarrier(cmd);
    if(!endSubmitWait(
            cmd,query,GpuWorkKind::ModelCompute,0,workEpoch_,nullptr))
        return false;

    uint32_t h[3]{};
    if(!downloadFromBuffer(o,h,3*sizeof(uint32_t))) return false;
    result.accepted=h[0];
    result.replacement=h[1];
    result.bonus=h[2];
    ++specAcceptGpuOps_;
    ++specAcceptResidentOps_;
    return true;
}

void VulkanCompute::ResetVerifiedHidden() {
    destroyBuffer(verifiedHidden_);
    verifiedHidden_={};
    verifiedHiddenWidth_=0;
}

bool VulkanCompute::WaitTimelineValue(uint64_t value, uint64_t timeoutNs) {
    if(!TimelineSemaphoreEnabled()||!value) return false;
    VkSemaphoreWaitInfo wi{};
    wi.sType = VK_STRUCTURE_TYPE_SEMAPHORE_WAIT_INFO;
    wi.flags = 0;
    wi.semaphoreCount = 1;
    wi.pSemaphores = &timelineSemaphore_;
    wi.pValues = &value;
    const VkResult r = vkWaitSemaphores(device_, &wi, timeoutNs);
    if(r == VK_SUCCESS) {
        ++timelineWaits_;
        return true;
    }
    return false;
}

bool VulkanCompute::SubmitTimelineCommand(
    VkCommandBuffer cmd,VkQueue q,
    uint64_t waitValue,uint64_t signalValue,
    VkPipelineStageFlags waitStage)
{
    if(!TimelineSemaphoreEnabled()||cmd==VK_NULL_HANDLE||q==VK_NULL_HANDLE||
       !signalValue)
        return false;
    VkTimelineSemaphoreSubmitInfo ti{};
    ti.sType=VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
    if(waitValue) {
        ti.waitSemaphoreValueCount=1;
        ti.pWaitSemaphoreValues=&waitValue;
    }
    ti.signalSemaphoreValueCount=1;
    ti.pSignalSemaphoreValues=&signalValue;
    VkSubmitInfo si{};
    si.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.pNext=&ti;
    if(waitValue) {
        si.waitSemaphoreCount=1;
        si.pWaitSemaphores=&timelineSemaphore_;
        si.pWaitDstStageMask=&waitStage;
    }
    si.commandBufferCount=1;
    si.pCommandBuffers=&cmd;
    si.signalSemaphoreCount=1;
    si.pSignalSemaphores=&timelineSemaphore_;
    if(vkQueueSubmit(q,1,&si,VK_NULL_HANDLE)!=VK_SUCCESS)
        return false;
    ++timelineSignals_;
    ++queueSubmitCount_;
    ++layerTimelineChains_;
    return true;
}
static bool deep2BeginOneShot(
    VkDevice device,VkCommandPool pool,VkCommandBuffer& cmd)
{
    VkCommandBufferAllocateInfo ai{};
    ai.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool=pool;
    ai.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount=1;
    if(vkAllocateCommandBuffers(device,&ai,&cmd)!=VK_SUCCESS) return false;
    VkCommandBufferBeginInfo bi{};
    bi.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    return vkBeginCommandBuffer(cmd,&bi)==VK_SUCCESS;
}

bool VulkanCompute::CaptureVerifiedHiddenTimeline(
    DeviceBuf& hiddenBatch,uint32_t tokenIndex,
    uint32_t hiddenWidth,uint32_t batch,
    uint64_t waitValue,HiddenCopyTicket& ticket)
{
    ticket={};
    if(!TimelineSemaphoreEnabled()||!hiddenBatch||!hiddenWidth||
       !batch||tokenIndex>=batch)
        return false;
    const size_t bytes=(size_t)hiddenWidth*sizeof(float);
    if(!verifiedHidden_||verifiedHiddenWidth_<hiddenWidth) {
        destroyBuffer(verifiedHidden_);
        if(!createBuffer(
                bytes,VK_BUFFER_USAGE_STORAGE_BUFFER_BIT|
                VK_BUFFER_USAGE_TRANSFER_SRC_BIT|
                VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT,verifiedHidden_))
            return false;
        verifiedHiddenWidth_=hiddenWidth;
    }
    if(!deep2BeginOneShot(device_,commandPool_,ticket.cmd)) return false;
    const VkDeviceSize src=(VkDeviceSize)tokenIndex*bytes;
    if(!recordCopy(ticket.cmd,hiddenBatch,verifiedHidden_,bytes,src,0))
        return false;
    if(vkEndCommandBuffer(ticket.cmd)!=VK_SUCCESS) return false;
    ticket.signalValue=NextTimelineValue();
    if(!SubmitTimelineCommand(
            ticket.cmd,queue_,waitValue,ticket.signalValue,
            VK_PIPELINE_STAGE_TRANSFER_BIT))
        return false;
    ticket.active=true;
    ++hiddenTimelineSubmits_;
    ++verifiedHiddenHandoffs_;
    return true;
}

bool VulkanCompute::RestoreVerifiedHiddenTimeline(
    uint32_t hiddenWidth,uint64_t waitValue,
    HiddenCopyTicket& ticket)
{
    ticket={};
    if(!TimelineSemaphoreEnabled()||!verifiedHidden_||
       hiddenWidth>verifiedHiddenWidth_||!SpecArena().hidden)
        return false;
    const size_t bytes=(size_t)hiddenWidth*sizeof(float);
    if(!deep2BeginOneShot(device_,commandPool_,ticket.cmd)) return false;
    if(!recordCopy(
            ticket.cmd,verifiedHidden_,SpecArena().hidden,bytes,0,0))
        return false;
    if(vkEndCommandBuffer(ticket.cmd)!=VK_SUCCESS) return false;
    ticket.signalValue=NextTimelineValue();
    if(!SubmitTimelineCommand(
            ticket.cmd,queue_,waitValue,ticket.signalValue,
            VK_PIPELINE_STAGE_TRANSFER_BIT))
        return false;
    ticket.active=true;
    ++hiddenTimelineSubmits_;
    return true;
}

bool VulkanCompute::WaitHiddenCopy(HiddenCopyTicket& ticket) {
    if(!ticket.active) return true;
    const bool ok=WaitTimelineValue(ticket.signalValue);
    if(ticket.cmd&&commandPool_)
        vkFreeCommandBuffers(device_,commandPool_,1,&ticket.cmd);
    ticket={};
    return ok;
}

} // namespace Deep2
