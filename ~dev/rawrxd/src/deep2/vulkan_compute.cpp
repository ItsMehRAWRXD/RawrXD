// ============================================================================
// vulkan_compute.cpp — Batch 9 real Vulkan device/runtime implementation
// ============================================================================
#include "vulkan_compute.h"

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
        d.ordinal = i;
        d.vendorId = p.vendorID;
        d.deviceId = p.deviceID;
        d.apiVersion = p.apiVersion;
        d.deviceLocalBytes = local;
        d.discrete = p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU;
        d.compute = compute;
        d.name = p.deviceName;
        out.push_back(std::move(d));
    }

    vkDestroyInstance(inst, nullptr);
    return out;
}

size_t VulkanCompute::ForwardArenaReserveBytes(
    uint32_t hidden, uint32_t intermediate,
    uint32_t, uint32_t kvHeads, uint32_t headDim,
    uint32_t maxSeq, uint32_t layers)
{
    const uint64_t H = hidden;
    const uint64_t I = intermediate;
    const uint64_t kv = static_cast<uint64_t>(kvHeads) * headDim;
    const uint64_t seqCap = std::min<uint64_t>(maxSeq ? maxSeq : 1, 4096);
    uint64_t floats =
        H * 8ull + I * 3ull + kv * 2ull +
        static_cast<uint64_t>(layers) * seqCap * kv * 2ull;
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
        n == 0 || requestedOrdinal_ >= n) return false;

    std::vector<VkPhysicalDevice> devs(n);
    if (vkEnumeratePhysicalDevices(instance_, &n, devs.data()) != VK_SUCCESS)
        return false;
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
    for (const auto& e : ext)
        if (std::strcmp(e.extensionName,
                        VK_EXT_CALIBRATED_TIMESTAMPS_EXTENSION_NAME) == 0)
            haveCalibrated = true;

    float prio = 1.0f;
    VkDeviceQueueCreateInfo qi{};
    qi.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    qi.queueFamilyIndex = queueFamily_;
    qi.queueCount = 1;
    qi.pQueuePriorities = &prio;

    std::vector<const char*> enabled;
    if (haveCalibrated)
        enabled.push_back(VK_EXT_CALIBRATED_TIMESTAMPS_EXTENSION_NAME);

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
    ps.descriptorCount = 32768;

    VkDescriptorPoolCreateInfo pi{};
    pi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pi.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    pi.maxSets = 8192;
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
    if (!ops.empty())
        (void)createPipelineFromFile(
            ops, opsSetLayout_, sizeof(OpsPush), opsPipelineLayout_, opsPipeline_);
    if (!q.empty())
        (void)createPipelineFromFile(
            q, qSetLayout_, sizeof(QPush), qPipelineLayout_, qPipeline_);
    return opsPipeline_ != VK_NULL_HANDLE;
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

    std::fprintf(stdout,
        "BATCH9_VK_DEVICE ordinal=%u name=%s vendor=0x%04x vram=%llu "
        "compute_pipeline=%u qgemv_pipeline=%u calibrated=%u\n",
        info_.ordinal, info_.name.c_str(), info_.vendorId,
        static_cast<unsigned long long>(info_.deviceLocalBytes),
        opsPipeline_ ? 1u : 0u, qPipeline_ ? 1u : 0u,
        calibratedAvailable_ ? 1u : 0u);
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

bool VulkanCompute::createBuffer(
    VkDeviceSize bytes, VkBufferUsageFlags usage,
    VkMemoryPropertyFlags required, DeviceBuf& out)
{
    destroyBuffer(out);
    if (!device_ || bytes == 0) return false;

    VkBufferCreateInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bi.size = bytes;
    bi.usage = usage;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device_, &bi, nullptr, &out.buffer) != VK_SUCCESS)
        return false;

    VkMemoryRequirements mr{};
    vkGetBufferMemoryRequirements(device_, out.buffer, &mr);
    uint32_t mt = findMemoryType(mr.memoryTypeBits, required);
    if (mt == UINT32_MAX) {
        vkDestroyBuffer(device_, out.buffer, nullptr);
        out = {};
        return false;
    }

    VkMemoryAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    ai.allocationSize = mr.size;
    ai.memoryTypeIndex = mt;
    if (vkAllocateMemory(device_, &ai, nullptr, &out.memory) != VK_SUCCESS) {
        vkDestroyBuffer(device_, out.buffer, nullptr);
        out = {};
        return false;
    }
    if (vkBindBufferMemory(device_, out.buffer, out.memory, 0) != VK_SUCCESS) {
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

bool VulkanCompute::uploadToBuffer(DeviceBuf& dst, const void* src, size_t bytes) {
    if (!dst || !src || !bytes || bytes > dst.size) return false;

    DeviceBuf staging{};
    if (!createBuffer(bytes, VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, staging))
        return false;

    void* mapped = nullptr;
    bool ok = vkMapMemory(device_, staging.memory, 0, bytes, 0, &mapped) == VK_SUCCESS;
    if (ok) {
        std::memcpy(mapped, src, bytes);
        vkUnmapMemory(device_, staging.memory);

        VkCommandBuffer cmd{};
        VkQueryPool query{};
        ok = beginCommand(cmd, query, true) &&
             recordCopy(cmd, staging, dst, bytes) &&
             endSubmitWait(cmd, query, GpuWorkKind::ModelTransfer,
                           bytes, workEpoch_, nullptr);
    }
    destroyBuffer(staging);
    return ok;
}

bool VulkanCompute::downloadFromBuffer(
    const DeviceBuf& src, void* dst, size_t bytes)
{
    if (!src || !dst || !bytes || bytes > src.size) return false;

    DeviceBuf staging{};
    if (!createBuffer(bytes, VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                      VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                      VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, staging))
        return false;

    VkCommandBuffer cmd{};
    VkQueryPool query{};
    bool ok = beginCommand(cmd, query, true) &&
              recordCopy(cmd, src, staging, bytes) &&
              endSubmitWait(cmd, query, GpuWorkKind::ModelTransfer,
                            bytes, workEpoch_, nullptr);
    if (ok) {
        void* mapped = nullptr;
        ok = vkMapMemory(device_, staging.memory, 0, bytes, 0, &mapped) == VK_SUCCESS;
        if (ok) {
            std::memcpy(dst, mapped, bytes);
            vkUnmapMemory(device_, staging.memory);
        }
    }
    destroyBuffer(staging);
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
        vkResetDescriptorPool(device_, descriptorPool_, 0);
        if (!beginCommand(cmd, query, true)) return false;
    }

    VkDescriptorSetAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ai.descriptorPool = descriptorPool_;
    ai.descriptorSetCount = 1;
    ai.pSetLayouts = &opsSetLayout_;
    VkDescriptorSet set = VK_NULL_HANDLE;
    if (vkAllocateDescriptorSets(device_, &ai, &set) != VK_SUCCESS)
        return false;

    DeviceBuf* bufs[4] = {&aa,&bb,&cc,&dd};
    VkDescriptorBufferInfo bi[4]{};
    VkWriteDescriptorSet wr[4]{};
    for (uint32_t i = 0; i < 4; ++i) {
        bi[i].buffer = bufs[i]->buffer;
        bi[i].offset = 0;
        bi[i].range = bufs[i]->size;
        wr[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        wr[i].dstSet = set;
        wr[i].dstBinding = i;
        wr[i].descriptorCount = 1;
        wr[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        wr[i].pBufferInfo = &bi[i];
    }
    vkUpdateDescriptorSets(device_, 4, wr, 0, nullptr);

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, opsPipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                            opsPipelineLayout_, 0, 1, &set, 0, nullptr);
    vkCmdPushConstants(cmd, opsPipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(push), &push);
    vkCmdDispatch(cmd, groupsX, 1, 1);
    recordComputeBarrier(cmd);

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
        vkResetDescriptorPool(device_, descriptorPool_, 0);
        if (!beginCommand(cmd, query, true)) return false;
    }

    VkDescriptorSetAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    ai.descriptorPool = descriptorPool_;
    ai.descriptorSetCount = 1;
    ai.pSetLayouts = &qSetLayout_;
    VkDescriptorSet set = VK_NULL_HANDLE;
    if (vkAllocateDescriptorSets(device_, &ai, &set) != VK_SUCCESS)
        return false;

    DeviceBuf* bufs[3] = {&weights,&input,&output};
    VkDescriptorBufferInfo bi[3]{};
    VkWriteDescriptorSet wr[3]{};
    for (uint32_t i = 0; i < 3; ++i) {
        bi[i].buffer = bufs[i]->buffer;
        bi[i].offset = 0;
        bi[i].range = bufs[i]->size;
        wr[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        wr[i].dstSet = set;
        wr[i].dstBinding = i;
        wr[i].descriptorCount = 1;
        wr[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        wr[i].pBufferInfo = &bi[i];
    }
    vkUpdateDescriptorSets(device_, 3, wr, 0, nullptr);

    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, qPipeline_);
    vkCmdBindDescriptorSets(cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                            qPipelineLayout_, 0, 1, &set, 0, nullptr);
    vkCmdPushConstants(cmd, qPipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(push), &push);
    vkCmdDispatch(cmd, (push.rows + 63u) / 64u, 1, 1);
    recordComputeBarrier(cmd);

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
    uint32_t maxSeq, uint32_t layers)
{
    if (!initialized_ || !hidden || !intermediate || !heads ||
        !kvHeads || !headDim || !maxSeq || !layers) return false;

    uint32_t seqCap = std::min<uint32_t>(maxSeq, 4096);
    if (const char* e = std::getenv("DEEP2_GPU_KV_SEQ_CAP")) {
        unsigned long v = std::strtoul(e, nullptr, 10);
        if (v) seqCap = std::min<uint32_t>(maxSeq, static_cast<uint32_t>(v));
    }

    if (hidden_ == hidden && intermediate_ == intermediate &&
        heads_ == heads && kvHeads_ == kvHeads && headDim_ == headDim &&
        maxSeq_ == seqCap && layers_ == layers && arenaHidden_)
        return true;

    auto kill = [&](DeviceBuf& b){ destroyBuffer(b); };
    kill(arenaHidden_); kill(arenaAttnW_); kill(arenaFfnW_); kill(arenaNormed_);
    kill(arenaQ_); kill(arenaK_); kill(arenaV_); kill(arenaAttn_);
    kill(arenaResidual_); kill(arenaGate_); kill(arenaUp_); kill(arenaFFNAct_);
    kill(arenaDown_); kill(arenaKCache_); kill(arenaVCache_);

    hidden_ = hidden; intermediate_ = intermediate; heads_ = heads;
    kvHeads_ = kvHeads; headDim_ = headDim; maxSeq_ = seqCap; layers_ = layers;
    kvDim_ = kvHeads * headDim;

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
        static_cast<uint64_t>(layers_) * maxSeq_ * kvDim_;

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
    uint32_t, size_t)
{
    if (!maxWeightBytes || !budgetBytes || budgetBytes < maxWeightBytes)
        return false;
    weightBudgetBytes_ = budgetBytes;
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

bool VulkanCompute::BeginFusedLayer() {
    if (fused_ || !initialized_ || !opsPipeline_) return false;
    vkResetDescriptorPool(device_, descriptorPool_, 0);
    if (!beginCommand(fusedCmd_, fusedQuery_, true)) return false;
    fused_ = true;
    fusedHostSubmitNs_ = 0;
    return true;
}

bool VulkanCompute::EndFusedLayer() {
    if (!fused_) return false;
    VkCommandBuffer cmd = fusedCmd_;
    VkQueryPool q = fusedQuery_;
    fused_ = false;
    fusedCmd_ = VK_NULL_HANDLE;
    fusedQuery_ = VK_NULL_HANDLE;
    bool ok = endSubmitWait(
        cmd, q, GpuWorkKind::ModelCompute, 0, workEpoch_, nullptr);
    vkResetDescriptorPool(device_, descriptorPool_, 0);
    return ok;
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
    if (!k || !v || kvDim != kvDim_ || pos >= maxSeq_ || layer >= layers_)
        return false;
    const VkDeviceSize bytes = static_cast<VkDeviceSize>(kvDim)*sizeof(float);
    const uint64_t elemOff =
        (static_cast<uint64_t>(layer)*maxSeq_ + pos)*kvDim_;
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
    if (!headDim || !heads || !kvHeads || heads%kvHeads ||
        !seqLen || seqLen>maxSeq_ || layer>=layers_) return false;

    uint64_t base = static_cast<uint64_t>(layer)*maxSeq_*kvDim_;
    if (base > std::numeric_limits<uint32_t>::max()) return false;

    OpsPush p{};
    p.op=OP_ATTN;
    p.n=heads*headDim;
    p.p0=headDim; p.p1=heads; p.p2=kvHeads; p.p3=seqLen;
    p.p4=kvDim_; p.p5=static_cast<uint32_t>(base); p.f0=scale;
    return dispatchOps(q,kCache,vCache,out,p,(p.n+63u)/64u);
}

void VulkanCompute::clearWeightCache() {
    for (auto& kv : weightCache_) destroyBuffer(kv.second.buffer);
    weightCache_.clear();
    weightCacheBytes_ = 0;
}

bool VulkanCompute::ensureWeightF32(
    const float* weights, uint64_t key, size_t bytes, DeviceBuf*& out)
{
    out = nullptr;
    auto it = weightCache_.find(key);
    if (it != weightCache_.end()) {
        ++weightHits_;
        out = &it->second.buffer;
        return true;
    }
    if (!weights || !bytes) return false;
    if (weightBudgetBytes_ && bytes > weightBudgetBytes_) return false;
    if (weightBudgetBytes_ && weightCacheBytes_ + bytes > weightBudgetBytes_)
        clearWeightCache();

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
    e.bytes=bytes; e.type=0;
    auto ins = weightCache_.emplace(key,std::move(e)).first;
    weightCacheBytes_ += bytes;
    ++weightUploads_;
    out=&ins->second.buffer;
    return true;
}

bool VulkanCompute::ensureWeightQuant(
    int type, const void* weights, size_t bytes, DeviceBuf*& out)
{
    const uint64_t key=quantWeightKey(weights,bytes,type);
    auto it=weightCache_.find(key);
    if(it!=weightCache_.end()){
        ++weightHits_;
        out=&it->second.buffer;
        return true;
    }
    if(!weights||!bytes) return false;
    if(weightBudgetBytes_ && bytes>weightBudgetBytes_) return false;
    if(weightBudgetBytes_ && weightCacheBytes_+bytes>weightBudgetBytes_)
        clearWeightCache();

    WeightCacheEntry e{};
    size_t padded=(bytes+3u)&~size_t(3u);
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
    e.bytes=bytes; e.type=type;
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

void VulkanCompute::cleanup() {
    if (device_) vkDeviceWaitIdle(device_);

    for (auto& e : prefetch_) destroyBuffer(e.buffer);
    prefetch_.clear();
    clearWeightCache();

    auto kill=[&](DeviceBuf& b){destroyBuffer(b);};
    kill(arenaHidden_);kill(arenaAttnW_);kill(arenaFfnW_);kill(arenaNormed_);
    kill(arenaQ_);kill(arenaK_);kill(arenaV_);kill(arenaAttn_);
    kill(arenaResidual_);kill(arenaGate_);kill(arenaUp_);kill(arenaFFNAct_);
    kill(arenaDown_);kill(arenaKCache_);kill(arenaVCache_);

    if(device_ && opsPipeline_) vkDestroyPipeline(device_,opsPipeline_,nullptr);
    if(device_ && qPipeline_) vkDestroyPipeline(device_,qPipeline_,nullptr);
    if(device_ && opsPipelineLayout_) vkDestroyPipelineLayout(device_,opsPipelineLayout_,nullptr);
    if(device_ && qPipelineLayout_) vkDestroyPipelineLayout(device_,qPipelineLayout_,nullptr);
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
    opsPipeline_=qPipeline_=VK_NULL_HANDLE;
    fpGetCalibrated_=nullptr;
    calibratedAvailable_=false;
    initialized_=false;
    fused_=false;
    fusedCmd_=VK_NULL_HANDLE;
    fusedQuery_=VK_NULL_HANDLE;
    hidden_=intermediate_=heads_=kvHeads_=headDim_=maxSeq_=layers_=kvDim_=0;
    weightBudgetBytes_=weightCacheBytes_=0;
}

} // namespace Deep2
