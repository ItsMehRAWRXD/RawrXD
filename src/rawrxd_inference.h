#pragma once
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

// Phase 46: Vulkan support with graceful fallback for dual GPU testing
// Include vulkan_compute.h from include directory for consistent Vulkan type definitions
#include "../include/vulkan_compute.h"

// Define RAWR_VULKAN_AVAILABLE based on whether real Vulkan is available
#if defined(RAWR_ENABLE_VULKAN) || defined(RAWR_HAS_VULKAN)
    #if __has_include(<vulkan/vulkan.h>)
        #define RAWR_VULKAN_AVAILABLE 1
    #else
        #pragma message("Vulkan SDK headers not found — using CPU fallback for dual GPU testing")
        #define RAWR_VULKAN_AVAILABLE 0
    #endif
#else
    #define RAWR_VULKAN_AVAILABLE 0
#endif

// Vulkan types are now provided by vulkan_compute.h
// Only define additional Vulkan constants here if not already defined
#ifndef VK_NULL_HANDLE
#define VK_NULL_HANDLE 0
#endif
#ifndef VK_STRUCTURE_TYPE_APPLICATION_INFO
#define VK_STRUCTURE_TYPE_APPLICATION_INFO 0
#endif
#ifndef VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO
#define VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO 0
#endif
#ifndef VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO
#define VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO 0
#endif
#ifndef VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO
#define VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO 0
#endif
#ifndef VK_MAKE_VERSION
#define VK_MAKE_VERSION(a, b, c) 0
#endif
#ifndef VK_API_VERSION_1_2
#define VK_API_VERSION_1_2 0
#endif
#ifndef VK_SUCCESS
#define VK_SUCCESS 0
#endif
#ifndef VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU
#define VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU 0
#endif
#ifndef VK_QUEUE_COMPUTE_BIT
#define VK_QUEUE_COMPUTE_BIT 0
#endif
#include "core/gguf_swarm_plan_builder.hpp"
#include "rawrxd_model_loader.h"
#include "rawrxd_sampler.h"
#include "rawrxd_tokenizer.h"
#include "rawrxd_transformer.h"
#include "core/swarm_scheduler.hpp"

/// Snapshot of MoE grouped pack cache + async prepack counters (Win32IDE HUD / staging telemetry).
struct MoEPackHudMetrics
{
    std::uint64_t packHits = 0;
    std::uint64_t packMisses = 0;
    std::uint64_t groupedFallbacks = 0;
    std::uint64_t syncPackInserts = 0;
    std::uint64_t prepackInserts = 0;
    std::uint64_t prepackQueueDropped = 0;
    std::uint64_t prepackSkippedNotResident = 0;
    std::uint64_t packEvictedByPlanRow = 0;
    std::size_t prepackQueueDepthApprox = 0;
    std::size_t packCachePackedBytes = 0;
    std::uint64_t packCacheEvictions = 0;
    std::uint64_t packCacheSelectiveRowInvalidations = 0;
};

// RawrXD Real Inference Orchestrator
// One-shot: Load model -> Tokenize -> Forward -> Sample -> Detokenize

class RawrXDInference
{
    RawrXDModelLoader loader;
    RawrXDTransformer transformer;
    RawrXDTokenizer tokenizer;
    RawrXDSampler sampler;
    std::unique_ptr<RawrXD::Swarm::SwarmScheduler> m_swarmScheduler;
    bool m_initialized = false;
    uint32_t m_contextLimit = 0;
    std::vector<float> m_lastLogits;
    std::string m_lastLoadErrorMessage;

    // Helpers
    VkInstance CreateVulkanInstance()
    {
#if !RAWR_VULKAN_AVAILABLE
        return VK_NULL_HANDLE;
#else
        VkApplicationInfo appInfo{};
        appInfo.sType = static_cast<VkStructureType>(VK_STRUCTURE_TYPE_APPLICATION_INFO);
        appInfo.pApplicationName = "RawrXD Inference";
        appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
        appInfo.pEngineName = "RawrXD Engine";
        appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
        appInfo.apiVersion = VK_API_VERSION_1_2;

        VkInstanceCreateInfo createInfo{};
        createInfo.sType = static_cast<VkStructureType>(VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO);
        createInfo.pApplicationInfo = &appInfo;
        createInfo.enabledLayerCount = 0;
        createInfo.enabledExtensionCount = 0;

        VkInstance instance = VK_NULL_HANDLE;
        if (vkCreateInstance(&createInfo, nullptr, &instance) != VK_SUCCESS)
        {
            printf("Failed to create Vulkan instance\n");
            return VK_NULL_HANDLE;
        }
        return instance;
#endif
    }

    VkPhysicalDevice SelectPhysicalDevice(VkInstance instance)
    {
#if !RAWR_VULKAN_AVAILABLE
        (void)instance;
        return VK_NULL_HANDLE;
#else
        uint32_t deviceCount = 0;
        vkEnumeratePhysicalDevices(instance, &deviceCount, nullptr);
        if (deviceCount == 0)
            return VK_NULL_HANDLE;

        std::vector<VkPhysicalDevice> devices(deviceCount);
        vkEnumeratePhysicalDevices(instance, &deviceCount, devices.data());

        for (const auto& device : devices)
        {
            VkPhysicalDeviceProperties deviceProperties;
            vkGetPhysicalDeviceProperties(device, &deviceProperties);
            if (deviceProperties.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU)
            {
                printf("Selected GPU: %s\n", deviceProperties.deviceName);
                return device;
            }
        }
        return devices[0];
#endif
    }

    VkDevice CreateLogicalDevice(VkPhysicalDevice physDevice)
    {
#if !RAWR_VULKAN_AVAILABLE
        (void)physDevice;
        return VK_NULL_HANDLE;
#else
        uint32_t queueFamilyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(physDevice, &queueFamilyCount, nullptr);
        std::vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
        vkGetPhysicalDeviceQueueFamilyProperties(physDevice, &queueFamilyCount, queueFamilies.data());

        int computeFamily = -1;
        for (uint32_t i = 0; i < queueFamilyCount; i++)
        {
            if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT)
            {
                computeFamily = i;
                break;
            }
        }

        float queuePriority = 1.0f;
        VkDeviceQueueCreateInfo queueCreateInfo{};
        queueCreateInfo.sType = static_cast<VkStructureType>(VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO);
        queueCreateInfo.queueFamilyIndex = computeFamily;
        queueCreateInfo.queueCount = 1;
        queueCreateInfo.pQueuePriorities = &queuePriority;

        VkDeviceCreateInfo createInfo{};
        createInfo.sType = static_cast<VkStructureType>(VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO);
        createInfo.pQueueCreateInfos = &queueCreateInfo;
        createInfo.queueCreateInfoCount = 1;
        VkPhysicalDeviceFeatures deviceFeatures{};
        createInfo.pEnabledFeatures = &deviceFeatures;

        VkDevice device = VK_NULL_HANDLE;
        if (vkCreateDevice(physDevice, &createInfo, nullptr, &device) != VK_SUCCESS)
        {
            printf("failed to create logical device!\n");
            return VK_NULL_HANDLE;
        }
        return device;
#endif
    }

  public:
    ~RawrXDInference()
    {
        // Fix use-after-free: transformer holds a raw pointer to m_swarmScheduler.
        // If we do not clear it here, ~RawrXDTransformer() runs AFTER the unique_ptr
        // has already destroyed the scheduler, causing an access violation.
        transformer.SetSwarmScheduler(nullptr);
    }

    const std::string& GetLastLoadErrorMessage() const { return m_lastLoadErrorMessage; }

    // B010: Weight-residency profiling accessors
    RawrXDModelLoader& GetLoader() { return loader; }
    const RawrXDModelLoader& GetLoader() const { return loader; }

    bool Initialize(const wchar_t* modelPath, const char* vocabPath, const char* mergesPath)
    {
        m_lastLoadErrorMessage.clear();
        loader.SetLoadErrorCallback([this](const std::string& stage, const std::string& message)
                                    { m_lastLoadErrorMessage = stage + ": " + message; });
#if RAWR_VULKAN_AVAILABLE
        VkInstance instance = CreateVulkanInstance();
        VkPhysicalDevice physDevice = VK_NULL_HANDLE;
        VkDevice device = VK_NULL_HANDLE;

        if (!instance)
        {
            printf("[RawrXD] Vulkan init failed at instance creation; falling back to CPU mode\n");
        }
        else
        {
            physDevice = SelectPhysicalDevice(instance);
            if (!physDevice)
            {
                printf("[RawrXD] Vulkan init failed at physical device selection; falling back to CPU mode\n");
            }
            else
            {
                device = CreateLogicalDevice(physDevice);
                if (!device)
                {
                    printf("[RawrXD] Vulkan init failed at logical device creation; falling back to CPU mode\n");
                    physDevice = VK_NULL_HANDLE;
                }
            }
        }
#else
        // CPU-only mode — no GPU required
        VkDevice device = VK_NULL_HANDLE;
        VkPhysicalDevice physDevice = VK_NULL_HANDLE;
        printf("[RawrXD] CPU-only mode (Vulkan disabled)\n");
#endif

        printf("[RawrXD] Stage: loader.Load\n");
        if (!loader.Load(modelPath, device, physDevice))
        {
            if (m_lastLoadErrorMessage.empty())
            {
                m_lastLoadErrorMessage = loader.GetLastLoadErrorMessage();
            }
            printf("[RawrXD] Failed to load model\n");
            return false;
        }

        RawrXDTransformer::Config cfg{};  // Zero-init all fields
        cfg.dim = loader.getDim();
        cfg.n_layers = loader.getLayers();
        cfg.n_heads = loader.getHeads();
        cfg.n_kv_heads = loader.getKVHeads();
        cfg.vocab_size = loader.getVocabSize();

        if (cfg.vocab_size == 0)
            cfg.vocab_size = 32000;
        if (cfg.dim == 0)
            cfg.dim = 4096;
        if (cfg.n_layers == 0)
            cfg.n_layers = 32;
        if (cfg.n_heads == 0)
            cfg.n_heads = 32;
        if (cfg.n_kv_heads == 0)
            cfg.n_kv_heads = cfg.n_heads;

        cfg.hidden_dim = (loader.getFFNDim() > 0) ? loader.getFFNDim() : cfg.dim * 4;
        cfg.n_ctx = 2048;  // Conservative context for CPU-only mode
        cfg.seq_len = 2048;
        cfg.rope_theta = 10000.0f;
        cfg.rms_norm_eps = 1e-5f;

        // B009-P2: Enable weight residency pool for batched prefill optimization
        cfg.weight_residency_pool_max_bytes = 512ULL * 1024 * 1024; // 512 MB

        printf("[RawrXD] Config: dim=%d layers=%d heads=%d kv_heads=%d vocab=%d hidden=%d ctx=%d\n", cfg.dim,
               cfg.n_layers, cfg.n_heads, cfg.n_kv_heads, cfg.vocab_size, cfg.hidden_dim, cfg.n_ctx);
        printf("[RawrXD] Stage: transformer.Initialize\n");
        transformer.Initialize(device, physDevice, cfg, &loader);

        m_swarmScheduler = RawrXD::Swarm::makeSwarmSchedulerWithLoader(&loader);
        RawrXD::Swarm::SchedulerConfig swarmCfg;
        swarmCfg.enableAsyncPrefetchThread = true;
        swarmCfg.admitFirstSliceOnExecutePlan = false;
        swarmCfg.prefetchAheadLayers = 2;
        swarmCfg.prefetchIoPollMs = 4;
        (void)m_swarmScheduler->configure(swarmCfg);

        std::vector<RawrXD::Swarm::ModelSlice> swarmPlan;
        const uint64_t fileSz = loader.GetFileSizeBytes();
        const uint32_t nl = static_cast<uint32_t>(cfg.n_layers);
        if (fileSz > 0 && nl > 0)
        {
            swarmPlan = RawrXD::Swarm::buildLayerSlicesFromGGUF(loader, nl);
            if (!swarmPlan.empty())
            {
                std::uint64_t planTotalBytes = 0;
                std::uint64_t planMaxSlice = 0;
                for (const auto& s : swarmPlan)
                {
                    planTotalBytes += s.byteSize;
                    planMaxSlice = std::max(planMaxSlice, s.byteSize);
                }
                const double planTotalGiB = static_cast<double>(planTotalBytes) / (1024.0 * 1024.0 * 1024.0);
                const double planMaxMiB = static_cast<double>(planMaxSlice) / (1024.0 * 1024.0);
                const double planAvgMiB =
                    static_cast<double>(planTotalBytes) / static_cast<double>(swarmPlan.size()) / (1024.0 * 1024.0);
                printf("[RawrXD] Swarm plan: GGUF coalesced (%zu slices total=%.2f GiB max=%.2f MiB avg=%.2f MiB)\n",
                       swarmPlan.size(), planTotalGiB, planMaxMiB, planAvgMiB);
            }
            else
            {
                for (uint32_t li = 0; li < nl; ++li)
                {
                    RawrXD::Swarm::ModelSlice s;
                    s.id.modelIndex = 0;
                    s.id.layerStart = li;
                    s.id.layerEnd = li + 1u;
                    s.id.expertIndex = 0xFFFFFFFFu;
                    const uint64_t per = fileSz / static_cast<uint64_t>(nl);
                    s.fileOffsetBytes = per * static_cast<uint64_t>(li);
                    s.byteSize = (li + 1u == nl) ? (fileSz - s.fileOffsetBytes) : per;
                    swarmPlan.push_back(std::move(s));
                }
                printf("[RawrXD] Swarm plan: file/layer stripe fallback (%u slices)\n", nl);
            }
        }
        (void)m_swarmScheduler->submitPlan(std::move(swarmPlan));
        (void)m_swarmScheduler->executePlan();
        transformer.SetSwarmScheduler(m_swarmScheduler.get());

        printf("[RawrXD] Stage: tokenizer.Load\n");
        tokenizer.Load(vocabPath);
        m_contextLimit = static_cast<uint32_t>(cfg.n_ctx);
        m_lastLogits.clear();

        printf("[RawrXD] Inference engine READY\n");
        m_initialized = true;
        return true;
    }

    bool IsInitialized() const { return m_initialized; }

    /** Forwarded to RawrXDTransformer (stdout/ODS unchanged). */
    void SetLayerProgressCallback(std::function<void(const std::string&)> cb)
    {
        transformer.SetProgressCallback(std::move(cb));
    }

    /// Loader VMM / multi-slot pressure (for IDE telemetry).
    [[nodiscard]] RawrXDModelLoader::SlidingWindowTelemetry loaderSlidingWindowTelemetry() const
    {
        return loader.slidingWindowTelemetrySnapshot();
    }
    /// Swarm prefetch / eviction counters (empty scheduler returns zeros).
    [[nodiscard]] RawrXD::Swarm::SwarmRuntimeStats swarmRuntimeStats() const
    {
        if (!m_swarmScheduler)
            return {};
        return m_swarmScheduler->runtimeStats();
    }

    /// Increments on each successful `submitPlan`; use to skip `refreshSwarmPlanSliceIndex()` when unchanged.
    [[nodiscard]] std::uint64_t swarmPlanGeneration() const
    {
        if (!m_swarmScheduler)
            return 0;
        return m_swarmScheduler->planGeneration();
    }

    /// MoE mixture pack cache + prepack worker counters (for IDE output / status HUD).
    [[nodiscard]] MoEPackHudMetrics moEPackHudMetrics() const
    {
        MoEPackHudMetrics m;
        m.packHits = transformer.moeGroupedPackCacheHits();
        m.packMisses = transformer.moeGroupedPackCacheMisses();
        m.groupedFallbacks = transformer.moeGroupedFallbacks();
        m.syncPackInserts = transformer.moeGroupedSyncPackInserts();
        m.prepackInserts = transformer.moePrepackInserts();
        m.prepackQueueDropped = transformer.moePrepackQueueDropped();
        m.prepackSkippedNotResident = transformer.moePrepackSkippedNotResident();
        m.packEvictedByPlanRow = transformer.moePackEvictedByPlanRow();
        m.prepackQueueDepthApprox = transformer.moePrepackQueueDepthApprox();
        m.packCachePackedBytes = transformer.moeMixturePackCacheCurrentPackedBytes();
        m.packCacheEvictions = transformer.moeMixturePackCacheEvictions();
        m.packCacheSelectiveRowInvalidations = transformer.moeMixturePackCacheSelectiveRowInvalidations();
        return m;
    }

    /// MoE / swarm residency grid for Win32IDE (single mutex pass on the scheduler).
    [[nodiscard]] bool CaptureSwarmExpertHeatmap(const RawrXD::Swarm::ExpertHeatmapCaptureParams& params,
                                                 RawrXD::Swarm::ExpertHeatmapSnapshot& out)
    {
        if (!m_swarmScheduler)
        {
            out = {};
            return false;
        }
        return m_swarmScheduler->captureExpertHeatmapSnapshot(params, out);
    }

    // Expose loader metadata to facade
    int getVocabSize() const { return loader.getVocabSize(); }
    int getDim() const { return loader.getDim(); }
    int getLayers() const { return loader.getLayers(); }
    int getHeads() const { return loader.getHeads(); }
    int getKVHeads() const { return loader.getKVHeads(); }
    uint32_t getContextLimit() const { return m_contextLimit; }
    std::uint64_t getRouterBoundaryMatMulCount() const { return transformer.routerBoundaryMatMulCount(); }
    std::uint64_t getLayerPredictCount() const { return transformer.layerPredictCount(); }
    std::uint64_t getLayerPrefetchCount() const { return transformer.layerPrefetchCount(); }

    std::vector<uint32_t> Tokenize(const std::string& text)
    {
        if (!m_initialized)
            return {};
        return tokenizer.Encode(text);
    }

    std::string Detokenize(const std::vector<uint32_t>& tokens)
    {
        if (!m_initialized)
            return {};
        return tokenizer.Decode(tokens);
    }

    std::vector<float> ForwardTokens(const std::vector<uint32_t>& tokens, uint32_t startPos = 0)
    {
        if (!m_initialized || tokens.empty())
        {
            return {};
        }
        m_lastLogits = transformer.Forward(tokens, startPos);
        return m_lastLogits;
    }

    const std::vector<float>& LastLogits() const { return m_lastLogits; }

    std::vector<uint32_t> GenerateFromTokens(const std::vector<uint32_t>& promptTokens, uint32_t maxTokens = 512,
                                             std::function<void(uint32_t, const std::string&)> callback = nullptr)
    {
        std::vector<uint32_t> generated;
        if (!m_initialized || maxTokens == 0 || promptTokens.empty())
        {
            return generated;
        }
        maxTokens = std::min<uint32_t>(maxTokens, 8192);

        std::vector<uint32_t> tokens = promptTokens;
        const uint32_t vocabSize = std::max(1, loader.getVocabSize());

        // Keep right-most context when prompt exceeds model context.
        if (m_contextLimit > 0 && tokens.size() > m_contextLimit)
        {
            tokens.erase(tokens.begin(), tokens.end() - m_contextLimit);
        }
        for (auto& t : tokens)
        {
            if (t >= vocabSize)
                t %= vocabSize;
        }

        printf("[STREAM] calling Forward() for prefill, tokens=%zu\n", tokens.size());
        auto logits = transformer.Forward(tokens, 0);
        printf("[STREAM] Forward() returned, logits.size()=%zu\n", logits.size());
        m_lastLogits = logits;
        uint32_t absolutePos = static_cast<uint32_t>(tokens.size());

        printf("[STREAM] entering generation loop, maxTokens=%u\n", maxTokens);
        for (uint32_t i = 0; i < maxTokens; i++)
        {
            printf("[STREAM] generation iteration %u\n", i);
            if (logits.empty())
            {
                printf("[STREAM] logits empty, breaking\n");
                break;
            }

            bool hasFinite = false;
            for (float v : logits)
            {
                if (std::isfinite(v))
                {
                    hasFinite = true;
                    break;
                }
            }
            if (!hasFinite)
            {
                printf("[STREAM] no finite logits, breaking\n");
                break;
            }

            uint32_t nextToken = sampler.Sample(logits.data(), logits.size(), tokens);
            printf("[STREAM] candidate token=%u\n", nextToken);
            if (nextToken >= vocabSize)
            {
                nextToken %= vocabSize;
            }
            tokens.push_back(nextToken);
            if (m_contextLimit > 0 && tokens.size() > m_contextLimit)
            {
                tokens.erase(tokens.begin(), tokens.end() - m_contextLimit);
            }
            generated.push_back(nextToken);

            if (nextToken == 2)
            {
                printf("[STREAM] EOS token, breaking\n");
                break;
            }

            std::vector<uint32_t> nextTokVec = {nextToken};
            printf("[STREAM] calling Forward() for decode, absolutePos=%u\n", absolutePos);
            logits = transformer.Forward(nextTokVec, absolutePos);
            printf("[STREAM] Forward() decode returned, logits.size()=%zu\n", logits.size());
            absolutePos++;
            m_lastLogits = logits;

            if (callback)
            {
                const std::string piece = tokenizer.Decode({nextToken});
                printf("[STREAM] invoking callback token=%u\n", nextToken);
                try
                {
                    callback(nextToken, piece);
                    printf("[STREAM] callback returned\n");
                }
                catch (...)
                {
                    printf("[STREAM] callback threw exception\n");
                }
            }
        }

        printf("[STREAM] generation loop complete, generated=%zu tokens\n", generated.size());
        return generated;
    }

    // B009-P4: Direct Forward() for residency amortization testing
    std::vector<float> ForwardDirect(const std::vector<uint32_t>& tokens, int startPos = 0)
    {
        if (!m_initialized)
            return {};
        return transformer.Forward(tokens, startPos);
    }

    std::string Generate(const std::string& prompt, uint32_t maxTokens = 512,
                         std::function<void(const std::string&)> callback = nullptr)
    {
        if (!m_initialized || maxTokens == 0)
        {
            return {};
        }
        maxTokens = std::min<uint32_t>(maxTokens, 8192);

        const auto tokens = tokenizer.Encode(prompt);
        if (tokens.empty())
        {
            return {};
        }

        std::string fullResponse;
        auto generated = GenerateFromTokens(tokens, maxTokens,
                                            [&](uint32_t, const std::string& piece)
                                            {
                                                if (callback)
                                                    callback(piece);
                                                fullResponse += piece;
                                            });
        (void)generated;
        return fullResponse;
    }
};
