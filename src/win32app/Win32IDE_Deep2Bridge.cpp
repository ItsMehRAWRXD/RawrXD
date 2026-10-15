// Win32IDE_Deep2Bridge.cpp - Deep2 Engine Bridge for Win32 IDE
// Connects IDE to Deep2 inference - uses real Deep2Engine when available
// CPU fallback available when Deep2Engine is not linked

#include "Win32IDE_Deep2Bridge.h"
#include "Win32IDE.h"
#include "IDELogger.h"
#include <sstream>
#include <chrono>

#ifdef HAVE_DEEP2_ENGINE
#include "Deep2Engine.h"
#include "deep2_snap.hpp"
#include "snap_process_guard.hpp"
#endif

Deep2Bridge::Deep2Bridge(Win32IDE* ide)
    : m_ide(ide)
#ifdef HAVE_DEEP2_ENGINE
    , m_engine(nullptr)
#else
    , m_cpuEngine(nullptr)
#endif
{
    LOG_INFO("Deep2Bridge constructed" 
#ifdef HAVE_DEEP2_ENGINE
        " (Deep2Engine mode)"
#else
        " (CPU fallback mode)"
#endif
    );
}

Deep2Bridge::~Deep2Bridge()
{
    Stop();
#ifdef HAVE_DEEP2_ENGINE
    if (m_engine) {
        delete m_engine;
        m_engine = nullptr;
    }
#else
    if (m_cpuEngine) {
        delete m_cpuEngine;
        m_cpuEngine = nullptr;
    }
#endif
    LOG_INFO("Deep2Bridge destroyed");
}

bool Deep2Bridge::Initialize(const std::string& modelPath)
{
    if (m_initialized.load()) {
        LOG_WARNING("Deep2Bridge already initialized");
        return true;
    }

    LOG_INFO("Initializing Deep2 Bridge...");
    
    try {
#ifdef HAVE_DEEP2_ENGINE
        m_engine = new Deep2::Deep2Engine();
        
        // Configure engine
        Deep2::EngineConfig config;
        config.maxSeqLen = 8192;
        config.useThreadPool = true;
        config.pinThreads = true;
        config.useKVCache = true;
        config.weightQuant = Deep2::EngineConfig::QuantType::Q4_K_M;
        config.kvCacheQuant = Deep2::EngineConfig::QuantType::FP16;
        
        if (!m_engine->initialize(config)) {
            LOG_ERROR("Deep2Engine initialization failed");
            delete m_engine;
            m_engine = nullptr;
            return false;
        }
        
        // Enable Vulkan GPU if available
        m_engine->enableVulkan(true);
        
        // Enable batched prefill for performance
        m_engine->enableBatchedPrefill(true);
        
        // Load model if path provided
        if (!modelPath.empty()) {
            if (!m_engine->loadModel(modelPath)) {
                LOG_WARNING("Failed to load model into Deep2Engine: " + modelPath);
                // Don't fail - allow lazy loading
            } else {
                m_modelPath = modelPath;
                LOG_INFO("Model loaded into Deep2Engine: " + modelPath);
            }
        }
        
        m_initialized.store(true);
        LOG_INFO("Deep2Bridge initialized (Deep2Engine mode)");
        
        if (m_espBus) {
            m_espBus->publish(rawrxd::esp::Kind::ModelLoad, m_modelPath.empty() ? "none" : m_modelPath, m_espRequestId);
        }
        
        return true;
#else
        m_cpuEngine = new RawrXD::CPUInferenceEngine();
        
        // Load model if path provided
        if (!modelPath.empty()) {
            if (!m_cpuEngine->LoadModel(modelPath)) {
                LOG_WARNING("Failed to load model into CPU engine: " + modelPath);
                // Don't fail - allow lazy loading
            } else {
                m_modelPath = modelPath;
                LOG_INFO("Model loaded into CPU fallback: " + modelPath);
            }
        }

        m_initialized.store(true);
        LOG_INFO("Deep2Bridge initialized (CPU fallback mode)");
        
        if (m_espBus) {
            m_espBus->publish(rawrxd::esp::Kind::ModelLoad, m_modelPath.empty() ? "none" : m_modelPath, m_espRequestId);
        }
        
        return true;
#endif
    }
    catch (const std::exception& e) {
        LOG_ERROR("Deep2Bridge initialization failed: " + std::string(e.what()));
        return false;
    }
    catch (...) {
        LOG_ERROR("Deep2Bridge initialization failed with unknown exception");
        return false;
    }
}

bool Deep2Bridge::LoadModel(const std::string& modelPath)
{
    if (!m_initialized.load()) {
        return Initialize(modelPath);
    }

    LOG_INFO("Loading model: " + modelPath);

    if (m_espBus) {
        m_espBus->publish(rawrxd::esp::Kind::ModelLoad, modelPath, m_espRequestId);
    }

#ifdef HAVE_DEEP2_ENGINE
    if (m_engine && m_engine->loadModel(modelPath)) {
        m_modelPath = modelPath;
        LOG_INFO("Model loaded successfully: " + modelPath);
        return true;
    }
#else
    if (m_cpuEngine && m_cpuEngine->LoadModel(modelPath)) {
        m_modelPath = modelPath;
        LOG_INFO("Model loaded successfully: " + modelPath);
        return true;
    }
#endif

    LOG_ERROR("Failed to load model: " + modelPath);
    if (m_espBus) {
        m_espBus->publish(rawrxd::esp::Kind::Error, "Model load failed: " + modelPath, m_espRequestId);
    }
    return false;
}

void Deep2Bridge::UnloadModel()
{
#ifdef HAVE_DEEP2_ENGINE
    if (m_engine) {
        m_engine->unloadModel();
        m_modelPath.clear();
        LOG_INFO("Model unloaded");
    }
#else
    if (m_cpuEngine) {
        m_cpuEngine->ClearCache();
        m_modelPath.clear();
        LOG_INFO("Model unloaded");
    }
#endif
}

bool Deep2Bridge::GenerateStream(const std::string& prompt,
                                 std::function<bool(const std::string& token, bool isComplete)> callback,
                                 int maxTokens,
                                 float temperature,
                                 float topP,
                                 int topK)
{
    if (!m_initialized.load()) {
        LOG_ERROR("Deep2Bridge not initialized");
        return false;
    }

#ifdef HAVE_DEEP2_ENGINE
    if (!m_engine) {
        LOG_ERROR("Deep2Engine not available");
        return false;
    }
#else
    if (!m_cpuEngine) {
        LOG_ERROR("CPU engine not available");
        return false;
    }
#endif

    if (m_generating.load()) {
        LOG_WARNING("Generation already in progress");
        return false;
    }

    m_maxTokens = maxTokens;
    m_temperature = temperature;
    m_topP = topP;
    m_topK = topK;

    m_tokenCallback = callback;
    m_accumulatedResponse.clear();
    m_generationComplete = false;
    m_cancelRequested.store(false);
    m_stopRequested.store(false);
    m_generating.store(true);

    if (m_espBus) {
        m_espBus->publish(rawrxd::esp::Kind::PrefillStart, "prompt_len=" + std::to_string(prompt.size()), m_espRequestId);
    }

    // Use engine for generation
    m_generationThread = std::thread([this, prompt, maxTokens]() {
        GenerationWorker(prompt, maxTokens);
    });

    return true;
}

void Deep2Bridge::GenerationWorker(const std::string& prompt, int maxTokens)
{
    try {
#ifdef HAVE_DEEP2_ENGINE
        if (!m_engine) {
            throw std::runtime_error("Deep2Engine not available");
        }

        if (m_espBus) {
            m_espBus->publish(rawrxd::esp::Kind::PrefillEnd, "tokens=0", m_espRequestId);
        }

        // Configure generation parameters
        Deep2::GenerationOptions options;
        options.maxTokens = static_cast<uint32_t>(maxTokens);
        options.temperature = m_temperature;
        options.topP = m_topP;
        options.topK = static_cast<uint32_t>(m_topK);
        options.repeatPenalty = 1.1f;
        options.minP = 0.0f;
        options.seed = 0;
        
        m_engine->configureGeneration(options);
        
        std::string fullResponse;
        
        // Use streaming generation
        auto result = m_engine->generateStream(
            prompt,
            options,
            [this, &fullResponse](int32_t tokenId, const std::string& token) {
                fullResponse += token;
                m_accumulatedResponse += token;
                
                if (m_espBus) {
                    m_espBus->publish(rawrxd::esp::Kind::TokenGenerated, token, m_espRequestId, 0, tokenId);
                }
                
                std::lock_guard<std::mutex> lock(m_callbackMutex);
                if (m_tokenCallback) {
                    bool continueGen = m_tokenCallback(token, false);
                    if (!continueGen) {
                        m_cancelRequested.store(true);
                        m_engine->requestCancel();
                    }
                }
                return !m_cancelRequested.load();
            }
        );
        
        OnGenerationComplete(m_cancelRequested.load());
#else
        if (!m_cpuEngine) {
            throw std::runtime_error("CPU engine not available");
        }

        if (m_espBus) {
            m_espBus->publish(rawrxd::esp::Kind::PrefillEnd, "tokens=0", m_espRequestId);
        }

        // Configure generation parameters
        m_cpuEngine->ConfigureGeneration(m_temperature, m_topP, static_cast<uint32_t>(m_topK), 1.1f, 0);
        
        std::string fullResponse;
        
        // Use streaming generation
        m_cpuEngine->GenerateStreaming(
            m_cpuEngine->Tokenize(prompt),
            maxTokens,
            [this, &fullResponse](const std::string& token) {
                fullResponse += token;
                m_accumulatedResponse += token;
                
                if (m_espBus) {
                    m_espBus->publish(rawrxd::esp::Kind::TokenGenerated, token, m_espRequestId);
                }
                
                std::lock_guard<std::mutex> lock(m_callbackMutex);
                if (m_tokenCallback) {
                    bool continueGen = m_tokenCallback(token, false);
                    if (!continueGen) {
                        m_cancelRequested.store(true);
                    }
                }
            },
            [this]() {
                // Completion callback
                OnGenerationComplete(m_cancelRequested.load());
            },
            [this](int32_t tokenId) {
                // Token ID callback - can be used for more detailed telemetry
                if (m_espBus) {
                    m_espBus->publish(rawrxd::esp::Kind::TokenGenerated, "id=" + std::to_string(tokenId), m_espRequestId, 0, tokenId);
                }
            }
        );
#endif
    }
    catch (const std::exception& e) {
        LOG_ERROR("Generation worker exception: " + std::string(e.what()));
        {
            std::lock_guard<std::mutex> lock(m_callbackMutex);
            if (m_tokenCallback) {
                m_tokenCallback("[ERROR: " + std::string(e.what()) + "]", true);
            }
        }
        OnGenerationComplete(true);
    }
    catch (...) {
        LOG_ERROR("Generation worker unknown exception");
        OnGenerationComplete(true);
    }
}

bool Deep2Bridge::OnTokenCallback(int32_t tokenId, const std::string& token)
{
    if (m_cancelRequested.load() || m_stopRequested.load()) {
        return false;
    }
    return true;
}

void Deep2Bridge::OnGenerationComplete(bool cancelled)
{
    m_generating.store(false);
    m_generationComplete = true;

    if (m_espBus) {
        if (cancelled) {
            m_espBus->publish(rawrxd::esp::Kind::SnapStop, "cancelled", m_espRequestId);
        } else {
            m_espBus->publish(rawrxd::esp::Kind::Finished, m_accumulatedResponse, m_espRequestId);
        }
    }

    std::lock_guard<std::mutex> lock(m_callbackMutex);
    if (m_tokenCallback) {
        m_tokenCallback("", true);
    }
}

std::string Deep2Bridge::GenerateSync(const std::string& prompt, int maxTokens)
{
    if (!m_initialized.load()) {
        return "Error: Deep2Bridge not initialized";
    }

    try {
#ifdef HAVE_DEEP2_ENGINE
        if (!m_engine) {
            return "Error: Deep2Engine not available";
        }
        
        Deep2::GenerationOptions options;
        options.maxTokens = static_cast<uint32_t>(maxTokens);
        options.temperature = m_temperature;
        options.topP = m_topP;
        options.topK = static_cast<uint32_t>(m_topK);
        options.repeatPenalty = 1.1f;
        options.minP = 0.0f;
        options.seed = 0;
        
        m_engine->configureGeneration(options);
        return m_engine->generateText(prompt, maxTokens);
#else
        if (!m_cpuEngine) {
            return "Error: CPU engine not available";
        }
        
        // Configure and use the sync inference
        m_cpuEngine->ConfigureGeneration(m_temperature, m_topP, static_cast<uint32_t>(m_topK), 1.1f, 0);
        return m_cpuEngine->infer(prompt);
#endif
    }
    catch (const std::exception& e) {
        return "Error: " + std::string(e.what());
    }
}

void Deep2Bridge::Cancel()
{
    m_cancelRequested.store(true);
    LOG_INFO("Deep2Bridge: Cancellation requested");
}

void Deep2Bridge::Stop()
{
    m_stopRequested.store(true);
    m_cancelRequested.store(true);
    if (m_generationThread.joinable()) {
        m_generationThread.join();
    }
    m_generating.store(false);
    LOG_INFO("Deep2Bridge: Stopped");
}

std::string Deep2Bridge::GetModelInfo() const
{
#ifdef HAVE_DEEP2_ENGINE
    if (!m_engine) {
        return "No model loaded (Deep2Engine mode)";
    }

    std::ostringstream oss;
    oss << "Model: " << m_modelPath << "\n";
    oss << "Backend: Deep2Engine (GPU" << (m_engine->isVulkanInitialized() ? " active" : " inactive") << ")\n";
    oss << "Context: " << m_engine->getConfig().maxSeqLen << "\n";
    oss << "Vocab Size: " << m_engine->getConfig().vocabSize << "\n";
    oss << "Layers: " << m_engine->getConfig().numLayers << "\n";
    oss << "Heads: " << m_engine->getConfig().numHeads << "\n";
    oss << "Hidden Dim: " << m_engine->getConfig().hiddenDim << "\n";
    if (m_engine->isVulkanInitialized()) {
        oss << "GPU Dispatches: " << m_engine->vulkanGemvSuccessCount() << "\n";
        oss << "CPU Fallbacks: " << m_engine->vulkanGemvFallbackCount() << "\n";
        oss << "GPU Weight Bytes: " << m_engine->vulkanGpuWeightBytes() << "\n";
    }
    return oss.str();
#else
    if (!m_cpuEngine) {
        return "No model loaded (CPU fallback mode)";
    }

    std::ostringstream oss;
    oss << "Model: " << m_modelPath << "\n";
    oss << "Backend: CPU fallback\n";
    oss << "Context: " << m_cpuEngine->GetContextLimit() << "\n";
    oss << "Vocab Size: " << m_cpuEngine->GetVocabSize() << "\n";
    oss << "Layers: " << m_cpuEngine->GetNumLayers() << "\n";
    oss << "Heads: " << m_cpuEngine->GetNumHeads() << "\n";
    return oss.str();
#endif
}

void Deep2Bridge::SetGenerationConfig(int maxTokens, float temperature, float topP, int topK)
{
    m_maxTokens = maxTokens;
    m_temperature = temperature;
    m_topP = topP;
    m_topK = topK;
}

void Deep2Bridge::SetESPBus(rawrxd::esp::Bus* bus, uint64_t requestId)
{
    m_espBus = bus;
    m_espRequestId = requestId;
}

void Deep2Bridge::SetOutputCallback(OutputCallback callback)
{
    m_outputCallback = callback;
}

std::string Deep2Bridge::GetStatus() const
{
    std::ostringstream oss;
#ifdef HAVE_DEEP2_ENGINE
    oss << "Deep2Bridge (Deep2Engine): ";
#else
    oss << "Deep2Bridge (CPU fallback): ";
#endif
    if (!m_initialized.load()) {
        oss << "Not Initialized";
    }
#ifdef HAVE_DEEP2_ENGINE
    else if (!m_engine) {
        oss << "Initialized, No Engine";
    } else if (!m_engine->isModelLoaded()) {
        oss << "Initialized, No Model";
    } else if (m_generating.load()) {
        oss << "Generating...";
    } else {
        oss << "Ready (Model: " << (m_modelPath.empty() ? "none" : m_modelPath) << ")";
    }
#else
    else if (!m_cpuEngine) {
        oss << "Initialized, No Engine";
    } else if (m_generating.load()) {
        oss << "Generating...";
    } else {
        oss << "Ready (Model: " << (m_modelPath.empty() ? "none" : m_modelPath) << ")";
    }
#endif
    return oss.str();
}

double Deep2Bridge::GetTokensPerSecond() const
{
    return 0.0;
}

size_t Deep2Bridge::GetContextLength() const
{
    if (!m_cpuEngine) return 8192;
    return m_cpuEngine->GetContextLimit();
}

bool Deep2Bridge::IsModelLoaded() const
{
#ifdef HAVE_DEEP2_ENGINE
    return m_engine && m_engine->isModelLoaded();
#else
    return m_cpuEngine && m_cpuEngine->IsModelLoaded();
#endif
}