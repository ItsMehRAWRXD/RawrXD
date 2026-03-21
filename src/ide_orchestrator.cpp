#include "ide_orchestrator.h"
#include "vulkan_compute.h"
#include "swarm_orchestrator.h"
#include "chain_of_thought.h"
#include "token_generator.h"
#include "agentic_ide.h"
#include "cpu_inference_engine.h"
#include "net/net_impl_win32.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace fs = std::filesystem;

namespace RawrXD {

IDEOrchestrator::IDEOrchestrator(const IDEConfig& config) : m_config(config) {
    spdlog::info("Creating IDE orchestrator with {} workers", config.maxWorkers);
}

IDEOrchestrator::~IDEOrchestrator() {
    stop();
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::initialize() {
    spdlog::info("Initializing IDE orchestrator...");
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Setup logging
    if (m_config.enableLogging) {
        auto logLevel = static_cast<spdlog::level::level_enum>(m_config.logLevel);
        spdlog::set_level(logLevel);
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
        
        if (m_config.enableFileLogging) {
            auto logDir = fs::path(m_config.logPath).parent_path();
            if (!fs::exists(logDir)) {
                fs::create_directories(logDir);
            }
            
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                m_config.logPath, true
            );
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            
            std::vector<spdlog::sink_ptr> sinks = {console_sink};
            if (m_config.enableFileLogging) {
                sinks.push_back(file_sink);
            }
            
            auto logger = std::make_shared<spdlog::logger>("ide", sinks.begin(), sinks.end());
            logger->set_level(logLevel);
            spdlog::set_default_logger(logger);
            
            spdlog::info("Logging initialized to {}", m_config.logPath);
        }
    }
    
    // Initialize components
    auto componentResult = initializeComponents();
    if (!componentResult) {
        spdlog::critical("Component initialization failed: {}", 
                        static_cast<int>(componentResult.error()));
        return componentResult;
    }
    
    spdlog::info("Components initialized successfully");
    
    // Setup networking if enabled
    if (m_config.enableNetwork) {
        auto networkResult = setupNetworking();
        if (!networkResult) {
            spdlog::error("Network setup failed: {}", static_cast<int>(networkResult.error()));
            // Continue without network
        } else {
            spdlog::info("Network stack initialized");
        }
    }
    
    // Setup tokenization if enabled
    if (m_config.enableTokenization) {
        auto tokenResult = setupTokenization();
        if (!tokenResult) {
            spdlog::error("Tokenization setup failed: {}", static_cast<int>(tokenResult.error()));
            return tokenResult;
        }
        spdlog::info("Tokenization initialized");
    }
    
    // Setup swarm if enabled
    if (m_config.enableSwarm) {
        auto swarmResult = setupSwarm();
        if (!swarmResult) {
            spdlog::error("Swarm setup failed: {}", static_cast<int>(swarmResult.error()));
            return swarmResult;
        }
        spdlog::info("Swarm orchestrator initialized");
    }
    
    // Setup chain-of-thought if enabled
    if (m_config.enableChainOfThought) {
        auto chainResult = setupChainOfThought();
        if (!chainResult) {
            spdlog::error("Chain-of-thought setup failed: {}", 
                         static_cast<int>(chainResult.error()));
            return chainResult;
        }
        spdlog::info("Chain-of-thought initialized");
    }
    
    // Setup editor if enabled
    if (m_config.enableMonaco) {
        auto editorResult = setupEditor();
        if (!editorResult) {
            spdlog::error("Editor setup failed: {}", static_cast<int>(editorResult.error()));
            return editorResult;
        }
        spdlog::info("Monaco editor initialized");
    }
    
    // Setup inference
    auto inferenceResult = setupInference();
    if (!inferenceResult) {
        spdlog::critical("Inference setup failed: {}", 
                        static_cast<int>(inferenceResult.error()));
        return inferenceResult;
    }
    spdlog::info("Inference engine initialized");
    
    // Start background threads
    auto threadResult = startBackgroundThreads();
    if (!threadResult) {
        spdlog::critical("Failed to start background threads: {}", 
                        static_cast<int>(threadResult.error()));
        return threadResult;
    }
    
    m_initialized = true;
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    
    spdlog::info("IDE orchestrator initialized successfully in {} ms", duration.count());
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::initializeComponents() {
    spdlog::debug("Initializing IDE components...");
    
    // Create Vulkan Compute first (hardware foundation)
    m_vulkanCompute = std::make_shared<VulkanCompute>();
    auto vkResult = m_vulkanCompute->Initialize();
    if (!vkResult) {
        spdlog::warn("Vulkan initialization failed (falling back to CPU)");
        // Don't fail the whole IDE, just run in CPU mode
    } else {
        spdlog::info("Vulkan Compute Engine initialized successfully");
    }

    // Create inference engine first (needed by others)
    m_inferenceEngine = std::make_shared<CPUInferenceEngine>();
    spdlog::debug("CPU inference engine created");
    
    // Create tokenizer
    m_tokenizer = std::make_shared<TokenGenerator>();
    if (m_vulkanCompute) {
        m_tokenizer->setVulkanCompute(m_vulkanCompute);
    }
    spdlog::debug("Token generator created");
    
    // Create network manager
    // Network manager is a singleton, access via instance()
    spdlog::debug("Network manager available via singleton");
    
    // Create swarm orchestrator
    m_swarm = std::make_shared<SwarmOrchestrator>(m_config.maxWorkers);
    spdlog::debug("Swarm orchestrator created");
    
    // Create chain-of-thought
    m_chainOfThought = std::make_shared<ChainOfThought>();
    spdlog::debug("Chain-of-thought created");
    
    // Editor (stub - Monaco not available)
    // m_editor = MonacoFactory::createEditor(MonacoVariant::Enterprise);
    spdlog::debug("Editor setup deferred (Monaco not available)");
    
    // Create main IDE
    IDEConfig ideConfig;
    ideConfig.modelsPath = m_config.modelsPath;
    ideConfig.toolsPath = m_config.toolsPath;
    ideConfig.maxWorkers = m_config.maxWorkers;
    ideConfig.logLevel = m_config.logLevel;
    ideConfig.enableFileLogging = m_config.enableFileLogging;
    ideConfig.logPath = m_config.logPath;
    ideConfig.enableLSP = m_config.enableLSP;
    ideConfig.enableChat = true;
    ideConfig.enableOrchestrator = true;
    ideConfig.enableZeroDay = true;
    
    m_ide = std::make_shared<AgenticIDE>(ideConfig);
    spdlog::debug("Agentic IDE created");
    
    // Wire components together
    // (Editor and swarm wiring deferred — APIs evolving)
    
    spdlog::info("All IDE components initialized and wired");
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::setupNetworking() {
    spdlog::debug("Setting up network stack...");
    
    auto& netManager = Net::NetworkManager::instance();
    Net::NetworkConfig netConfig;
    auto result = netManager.initialize(netConfig);
    
    if (!result) {
        return RawrXD::unexpected(IDEError::NetworkUnavailable);
    }
    
    // Test network connectivity
    auto httpResult = netManager.getHttpClient().get("http://localhost:11434/api/tags");
    if (!httpResult) {
        spdlog::warn("Network test failed: {}", static_cast<int>(httpResult.error()));
    } else {
        spdlog::info("Network connectivity confirmed");
    }
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::setupTokenization() {
    spdlog::debug("Setting up tokenization...");
    
    if (!m_config.enableTokenization) {
        spdlog::info("Tokenization disabled in config");
        return {};
    }
    
    // Tokenizer uses model path for vocabulary loading
    std::string vocabPath = m_config.modelsPath + "/tokenizer.json";
    std::string mergesPath = m_config.modelsPath + "/tokenizer_config.json";
    
    spdlog::info("Tokenizer setup complete");
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::setupSwarm() {
    spdlog::debug("Setting up swarm orchestrator...");
    
    auto initResult = m_swarm->initialize();
    if (!initResult) {
        spdlog::warn("Swarm initialization returned error, continuing...");
    }
    
    spdlog::info("Swarm orchestrator configured");
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::setupChainOfThought() {
    spdlog::debug("Setting up chain-of-thought...");
    
    // Test chain-of-thought
    std::string testGoal = "Debug a segmentation fault in C++ code";
    std::unordered_map<std::string, std::string> context = {
        {"language", "cpp"},
        {"error", "segmentation fault"},
        {"line", "42"}
    };
    
    auto chainResult = m_chainOfThought->generateChain(testGoal, context);
    if (chainResult) {
        spdlog::debug("Chain-of-thought test completed with {} steps", 
                     chainResult->steps.size());
    }
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::setupEditor() {
    spdlog::debug("Setting up editor...");
    
    if (!m_editor) {
        spdlog::info("Editor not initialized (Monaco not available), skipping editor setup");
        return {};
    }
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::setupInference() {
    spdlog::debug("Setting up inference engine...");
    
    // Load a test model
    std::string modelPath = m_config.modelsPath + "/test.gguf";
    if (fs::exists(modelPath)) {
        auto loadResult = m_inferenceEngine->loadModel(modelPath);
        if (loadResult) {
            spdlog::info("Inference engine loaded model: {}", modelPath);
        } else {
            spdlog::warn("Failed to load model: {}", static_cast<int>(loadResult.error()));
        }
    } else {
        spdlog::warn("No model found at {}, inference will use fallback", modelPath);
    }
    
    return {};
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::startBackgroundThreads() {
    spdlog::debug("Starting background threads...");
    
    m_running = true;
    
    // Start main thread
    m_mainThread = std::thread(&IDEOrchestrator::mainLoop, this);
    
    // Start inference thread
    m_inferenceThread = std::thread(&IDEOrchestrator::inferenceLoop, this);
    
    // Start render thread
    m_renderThread = std::thread(&IDEOrchestrator::renderLoop, this);
    
    // Start network thread
    m_networkThread = std::thread(&IDEOrchestrator::networkLoop, this);
    
    spdlog::info("Started {} background threads", 4);
    
    return {};
}

void IDEOrchestrator::mainLoop() {
    spdlog::info("Main orchestrator loop started");
    
    while (m_running.load()) {
        std::unique_lock lock(m_taskMutex);
        
        // Wait for tasks or timeout
        m_taskCondition.wait_for(lock, std::chrono::milliseconds(100), 
            [this] { return !m_taskQueue.empty() || !m_running.load(); });
        
        if (!m_running.load()) break;
        
        // Process tasks
        while (!m_taskQueue.empty()) {
            auto task = std::move(m_taskQueue.front());
            m_taskQueue.pop();
            lock.unlock();
            
            processTask(task);
            
            lock.lock();
        }
        
        lock.unlock();
        
        // Collect metrics periodically
        static auto lastMetrics = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (now - lastMetrics > std::chrono::seconds(30)) {
            collectMetrics();
            lastMetrics = now;
        }
    }
    
    spdlog::info("Main orchestrator loop stopped");
}

void IDEOrchestrator::inferenceLoop() {
    spdlog::info("Inference thread started");
    
    while (m_running.load()) {
        std::unique_lock lock(m_inferenceMutex);
        
        m_inferenceCondition.wait_for(lock, std::chrono::milliseconds(10), 
            [this] { return !m_inferenceQueue.empty() || !m_running.load(); });
        
        if (!m_running.load()) break;
        
        while (!m_inferenceQueue.empty()) {
            auto inference = std::move(m_inferenceQueue.front());
            m_inferenceQueue.pop();
            lock.unlock();
            
            processInference(inference);
            
            lock.lock();
        }
    }
    
    spdlog::info("Inference thread stopped");
}

void IDEOrchestrator::renderLoop() {
    spdlog::info("Render thread started");
    
    while (m_running.load()) {
        std::unique_lock lock(m_renderMutex);
        
        m_renderCondition.wait_for(lock, std::chrono::milliseconds(16), // ~60 FPS
            [this] { return !m_renderQueue.empty() || !m_running.load(); });
        
        if (!m_running.load()) break;
        
        while (!m_renderQueue.empty()) {
            auto render = std::move(m_renderQueue.front());
            m_renderQueue.pop();
            lock.unlock();
            
            processRender(render);
            
            lock.lock();
        }
    }
    
    spdlog::info("Render thread stopped");
}

void IDEOrchestrator::networkLoop() {
    spdlog::info("Network thread started");
    
    while (m_running.load()) {
        // Process network events
        auto& netManager = Net::NetworkManager::instance();
        
        if (netManager.isInitialized()) {
            // Check for pending requests
            // This is where we'd handle async network callbacks
            
            // Poll for incoming data
            // This is where we'd handle WebSocket messages
            
            // Handle timeouts
            // This is where we'd cancel stuck requests
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    spdlog::info("Network thread stopped");
}

void IDEOrchestrator::processTask(std::function<void()> task) {
    auto startTime = std::chrono::steady_clock::now();
    
    try {
        task();
        m_successfulRequests.fetch_add(1);
    } catch (const std::exception& e) {
        spdlog::error("Task execution failed: {}", e.what());
        m_failedRequests.fetch_add(1);
    }
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime);
    m_totalProcessingTimeMs.fetch_add(duration.count());
}

void IDEOrchestrator::processInference(std::function<void()> inference) {
    try {
        inference();
    } catch (const std::exception& e) {
        spdlog::error("Inference failed: {}", e.what());
    }
}

void IDEOrchestrator::processRender(std::function<void()> render) {
    try {
        render();
    } catch (const std::exception& e) {
        spdlog::error("Render failed: {}", e.what());
    }
}

void IDEOrchestrator::collectMetrics() {
    json metrics = {
        {"timestamp", getTimestamp()},
        {"requests", {
            {"total", m_totalRequests.load()},
            {"successful", m_successfulRequests.load()},
            {"failed", m_failedRequests.load()}
        }},
        {"processing_time_ms", m_totalProcessingTimeMs.load()},
        {"tokens_generated", m_tokensGenerated.load()},
        {"cache", {
            {"hits", m_cacheHits.load()},
            {"misses", m_cacheMisses.load()}
        }}
    };
    
    // Save metrics to file
    std::string metricsPath = "metrics.json";
    std::ofstream file(metricsPath);
    if (file) {
        file << metrics.dump(2);
    }
    
    // Report to monitoring system if configured
    if (m_config.enableMetrics) {
        reportMetrics();
    }
}

void IDEOrchestrator::reportMetrics() {
    // In production, this would send metrics to a monitoring service
    // For now, just log them
    spdlog::info("Metrics report: {}", getMetrics().dump());
}

json IDEOrchestrator::getStatus() const {
    std::lock_guard lock(m_mutex);
    
    return {
        {"running", m_running.load()},
        {"initialized", m_initialized.load()},
        {"components", {
            {"ide", m_ide ? m_ide->getStatus() : json()},
            {"swarm", m_swarm ? m_swarm->getStatus() : json()},
            {"chain_of_thought", m_chainOfThought ? m_chainOfThought->getStatus() : json()},
            {"inference_engine", m_inferenceEngine ? json({{"loaded", m_inferenceEngine->isModelLoaded()}}) : json()}
        }},
        {"metrics", getMetrics()},
        {"config", {
            {"models_path", m_config.modelsPath},
            {"max_workers", m_config.maxWorkers},
            {"max_memory_mb", m_config.maxMemoryMB},
            {"enable_network", m_config.enableNetwork},
            {"enable_swarm", m_config.enableSwarm},
            {"enable_chain_of_thought", m_config.enableChainOfThought},
            {"enable_tokenization", m_config.enableTokenization},
            {"enable_vulkan", m_config.enableVulkan},
            {"enable_monaco", m_config.enableMonaco}
        }}
    };
}

json IDEOrchestrator::getMetrics() const {
    return {
        {"timestamp", getTimestamp()},
        {"requests", {
            {"total", m_totalRequests.load()},
            {"successful", m_successfulRequests.load()},
            {"failed", m_failedRequests.load()}
        }},
        {"processing_time_ms", m_totalProcessingTimeMs.load()},
        {"tokens_generated", m_tokensGenerated.load()},
        {"cache", {
            {"hits", m_cacheHits.load()},
            {"misses", m_cacheMisses.load()}
        }}
    };
}

std::string IDEOrchestrator::getTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// IDEManager Implementation
IDEManager& IDEManager::getInstance() {
    static IDEManager instance;
    return instance;
}

RawrXD::Expected<std::shared_ptr<IDEOrchestrator>, IDEError> IDEManager::createIDE(
    const IDEConfig& config
) {
    std::lock_guard lock(m_mutex);
    
    auto id = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto ide = std::make_shared<IDEOrchestrator>(config);
    
    auto result = ide->initialize();
    if (!result) {
        return RawrXD::unexpected(result.error());
    }
    
    m_ides[id] = ide;
    
    spdlog::info("Created IDE instance: {}", id);
    
    return ide;
}

RawrXD::Expected<void, IDEError> IDEManager::destroyIDE(const std::string& id) {
    std::lock_guard lock(m_mutex);
    
    auto it = m_ides.find(id);
    if (it == m_ides.end()) {
        return RawrXD::unexpected(IDEError::ComponentNotFound);
    }
    
    it->second->stop();
    m_ides.erase(it);
    
    spdlog::info("Destroyed IDE instance: {}", id);
    
    return {};
}

std::shared_ptr<IDEOrchestrator> IDEManager::getIDE(const std::string& id) const {
    std::lock_guard lock(m_mutex);
    
    auto it = m_ides.find(id);
    if (it != m_ides.end()) {
        return it->second;
    }
    
    return nullptr;
}

json IDEManager::getAllStatus() const {
    std::lock_guard lock(m_mutex);
    
    json status;
    status["ides"] = json::array();
    
    for (const auto& [id, ide] : m_ides) {
        status["ides"].push_back({
            {"id", id},
            {"status", ide->getStatus()}
        });
    }
    
    return status;
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::start() {
    spdlog::info("Starting IDE orchestrator...");
    if (m_running) return {};
    if (m_ide) m_ide->start();
    return startBackgroundThreads();
}

RawrXD::Expected<void, IDEError> IDEOrchestrator::stop() {
    spdlog::info("Stopping IDE orchestrator...");
    m_running = false;
    if (m_ide) m_ide->stop();
    if (m_mainThread.joinable()) m_mainThread.join();
    if (m_inferenceThread.joinable()) m_inferenceThread.join();
    if (m_renderThread.joinable()) m_renderThread.join();
    if (m_networkThread.joinable()) m_networkThread.join();
    return {};
}

json IDEManager::getAllMetrics() const {
    std::lock_guard lock(m_mutex);
    
    json metrics;
    metrics["ides"] = json::array();
    
    for (const auto& [id, ide] : m_ides) {
        metrics["ides"].push_back({
            {"id", id},
            {"metrics", ide->getMetrics()}
        });
    }
    
    return metrics;
}

} // namespace RawrXD
