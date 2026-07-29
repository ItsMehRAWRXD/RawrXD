/**
 * @file ide_agent_bridge_hot_patching_integration.hpp
 * @brief Extended IDEAgentBridge with real-time hallucination correction (Qt-free)
 */
#pragma once

#include "ide_agent_bridge.hpp"
#include "agent_hot_patcher.hpp"
#include "gguf_proxy_server.hpp"
#include <memory>
<<<<<<< HEAD
#include <string>
#include <functional>
#include <nlohmann/json.hpp>
=======
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

// Forward declare definitions of records used in database loading
struct CorrectionPatternRecord {
    int id;
    std::string pattern;
    std::string type;
    double confidenceThreshold;
};

struct BehaviorPatchRecord {
    int id;
    std::string description;
    std::string patchType;
    std::string payloadJson;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

class IDEAgentBridgeWithHotPatching : public IDEAgentBridge {
<<<<<<< HEAD
public:
    IDEAgentBridgeWithHotPatching() = default;
    ~IDEAgentBridgeWithHotPatching() override = default;
=======

public:
    IDEAgentBridgeWithHotPatching();
    ~IDEAgentBridgeWithHotPatching() override;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    void initializeWithHotPatching();
    bool startHotPatchingProxy();
    void stopHotPatchingProxy();
    AgentHotPatcher* getHotPatcher() const;
    GGUFProxyServer* getProxyServer() const;
    bool isHotPatchingActive() const;
<<<<<<< HEAD
    nlohmann::json getHotPatchingStatistics() const;
=======

    /**
     * Get hot patching statistics
     */
    nlohmann::json getHotPatchingStatistics() const;

    /**
     * Enable/disable hot patching at runtime
     */
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    void setHotPatchingEnabled(bool enabled);
    void loadCorrectionPatterns(const std::string& databasePath);
    void loadBehaviorPatches(const std::string& databasePath);

<<<<<<< HEAD
    std::string proxyPort() const { return m_proxyPort; }
    void setProxyPort(const std::string& port) { m_proxyPort = port; }
    std::string ggufEndpoint() const { return m_ggufEndpoint; }
    void setGgufEndpoint(const std::string& endpoint) { m_ggufEndpoint = endpoint; }
    void onModelInvokerReplaced();

    // Event handlers (replace Qt slots)
    void handleHallucinationDetected(const HallucinationDetection& detection);
    void handleHallucinationCorrected(const HallucinationDetection& correction);
    void handleNavigationErrorFixed(const NavigationFix& fix);
    void handleBehaviorPatchApplied(const BehaviorPatch& patch);

    // Callbacks (replace Qt signals)
    std::function<void()> onProxyPortChanged;
    std::function<void()> onGgufEndpointChanged;
=======
    /**
     * Load correction patterns from JSON
     */
    void loadCorrectionPatterns(const std::string& jsonPath);

    /**
     * Load behavior patches from JSON
     */
    void loadBehaviorPatches(const std::string& jsonPath);

    /**
     * Runtime configuration: proxy port
     * @note Changing this requires stopping and restarting the proxy
     */
    std::string proxyPort() const { return m_proxyPort; }
    void setProxyPort(const std::string& port) {
        if (port != m_proxyPort) {
            m_proxyPort = port;
            proxyPortChanged();
        }
    }

    /**
     * Runtime configuration: GGUF backend endpoint
     * @note Changing this requires stopping and restarting the proxy
     */
    std::string ggufEndpoint() const { return m_ggufEndpoint; }
    void setGgufEndpoint(const std::string& endpoint) {
        if (endpoint != m_ggufEndpoint) {
            m_ggufEndpoint = endpoint;
            ggufEndpointChanged();
        }
    }

    /**
     * Guard against ModelInvoker replacement
     * Re-wires proxy endpoint if ModelInvoker is recreated
     */
    void onModelInvokerReplaced();

public:
    /**
     * Handle hallucination detected signal
     */
    void onHallucinationDetected(const HallucinationDetection& detection);

    /**
     * Handle hallucination corrected signal
     */
    void onHallucinationCorrected(const HallucinationDetection& correction);

    /**
     * Handle navigation error fixed signal
     */
    void onNavigationErrorFixed(const NavigationFix& fix);

    /**
     * Handle behavior patch applied signal
     */
    void onBehaviorPatchApplied(const BehaviorPatch& patch);

    /**
     * Emitted when proxy port configuration changes
     */
    void proxyPortChanged();

    /**
     * Emitted when GGUF endpoint configuration changes
     */
    void ggufEndpointChanged();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

private:
    std::unique_ptr<AgentHotPatcher> m_hotPatcher;
    std::unique_ptr<GGUFProxyServer> m_proxyServer;
    bool m_hotPatchingEnabled = false;
    std::string m_proxyPort = "11435";
    std::string m_ggufEndpoint = "localhost:11434";
<<<<<<< HEAD
    void logCorrection(const HallucinationDetection& correction);
    void logNavigationFix(const NavigationFix& fix);
=======

    // Logging
    void logCorrection(const HallucinationDetection& correction);
    void logNavigationFix(const NavigationFix& fix);

    // Shadow initialize to ensure proxy is hooked up
    void initialize(const std::string& endpoint, const std::string& backend, const std::string& apiKey) {
        IDEAgentBridge::initialize(endpoint, backend, apiKey);
        if (isHotPatchingActive()) {
             onModelInvokerReplaced();
        }
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
