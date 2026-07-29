/**
 * @file ide_agent_bridge_hot_patching_integration.cpp
 * @brief Extended IDEAgentBridge with runtime hallucination correction (Qt-free)
 *
 * Uses SQLite3 C API directly instead of QSqlDatabase.
 * Uses std::filesystem + std::ofstream for logging.
 */
#include "ide_agent_bridge_hot_patching_integration.hpp"
<<<<<<< HEAD
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include "model_invoker.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
namespace {

void ensureLogDirectory() {
    static std::mutex dirMutex;
    std::lock_guard<std::mutex> lock(dirMutex);
    std::error_code ec;
    fs::create_directories("logs", ec);
}

bool isValidPort(int port) { return port > 0 && port < 65536; }

bool isValidEndpoint(const std::string& ep) {
    auto colon = ep.rfind(':');
    if (colon == std::string::npos) return false;
    int port = std::atoi(ep.substr(colon + 1).c_str());
    return isValidPort(port);
}

std::string nowISO() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[64]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    return buf;
}

// ---------------------------------------------------------------------------
// Lightweight SQLite3 access (uses C API; link with sqlite3.lib / -lsqlite3)
// If sqlite3.h is unavailable the DB fetch functions just return empty vectors.
// ---------------------------------------------------------------------------
#if __has_include(<sqlite3.h>)
#  include <sqlite3.h>
#  define HAS_SQLITE 1
#else
#  define HAS_SQLITE 0
#endif

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

std::vector<CorrectionPatternRecord> fetchCorrectionPatternsFromDb(
    const std::string& dbPath) {
    std::vector<CorrectionPatternRecord> out;
    if (!fs::exists(dbPath)) {
        fprintf(stderr, "[WARN] [IDEAgentBridge] Pattern DB not found: %s\n", dbPath.c_str());
        return out;
    }
#if HAS_SQLITE
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        fprintf(stderr, "[WARN] [IDEAgentBridge] Cannot open pattern DB: %s\n",
                sqlite3_errmsg(db));
        sqlite3_close(db);
        return out;
    }
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, pattern, type, confidence_threshold FROM correction_patterns";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            CorrectionPatternRecord rec;
            rec.id   = sqlite3_column_int(stmt, 0);
            rec.pattern = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            rec.type    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            rec.confidenceThreshold = sqlite3_column_double(stmt, 3);
            out.push_back(rec);
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
#else
    fprintf(stderr, "[INFO] [IDEAgentBridge] sqlite3 not available – skipping pattern DB\n");
#endif
    return out;
}

std::vector<BehaviorPatchRecord> fetchBehaviorPatchesFromDb(
    const std::string& dbPath) {
    std::vector<BehaviorPatchRecord> out;
    if (!fs::exists(dbPath)) {
        fprintf(stderr, "[WARN] [IDEAgentBridge] Patch DB not found: %s\n", dbPath.c_str());
        return out;
    }
#if HAS_SQLITE
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
        fprintf(stderr, "[WARN] [IDEAgentBridge] Cannot open patch DB: %s\n",
                sqlite3_errmsg(db));
        sqlite3_close(db);
        return out;
    }
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT id, description, patch_type, payload_json FROM behavior_patches";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            BehaviorPatchRecord rec;
            rec.id          = sqlite3_column_int(stmt, 0);
            rec.description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            rec.patchType   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            rec.payloadJson = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            out.push_back(rec);
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
#else
    fprintf(stderr, "[INFO] [IDEAgentBridge] sqlite3 not available – skipping patch DB\n");
#endif
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------
IDEAgentBridgeWithHotPatching::IDEAgentBridgeWithHotPatching()
    : m_hotPatcher(nullptr)
=======
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

static void ensureLogDirectory()
{
    static std::mutex dirMutex;
    std::lock_guard<std::mutex> locker(dirMutex);
    std::filesystem::path logDir("logs");
    if (!std::filesystem::exists(logDir)) std::filesystem::create_directories(logDir);
}

// ============================================================================
// Validation helpers
// ============================================================================
static bool isValidPort(int port) { return port > 0 && port < 65536; }

static int stringToInt(const std::string& str, int defaultVal = -1) {
    try {
        return std::stoi(str);
    } catch (...) {
        return defaultVal;
    }
}

static bool isValidEndpoint(const std::string& ep)
{
    // Simple check: host:port
    size_t colonPos = ep.find_last_of(':');
    if (colonPos == std::string::npos || colonPos == ep.length() - 1) {
        return false;
    }
    
    std::string portStr = ep.substr(colonPos + 1);
    int port = stringToInt(portStr);
    return isValidPort(port);
}

static std::string truncateString(const std::string& str, size_t maxLen) {
    if (str.length() <= maxLen) return str;
    return str.substr(0, maxLen);
}

// ============================================================================
// Helper: Ensure log directory exists
// ============================================================================
static void ensureLogDirectory() {
    try {
        if (!std::filesystem::exists("logs")) {
            std::filesystem::create_directories("logs");
        }
    } catch (...) {}
}

// ============================================================================
// Helper: Current Time String
// ============================================================================
static std::string getCurrentTimeStr() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// ============================================================================
// Helper: Load correction patterns from JSON
// ============================================================================

static std::vector<CorrectionPatternRecord> fetchCorrectionPatternsFromDb(
    const std::string& dbPath)
{
    std::vector<CorrectionPatternRecord> patterns;
    
    // Switch .db to .json for modern storage
    std::string jsonPath = dbPath;
    if (jsonPath.ends_with(".db")) {
        jsonPath.replace(jsonPath.length() - 3, 3, ".json");
    }

    if (!std::filesystem::exists(jsonPath)) {
        return patterns;
    }

    try {
        std::ifstream f(jsonPath);
        json j;
        f >> j;

        for (const auto& item : j) {
            CorrectionPatternRecord rec;
            rec.id = item.value("id", 0);
            rec.pattern = item.value("pattern", "");
            rec.type = item.value("type", "general");
            rec.confidenceThreshold = item.value("confidence_threshold", 0.8);
            patterns.push_back(rec);
        }
    } catch (const std::exception& e) {
        // Log error
    }

    return patterns;
}

// ============================================================================
// Helper: Load behavior patches from JSON
// ============================================================================

static std::vector<BehaviorPatchRecord> fetchBehaviorPatchesFromDb(
    const std::string& dbPath)
{
    std::vector<BehaviorPatchRecord> patches;

    std::string jsonPath = dbPath;
    if (jsonPath.ends_with(".db")) {
        jsonPath.replace(jsonPath.length() - 3, 3, ".json");
    }

    if (!std::filesystem::exists(jsonPath)) {
        return patches;
    }

    try {
        std::ifstream f(jsonPath);
        json j;
        f >> j;

        for (const auto& item : j) {
            BehaviorPatchRecord rec;
            rec.id = item.value("id", 0);
            rec.description = item.value("description", "");
            rec.patchType = item.value("patch_type", "");
            rec.payloadJson = item.value("payload_json", "{}");
            patches.push_back(rec);
        }
    } catch (...) {
        // ignore
    }

    return patches;
}

IDEAgentBridgeWithHotPatching::IDEAgentBridgeWithHotPatching(void* parent)
    : IDEAgentBridge()
    , m_hotPatcher(nullptr)
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    , m_proxyServer(nullptr)
    , m_hotPatchingEnabled(false)
    , m_proxyPort("11435")
    , m_ggufEndpoint("localhost:11434")
{
<<<<<<< HEAD
    fprintf(stderr, "[INFO] [IDEAgentBridge] Creating extended bridge with hot patching\n");
}

IDEAgentBridgeWithHotPatching::~IDEAgentBridgeWithHotPatching() {
    try {
        if (m_proxyServer && m_proxyServer->isListening()) {
            m_proxyServer->stopServer();
            fprintf(stderr, "[INFO] [IDEAgentBridge] Hot patching proxy shut down\n");
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "[WARN] [IDEAgentBridge] Exception on destruction: %s\n", e.what());
    }
}

// ---------------------------------------------------------------------------
void IDEAgentBridgeWithHotPatching::initializeWithHotPatching() {
    fprintf(stderr, "[INFO] [IDEAgentBridge] Initializing with hot patching\n");

    try {
        ensureLogDirectory();
        this->initialize();

        // Hot patcher
        m_hotPatcher = std::make_unique<AgentHotPatcher>();
        m_hotPatcher->initialize("./gguf_loader", 0);
        fprintf(stderr, "[INFO] [IDEAgentBridge] AgentHotPatcher initialized\n");

        // Proxy
        m_proxyServer = std::make_unique<GGUFProxyServer>();
        fprintf(stderr, "[INFO] [IDEAgentBridge] GGUFProxyServer created\n");

        // Wire callbacks instead of Qt signals
        m_hotPatcher->onHallucinationDetected = [this](const HallucinationDetection& d) {
            handleHallucinationDetected(d);
        };
        m_hotPatcher->onHallucinationCorrected = [this](const HallucinationDetection& c) {
            handleHallucinationCorrected(c);
        };
        m_hotPatcher->onNavigationErrorFixed = [this](const NavigationFix& f) {
            handleNavigationErrorFixed(f);
        };
        m_hotPatcher->onBehaviorPatchApplied = [this](const BehaviorPatch& p) {
            handleBehaviorPatchApplied(p);
        };

        fprintf(stderr, "[INFO] [IDEAgentBridge] Hot patcher callbacks connected\n");

        loadCorrectionPatterns("data/correction_patterns.db");
        loadBehaviorPatches("data/behavior_patches.db");

        // Redirect ModelInvoker to proxy
        if (this->getModelInvoker()) {
            this->getModelInvoker()->setLLMBackend(
                this->getModelInvoker()->getLLMBackend(),
                "http://localhost:" + m_proxyPort);
            fprintf(stderr, "[INFO] [IDEAgentBridge] ModelInvoker redirected to proxy\n");
        }
=======
    (void)parent;
}

IDEAgentBridgeWithHotPatching::~IDEAgentBridgeWithHotPatching() noexcept
{
    try {
        if (m_proxyServer && m_proxyServer->isListening()) m_proxyServer->stopServer();
    } catch (...) {}
}

void IDEAgentBridgeWithHotPatching::initializeWithHotPatching()
{

    try {
        ensureLogDirectory();
        this->initialize("http://localhost:11435", "llama.cpp", "sk-none");

        m_hotPatcher = std::make_unique<AgentHotPatcher>();
        m_hotPatcher->initialize("./gguf_loader", 0);
        m_proxyServer = std::make_unique<GGUFProxyServer>();

        m_hotPatcher->onHallucinationDetected = [this](const HallucinationDetection& d) { this->onHallucinationDetected(d); };
        m_hotPatcher->onHallucinationCorrected = [this](const HallucinationDetection& c) { this->onHallucinationCorrected(c); };
        m_hotPatcher->onNavigationErrorFixed = [this](const NavigationFix& f) { this->onNavigationErrorFixed(f); };

        loadCorrectionPatterns("data/correction_patterns.json");
        loadBehaviorPatches("data/behavior_patches.json");
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

        if (this->getModelInvoker()) this->getModelInvoker()->setEndpoint("http://localhost:11435");
        
        m_hotPatchingEnabled = true;
<<<<<<< HEAD
        fprintf(stderr, "[INFO] [IDEAgentBridge] Hot patching initialization complete\n");

    } catch (const std::exception& ex) {
        fprintf(stderr, "[CRIT] [IDEAgentBridge] Hot patching init failed: %s\n", ex.what());
        m_hotPatchingEnabled = false;
    }
}

bool IDEAgentBridgeWithHotPatching::startHotPatchingProxy() {
    if (!m_proxyServer) {
        fprintf(stderr, "[WARN] [IDEAgentBridge] Proxy not initialized\n");
        return false;
    }
    if (m_proxyServer->isListening()) return true;

    try {
        int port = std::atoi(m_proxyPort.c_str());
        if (!isValidPort(port)) {
            fprintf(stderr, "[WARN] [IDEAgentBridge] Invalid proxy port: %s\n", m_proxyPort.c_str());
            return false;
        }
        if (!isValidEndpoint(m_ggufEndpoint)) {
            fprintf(stderr, "[WARN] [IDEAgentBridge] Invalid endpoint: %s\n", m_ggufEndpoint.c_str());
            return false;
        }

        m_proxyServer->initialize(port, m_hotPatcher.get(), m_ggufEndpoint);
        if (!m_proxyServer->startServer()) {
            fprintf(stderr, "[WARN] [IDEAgentBridge] Proxy start failed\n");
            return false;
        }

        fprintf(stderr, "[INFO] [IDEAgentBridge] Proxy started on port %d\n", port);
        return true;
    } catch (const std::exception& ex) {
        fprintf(stderr, "[CRIT] [IDEAgentBridge] Proxy exception: %s\n", ex.what());
        return false;
    }
}

void IDEAgentBridgeWithHotPatching::stopHotPatchingProxy() {
    if (m_proxyServer && m_proxyServer->isListening()) {
        m_proxyServer->stopServer();
        fprintf(stderr, "[INFO] [IDEAgentBridge] Proxy stopped\n");
    }
}

AgentHotPatcher* IDEAgentBridgeWithHotPatching::getHotPatcher() const {
    return m_hotPatcher.get();
}

GGUFProxyServer* IDEAgentBridgeWithHotPatching::getProxyServer() const {
    return m_proxyServer.get();
}

bool IDEAgentBridgeWithHotPatching::isHotPatchingActive() const {
    return m_hotPatchingEnabled && m_hotPatcher && m_proxyServer
           && m_proxyServer->isListening();
}

json IDEAgentBridgeWithHotPatching::getHotPatchingStatistics() const {
    if (!m_hotPatcher) return {};
    json stats = m_hotPatcher->getCorrectionStatistics();
    if (m_proxyServer)
        stats["proxyServerRunning"] = m_proxyServer->isListening();
    return stats;
}

void IDEAgentBridgeWithHotPatching::setHotPatchingEnabled(bool enabled) {
    if (m_hotPatchingEnabled == enabled) return;
    m_hotPatchingEnabled = enabled;

    if (m_hotPatcher) {
        m_hotPatcher->setHotPatchingEnabled(enabled);
        fprintf(stderr, "[INFO] [IDEAgentBridge] Hot patching %s\n",
                enabled ? "enabled" : "disabled");
    }

    if (m_proxyServer) {
        if (enabled && !m_proxyServer->isListening())
            startHotPatchingProxy();
        else if (!enabled && m_proxyServer->isListening())
            stopHotPatchingProxy();
    }
}

// ---------------------------------------------------------------------------
// Pattern / patch loading
// ---------------------------------------------------------------------------
void IDEAgentBridgeWithHotPatching::loadCorrectionPatterns(const std::string& dbPath) {
    if (!m_hotPatcher) return;
    auto patterns = fetchCorrectionPatternsFromDb(dbPath);
    if (patterns.empty()) {
        fprintf(stderr, "[INFO] [IDEAgentBridge] No correction patterns found – using defaults\n");
        return;
    }

    int ok = 0;
    for (const auto& rec : patterns) {
        fprintf(stderr, "[INFO] [IDEAgentBridge] Pattern ID=%d Type=%s Threshold=%.2f\n",
                rec.id, rec.type.c_str(), rec.confidenceThreshold);
        ok++;
    }
    fprintf(stderr, "[INFO] [IDEAgentBridge] Loaded %d/%zu correction patterns\n",
            ok, patterns.size());
}

void IDEAgentBridgeWithHotPatching::loadBehaviorPatches(const std::string& dbPath) {
    if (!m_hotPatcher) return;
    auto patches = fetchBehaviorPatchesFromDb(dbPath);
    if (patches.empty()) {
        fprintf(stderr, "[INFO] [IDEAgentBridge] No behavior patches found – using defaults\n");
        return;
    }

    int ok = 0;
    for (const auto& rec : patches) {
        fprintf(stderr, "[INFO] [IDEAgentBridge] Patch ID=%d Type=%s\n",
                rec.id, rec.patchType.c_str());
        ok++;
    }
    fprintf(stderr, "[INFO] [IDEAgentBridge] Loaded %d/%zu behavior patches\n",
            ok, patches.size());
}

// ---------------------------------------------------------------------------
// Event handlers
// ---------------------------------------------------------------------------
void IDEAgentBridgeWithHotPatching::handleHallucinationDetected(
    const HallucinationDetection& detection) {
    fprintf(stderr, "[INFO] [IDEAgentBridge] Hallucination detected | Type: %s | Conf: %.2f\n",
            detection.hallucationType.c_str(), detection.confidence);
    logCorrection(detection);
}

void IDEAgentBridgeWithHotPatching::handleHallucinationCorrected(
    const HallucinationDetection& correction) {
    fprintf(stderr, "[INFO] [IDEAgentBridge] Hallucination corrected | Type: %s\n",
            correction.hallucationType.c_str());
    logCorrection(correction);
}

void IDEAgentBridgeWithHotPatching::handleNavigationErrorFixed(
    const NavigationFix& fix) {
    fprintf(stderr, "[INFO] [IDEAgentBridge] Nav error fixed | %s -> %s | Eff: %.2f\n",
            fix.incorrectPath.c_str(), fix.correctPath.c_str(), fix.effectiveness);
    logNavigationFix(fix);
}

void IDEAgentBridgeWithHotPatching::handleBehaviorPatchApplied(
    const BehaviorPatch& patch) {
    fprintf(stderr, "[INFO] [IDEAgentBridge] Behavior patch applied | ID: %s Type: %s Rate: %.2f\n",
            patch.patchId.c_str(), patch.patchType.c_str(), patch.successRate);
}

void IDEAgentBridgeWithHotPatching::onModelInvokerReplaced() {
    if (this->getModelInvoker() && m_hotPatchingEnabled) {
        std::string endpoint = "http://localhost:" + m_proxyPort;
        this->getModelInvoker()->setLLMBackend(
            this->getModelInvoker()->getLLMBackend(), endpoint);
        fprintf(stderr, "[INFO] [IDEAgentBridge] ModelInvoker re-wired to proxy: %s\n",
                endpoint.c_str());
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
void IDEAgentBridgeWithHotPatching::logCorrection(
    const HallucinationDetection& correction) {
    static std::mutex logMutex;
    std::lock_guard<std::mutex> lock(logMutex);
    ensureLogDirectory();

    std::ofstream f("logs/corrections.log", std::ios::app);
    if (!f.is_open()) return;

    f << nowISO() << " | "
      << "Type: " << correction.hallucationType << " | "
      << "Confidence: " << correction.confidence << " | "
      << "Detected: " << correction.detectedContent.substr(0, 50) << " | "
      << "Corrected: " << correction.expectedContent.substr(0, 50) << "\n";
}

void IDEAgentBridgeWithHotPatching::logNavigationFix(const NavigationFix& fix) {
    static std::mutex logMutex;
    std::lock_guard<std::mutex> lock(logMutex);
    ensureLogDirectory();

    std::ofstream f("logs/navigation_fixes.log", std::ios::app);
    if (!f.is_open()) return;

    f << nowISO() << " | "
      << "From: " << fix.incorrectPath << " | "
      << "To: " << fix.correctPath << " | "
      << "Eff: " << fix.effectiveness << " | "
      << "Reason: " << fix.reasoning << "\n";
=======
        startHotPatchingProxy();
    } catch (...) { m_hotPatchingEnabled = false; }
}

bool IDEAgentBridgeWithHotPatching::startHotPatchingProxy()
{
    if (!m_proxyServer) return false;
    if (m_proxyServer->isListening()) return true;
    try {
        int port = std::stoi(m_proxyPort);
        m_proxyServer->initialize(port, m_hotPatcher.get(), m_ggufEndpoint);
        return m_proxyServer->startServer();
    } catch (...) { return false; }
}

void IDEAgentBridgeWithHotPatching::stopHotPatchingProxy()
{
    if (m_proxyServer) m_proxyServer->stopServer();
}

AgentHotPatcher* IDEAgentBridgeWithHotPatching::getHotPatcher() const { return m_hotPatcher.get(); }
GGUFProxyServer* IDEAgentBridgeWithHotPatching::getProxyServer() const { return m_proxyServer.get(); }
bool IDEAgentBridgeWithHotPatching::isHotPatchingActive() const { return m_proxyServer && m_proxyServer->isListening(); }
nlohmann::json IDEAgentBridgeWithHotPatching::getHotPatchingStatistics() const 
{ 
    nlohmann::json stats;
    if (m_hotPatcher) {
        // stats["total_hallucinations"] = m_hotPatcher->getTotalHallucinations(); // Assuming accessor exists or direct access
        // Since AgentHotPatcher implementation details were in the other file, we'll try to get what we can.
        // For now return empty object is better than nullptr/void* mismatch.
        stats["status"] = "active";
    } else {
        stats["status"] = "inactive";
    }
    return stats; 
}

void IDEAgentBridgeWithHotPatching::setHotPatchingEnabled(bool enabled)
{
    if (m_hotPatchingEnabled == enabled) return;
    m_hotPatchingEnabled = enabled;
    if (m_hotPatcher) m_hotPatcher->setHotPatchingEnabled(enabled);
    if (enabled) startHotPatchingProxy(); else stopHotPatchingProxy();
}

void IDEAgentBridgeWithHotPatching::loadCorrectionPatterns(const std::string& databasePath)
{
    if (!m_hotPatcher) return;
    // Load patterns from SQLite database
    std::vector<CorrectionPatternRecord> patterns = 
        fetchCorrectionPatternsFromDb(databasePath);
    
    if (patterns.empty()) {
        // Log info: Using default patterns only
        return;
    }

    // Register patterns with the hot patcher
    int successCount = 0;
    for (const auto& rec : patterns) {
        try {
            // Log each pattern loaded
            HallucinationDetection hd;
            hd.detectionId = std::to_string(rec.id);
            hd.hallucinationType = rec.type;
            hd.detectedContent = rec.pattern;
            hd.confidence = rec.confidenceThreshold;
            m_hotPatcher->registerCorrectionPattern(hd);
            
            successCount++;
        } catch (const std::exception& ex) {
        }
    }
}

void IDEAgentBridgeWithHotPatching::loadBehaviorPatches(const std::string& databasePath)
{
    if (!m_hotPatcher) return;
    // Load patches from SQLite database
    std::vector<BehaviorPatchRecord> patches = 
        fetchBehaviorPatchesFromDb(databasePath);

    if (patches.empty()) {
        // Log info: Using default behaviors only
        return;
    }

    // Register patches with the hot patcher
    for (const auto& rec : patches) {
        try {
            BehaviorPatch p;
            p.patchId = std::to_string(rec.id);
            p.patchType = rec.patchType;
            
            try {
                auto j = json::parse(rec.payloadJson);
                p.condition = j.value("condition", "");
                p.action = j.value("action", "");
                p.affectedModels = j.value("affectedModels", std::vector<std::string>{});
                p.successRate = j.value("successRate", 0.0);
                p.enabled = j.value("enabled", true);
            } catch (...) {
                std::cerr << "Warning: Failed to parse payload JSON for patch " << rec.id << std::endl;
            }

            m_hotPatcher->createBehaviorPatch(p);
        } catch (const std::exception& ex) {
            std::cerr << "Error loading patch " << rec.id << ": " << ex.what() << std::endl;
        }
    }
}

void IDEAgentBridgeWithHotPatching::onHallucinationDetected(const HallucinationDetection& d) { logCorrection(d); }
void IDEAgentBridgeWithHotPatching::onHallucinationCorrected(const HallucinationDetection& c) { logCorrection(c); }
void IDEAgentBridgeWithHotPatching::onNavigationErrorFixed(const NavigationFix& f) { logNavigationFix(f); }
void IDEAgentBridgeWithHotPatching::onBehaviorPatchApplied(const BehaviorPatch& p) {}
void IDEAgentBridgeWithHotPatching::onModelInvokerReplaced() { if (m_hotPatchingEnabled) this->getModelInvoker()->setEndpoint("http://localhost:" + m_proxyPort); }
void IDEAgentBridgeWithHotPatching::proxyPortChanged() { if (m_proxyServer && m_proxyServer->isListening()) { stopHotPatchingProxy(); startHotPatchingProxy(); } }
void IDEAgentBridgeWithHotPatching::ggufEndpointChanged() { if (m_proxyServer && m_proxyServer->isListening()) { stopHotPatchingProxy(); startHotPatchingProxy(); } }

void IDEAgentBridgeWithHotPatching::logCorrection(const HallucinationDetection& c)
{
     static std::mutex logMutex;
    std::lock_guard<std::mutex> locker(logMutex);
    ensureLogDirectory();
    std::ofstream logFile("logs/corrections.log", std::ios::app);
    if (!logFile.is_open()) return;
    
    json j;
    j["timestamp"] = getCurrentTimeStr();
    j["id"] = c.detectionId;
    j["type"] = c.hallucinationType;
    j["original"] = c.detectedContent;
    j["corrected"] = c.expectedContent;
    j["confidence"] = c.confidence;
    
    logFile << j.dump() << std::endl;
}

void IDEAgentBridgeWithHotPatching::logNavigationFix(const NavigationFix& f)
{
     static std::mutex logMutex;
    std::lock_guard<std::mutex> locker(logMutex);
    ensureLogDirectory();
    std::ofstream logFile("logs/navigation_fixes.log", std::ios::app);
    if (!logFile.is_open()) return;
    
    json j;
    j["timestamp"] = getCurrentTimeStr();
    j["incorrect"] = f.incorrectPath;
    j["correct"] = f.correctPath;
    j["strategy"] = f.resolutionStrategy;
    
    logFile << j.dump() << std::endl;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
