#include "Win32IDE_Autonomy.h"
#include <sstream>
#include <fstream>
#include <filesystem>
#include <array>
#include <algorithm>
#include <cctype>

namespace {
std::string trimCopy(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}
}

AutonomyManager::AutonomyManager(AgenticBridge* bridge)
    : m_bridge(bridge), m_running(false), m_autoLoop(false),
      m_maxActionsPerMinute(30), m_actionsThisWindow(0) {
    m_windowStart = std::chrono::steady_clock::now();
        m_lastActionTs = m_windowStart;
        loadAutonomyCriteria();
    LOG_INFO("AutonomyManager constructed");
}

AutonomyManager::~AutonomyManager() {
    stop();
    LOG_INFO("AutonomyManager destroyed");
}

void AutonomyManager::start() {
    if (m_running.load()) {
        return;
    }
    m_running.store(true);
    m_lastError.clear();
    LOG_INFO("Autonomy started");
}

void AutonomyManager::stop() {
    m_autoLoop.store(false);
    if (m_loopThread.joinable()) {
        m_loopThread.join();
    }
    if (m_running.load()) {
        m_running.store(false);
    }
    LOG_INFO("Autonomy stopped");
}

void AutonomyManager::enableAutoLoop(bool enable) {
    if (enable && !m_autoLoop.load()) {
        if (!m_running.load()) start();
        if (m_loopThread.joinable()) {
            m_loopThread.join();
        }
        m_autoLoop.store(true);
        m_loopThread = std::thread([this]{ loop(); });
        LOG_INFO("Autonomy auto loop enabled");
    } else if (!enable && m_autoLoop.load()) {
        m_autoLoop.store(false);
        if (m_loopThread.joinable()) {
            m_loopThread.join();
        }
        LOG_INFO("Autonomy auto loop disabled");
    }
}

void AutonomyManager::setGoal(const std::string& goal) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_goal = sanitizeGoal(goal);
    LOG_INFO("Goal set: " + m_goal);
}

std::string AutonomyManager::getGoal() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_goal;
}

void AutonomyManager::addObservation(const std::string& obs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_memory.push_back(obs);
    if (m_memory.size() > 2048) {
        m_memory.erase(m_memory.begin()); // simple cap
    }
    LOG_DEBUG("Observation added");
}

std::vector<std::string> AutonomyManager::getMemorySnapshot() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_memory;
}

void AutonomyManager::tick() {
    if (!m_running.load()) return;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_totalTicks;
    }
    if (!rateLimitAllow()) {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_skippedTicks;
        LOG_WARNING("Rate limit hit, skipping tick");
        return;
    }
    std::string action = planNextAction();
    executeAction(action);
}

std::string AutonomyManager::getStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::ostringstream oss;
    const auto idleMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - m_lastActionTs).count();
    const char* maturity = m_criteriaDefined ? "criteria-gated" : "unlabeled";
    oss << "running=" << (m_running.load() ? "true" : "false")
        << " autoLoop=" << (m_autoLoop.load() ? "true" : "false")
        << " goal='" << m_goal << "' memoryItems=" << m_memory.size()
        << " actionsWindow=" << m_actionsThisWindow << "/" << m_maxActionsPerMinute
        << " maturity=" << maturity
        << " criteriaPath='" << m_criteriaPath << "'"
        << " totalTicks=" << m_totalTicks
        << " skippedTicks=" << m_skippedTicks
        << " failedActions=" << m_failedActions
        << " lastAction='" << m_lastAction << "'"
        << " lastError='" << m_lastError << "'"
        << " idleMs=" << idleMs;
    return oss.str();
}

void AutonomyManager::loop() {
    LOG_INFO("Autonomy loop thread started");
    while (m_autoLoop.load()) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
    }
    LOG_INFO("Autonomy loop thread exiting");
}

std::string AutonomyManager::planNextAction() {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Extremely naive planner: if no goal -> idle
    if (m_goal.empty()) {
        return "NOOP";
    }
    // Example heuristic: examine memory size to decide next step
    if (m_memory.empty()) {
        return "tool:list_dir path=."; // gather context
    }
    // After some memory items, attempt summarization (placeholder prompt)
    if (m_memory.size() % 5 == 0) {
        return "prompt: Summarize recent observations concisely.";
    }
    return "prompt: Reflect on goal and propose next file to inspect.";
}

void AutonomyManager::executeAction(const std::string& action) {
    if (action == "NOOP") {
        LOG_DEBUG("Planner produced NOOP");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastAction = action;
        m_lastActionTs = std::chrono::steady_clock::now();
    }
    if (!m_bridge || !m_bridge->IsInitialized()) {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_failedActions;
        m_lastError = "Bridge not initialized";
        LOG_WARNING("Bridge not initialized; cannot execute action: " + action);
        return;
    }
    // Differentiate tool vs prompt
    if (action.rfind("tool:", 0) == 0) {
        std::string toolCall = action.substr(5);
        auto resp = m_bridge->ExecuteAgentCommand(toolCall);
        if (resp.content.empty()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_failedActions;
            m_lastError = "Empty tool response";
        } else {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_lastError.clear();
        }
        addObservation("TOOL:" + toolCall + " => " + resp.content);
    } else if (action.rfind("prompt:", 0) == 0) {
        std::string prompt = action.substr(7);
        auto resp = m_bridge->ExecuteAgentCommand(prompt);
        if (resp.content.empty()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_failedActions;
            m_lastError = "Empty prompt response";
        } else {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_lastError.clear();
        }
        addObservation("ANSWER:" + resp.content);
    } else {
        auto resp = m_bridge->ExecuteAgentCommand(action);
        if (resp.content.empty()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            ++m_failedActions;
            m_lastError = "Empty raw response";
        } else {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_lastError.clear();
        }
        addObservation("RAW:" + resp.content);
    }
    LOG_INFO("Executed autonomy action: " + action);
}

bool AutonomyManager::rateLimitAllow() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_windowStart).count();
    if (elapsed >= 60) {
        m_windowStart = now;
        m_actionsThisWindow = 0;
    }
    if (m_actionsThisWindow >= m_maxActionsPerMinute) {
        return false;
    }
    ++m_actionsThisWindow;
    return true;
}

bool AutonomyManager::loadAutonomyCriteria() {
    namespace fs = std::filesystem;
    if (m_criteriaLoaded) {
        return m_criteriaDefined;
    }

    m_criteriaLoaded = true;
    const fs::path base = fs::current_path();
    const fs::path direct = base / "autonomy_criteria.json";
    const fs::path configPath = base / "config" / "autonomy_criteria.json";
    const fs::path docsPath = base / "docs" / "autonomy_criteria.json";

    std::array<fs::path, 3> candidates = { direct, configPath, docsPath };
    for (const auto& p : candidates) {
        if (!fs::exists(p)) {
            continue;
        }
        std::ifstream f(p.string());
        if (!f) {
            continue;
        }
        std::stringstream ss;
        ss << f.rdbuf();
        const std::string body = ss.str();
        if (body.find("criteria") != std::string::npos ||
            body.find("requirements") != std::string::npos ||
            body.find("maturity") != std::string::npos) {
            m_criteriaDefined = true;
            m_criteriaPath = p.string();
            return true;
        }
    }

    m_criteriaDefined = false;
    m_criteriaPath = "(none)";
    return false;
}

std::string AutonomyManager::sanitizeGoal(const std::string& goal) {
    std::string out = trimCopy(goal);
    constexpr size_t kMaxGoal = 512;
    if (out.size() > kMaxGoal) {
        out.resize(kMaxGoal);
    }
    return out;
}
