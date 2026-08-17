#include "../include/shared_context.h"
#include <windows.h>
#include <psapi.h>
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "psapi.lib")

GlobalContext& GlobalContext::Get() {
    static GlobalContext instance;
    return instance;
}

GlobalContext::GlobalContext() 
    : m_initialized(false)
    , m_sessionStartTime(std::chrono::steady_clock::now())
    , m_peakMemoryBytes(0)
    , m_totalRequestsProcessed(0)
    , m_errorCount(0) {
    InitializeCriticalSection(&m_cs);
}

GlobalContext::~GlobalContext() {
    DeleteCriticalSection(&m_cs);
}

bool GlobalContext::Initialize() {
    EnterCriticalSection(&m_cs);
    if (!m_initialized) {
        m_initialized = true;
        m_sessionId = GenerateSessionId();
        UpdateMemoryStats();
    }
    LeaveCriticalSection(&m_cs);
    return true;
}

void GlobalContext::Shutdown() {
    EnterCriticalSection(&m_cs);
    m_initialized = false;
    m_activeEditors.clear();
    m_openFiles.clear();
    LeaveCriticalSection(&m_cs);
}

bool GlobalContext::IsInitialized() const {
    return m_initialized;
}

std::string GlobalContext::GetSessionId() const {
    return m_sessionId;
}

void GlobalContext::RegisterEditor(void* editorHandle, const std::string& filePath) {
    EnterCriticalSection(&m_cs);
    m_activeEditors[editorHandle] = filePath;
    LeaveCriticalSection(&m_cs);
}

void GlobalContext::UnregisterEditor(void* editorHandle) {
    EnterCriticalSection(&m_cs);
    m_activeEditors.erase(editorHandle);
    LeaveCriticalSection(&m_cs);
}

std::string GlobalContext::GetEditorFile(void* editorHandle) const {
    EnterCriticalSection(&m_cs);
    auto it = m_activeEditors.find(editorHandle);
    std::string result = (it != m_activeEditors.end()) ? it->second : "";
    LeaveCriticalSection(&m_cs);
    return result;
}

void GlobalContext::OpenFile(const std::string& filePath) {
    EnterCriticalSection(&m_cs);
    m_openFiles.insert(filePath);
    m_recentFiles.push_front(filePath);
    if (m_recentFiles.size() > 20) {
        m_recentFiles.pop_back();
    }
    LeaveCriticalSection(&m_cs);
}

void GlobalContext::CloseFile(const std::string& filePath) {
    EnterCriticalSection(&m_cs);
    m_openFiles.erase(filePath);
    LeaveCriticalSection(&m_cs);
}

bool GlobalContext::IsFileOpen(const std::string& filePath) const {
    EnterCriticalSection(&m_cs);
    bool result = m_openFiles.count(filePath) > 0;
    LeaveCriticalSection(&m_cs);
    return result;
}

std::vector<std::string> GlobalContext::GetRecentFiles() const {
    EnterCriticalSection(&m_cs);
    std::vector<std::string> result(m_recentFiles.begin(), m_recentFiles.end());
    LeaveCriticalSection(&m_cs);
    return result;
}

void GlobalContext::UpdateMemoryStats() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        m_peakMemoryBytes = pmc.PeakWorkingSetSize;
        m_currentMemoryBytes = pmc.WorkingSetSize;
    }
}

size_t GlobalContext::GetCurrentMemoryUsage() const {
    return m_currentMemoryBytes.load();
}

size_t GlobalContext::GetPeakMemoryUsage() const {
    return m_peakMemoryBytes.load();
}

void GlobalContext::IncrementRequestCount() {
    ++m_totalRequestsProcessed;
}

uint64_t GlobalContext::GetTotalRequests() const {
    return m_totalRequestsProcessed.load();
}

void GlobalContext::IncrementErrorCount() {
    ++m_errorCount;
}

uint64_t GlobalContext::GetErrorCount() const {
    return m_errorCount.load();
}

std::string GlobalContext::GenerateSessionId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::stringstream ss;
    ss << "RXD-" << std::hex << ms << "-" << GetCurrentProcessId();
    return ss.str();
}

std::chrono::steady_clock::time_point GlobalContext::GetSessionStartTime() const {
    return m_sessionStartTime;
}

uint64_t GlobalContext::GetUptimeSeconds() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now - m_sessionStartTime).count();
}
