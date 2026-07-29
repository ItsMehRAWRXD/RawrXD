// IDEDiagnosticAutoHealer.cpp - Autonomous IDE Self-Healing System Implementation
#include "IDEDiagnosticAutoHealer.h"
<<<<<<< HEAD
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>

// Forward declarations
typedef HRESULT (*DigestionEngineFunc)(const wchar_t*, const wchar_t*, void*);
=======
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <ctime>
#include <vector>

// Forward declarations
typedef HRESULT(*DigestionEngineFunc)(const wchar_t*, const wchar_t*, void*);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

<<<<<<< HEAD
IDEDiagnosticAutoHealer& IDEDiagnosticAutoHealer::Instance()
{
=======
IDEDiagnosticAutoHealer& IDEDiagnosticAutoHealer::Instance() {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    static IDEDiagnosticAutoHealer instance;
    return instance;
}

<<<<<<< HEAD
BeaconStorage& BeaconStorage::Instance()
{
=======
BeaconStorage& BeaconStorage::Instance() {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    static BeaconStorage instance;
    return instance;
}

// ============================================================================
// IDE DIAGNOSTIC AUTO-HEALER IMPLEMENTATION
// ============================================================================

<<<<<<< HEAD
void IDEDiagnosticAutoHealer::StartFullDiagnostic()
{
    if (m_running.exchange(true))
    {
        return;  // Already running
    }

    OutputDebugStringW(L"[AutoHealer] Starting full diagnostic sequence\n");

=======
void IDEDiagnosticAutoHealer::StartFullDiagnostic() {
    if (m_running.exchange(true)) {
        return;  // Already running
    }
    
    OutputDebugStringW(L"[AutoHealer] Starting full diagnostic sequence\n");
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    InitializeCriticalSection(&m_lock);
    m_idleEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_diagEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_healEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
<<<<<<< HEAD

=======
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    // Configure paths
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring basePath = exePath;
    basePath = basePath.substr(0, basePath.find_last_of(L"\\"));
<<<<<<< HEAD

=======
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    m_config.ideExePath = basePath + L"\\RawrXD-Win32IDE.exe";
    m_config.testFilePath = basePath + L"\\test_input.cpp";
    m_config.diagnosticReportPath = basePath + L"\\diagnostic_report.json";
    m_config.maxRetries = 3;
    m_config.timeoutMs = 10000;
    m_config.autoHealEnabled = true;
<<<<<<< HEAD

    // Start diagnostic thread
    m_diagnosticThread = std::make_unique<std::thread>([this]() { this->DiagnosticThreadProc(); });
}

void IDEDiagnosticAutoHealer::StopDiagnostic()
{
    m_running = false;

    if (m_diagnosticThread && m_diagnosticThread->joinable())
    {
        m_diagnosticThread->join();
    }

    if (m_idleEvent)
        CloseHandle(m_idleEvent);
    if (m_diagEvent)
        CloseHandle(m_diagEvent);
    if (m_healEvent)
        CloseHandle(m_healEvent);

    DeleteCriticalSection(&m_lock);

    OutputDebugStringW(L"[AutoHealer] Diagnostic stopped\n");
}

void IDEDiagnosticAutoHealer::DiagnosticThreadProc()
{
    OutputDebugStringW(L"[AutoHealer-Diag] Thread started\n");

    try
    {
        // STAGE 1: IDE LAUNCH
        EmitBeacon(BeaconStage::IDE_LAUNCH, S_OK, "Launching IDE process");
        HRESULT hr = ExecuteIDELaunch();
        if (FAILED(hr))
        {
=======
    
    // Start diagnostic thread
    m_diagnosticThread = std::make_unique<std::thread>([this]() {
        this->DiagnosticThreadProc();
    });
}

void IDEDiagnosticAutoHealer::StopDiagnostic() {
    m_running = false;
    
    if (m_diagnosticThread && m_diagnosticThread->joinable()) {
        m_diagnosticThread->join();
    }
    
    if (m_idleEvent) CloseHandle(m_idleEvent);
    if (m_diagEvent) CloseHandle(m_diagEvent);
    if (m_healEvent) CloseHandle(m_healEvent);
    
    DeleteCriticalSection(&m_lock);
    
    OutputDebugStringW(L"[AutoHealer] Diagnostic stopped\n");
}

void IDEDiagnosticAutoHealer::DiagnosticThreadProc() {
    OutputDebugStringW(L"[AutoHealer-Diag] Thread started\n");
    
    try {
        // STAGE 1: IDE LAUNCH
        EmitBeacon(BeaconStage::IDE_LAUNCH, S_OK, "Launching IDE process");
        HRESULT hr = ExecuteIDELaunch();
        if (FAILED(hr)) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            OutputDebugStringW(L"[AutoHealer-Diag] IDE launch failed, attempting heal\n");
            ApplyHealing(HealingStrategy::PROCESS_RESTART);
            return;
        }
<<<<<<< HEAD

        // STAGE 2: WINDOW CREATION
        Sleep(1000);  // Wait for window creation
        EmitBeacon(BeaconStage::WINDOW_CREATED, S_OK, "IDE window created");

        // Find main window
        m_ideMainWindow = DiagnosticUtils::FindIDEMainWindow(m_ideProcessId);
        if (!m_ideMainWindow)
        {
=======
        
        // STAGE 2: WINDOW CREATION
        Sleep(1000);  // Wait for window creation
        EmitBeacon(BeaconStage::WINDOW_CREATED, S_OK, "IDE window created");
        
        // Find main window
        m_ideMainWindow = DiagnosticUtils::FindIDEMainWindow(m_ideProcessId);
        if (!m_ideMainWindow) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
            OutputDebugStringW(L"[AutoHealer-Diag] Main window not found\n");
            ApplyHealing(HealingStrategy::WINDOW_REFOCUS);
            m_ideMainWindow = DiagnosticUtils::FindIDEMainWindow(m_ideProcessId);
        }
<<<<<<< HEAD

        if (!m_ideMainWindow)
        {
            EmitBeacon(BeaconStage::WINDOW_CREATED, E_HANDLE, "Window creation failed");
            return;
        }

        // STAGE 3: OPEN FILE
        Sleep(500);
        EmitBeacon(BeaconStage::FILE_OPENED, S_OK, "Opening test file");
        if (!DiagnosticUtils::OpenFileInEditor(m_ideMainWindow, m_config.testFilePath))
        {
            OutputDebugStringW(L"[AutoHealer-Diag] File open failed\n");
            ApplyHealing(HealingStrategy::FILE_REOPEN);
        }

=======
        
        if (!m_ideMainWindow) {
            EmitBeacon(BeaconStage::WINDOW_CREATED, E_HANDLE, "Window creation failed");
            return;
        }
        
        // STAGE 3: OPEN FILE
        Sleep(500);
        EmitBeacon(BeaconStage::FILE_OPENED, S_OK, "Opening test file");
        if (!DiagnosticUtils::OpenFileInEditor(m_ideMainWindow, m_config.testFilePath)) {
            OutputDebugStringW(L"[AutoHealer-Diag] File open failed\n");
            ApplyHealing(HealingStrategy::FILE_REOPEN);
        }
        
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        // STAGE 4: SEND HOTKEY
        Sleep(500);
        EmitBeacon(BeaconStage::HOTKEY_SENT, S_OK, "Sending Ctrl+Shift+D hotkey");
        SetFocus(m_ideMainWindow);
<<<<<<< HEAD

        if (!DiagnosticUtils::SendHotkey(m_ideMainWindow, 'D', true, true, false))
        {
            OutputDebugStringW(L"[AutoHealer-Diag] Hotkey send failed\n");
            ApplyHealing(HealingStrategy::HOTKEY_RESEND);
        }

=======
        
        if (!DiagnosticUtils::SendHotkey(m_ideMainWindow, 'D', true, true, false)) {
            OutputDebugStringW(L"[AutoHealer-Diag] Hotkey send failed\n");
            ApplyHealing(HealingStrategy::HOTKEY_RESEND);
        }
        
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        // STAGE 5: MONITOR COMPLETION
        EmitBeacon(BeaconStage::MESSAGE_RECEIVED, S_OK, "Waiting for digestion");
        DWORD startTime = GetTickCount();
        bool completed = false;
<<<<<<< HEAD

        while ((GetTickCount() - startTime) < m_config.timeoutMs && m_running)
        {
            // Check for digest output file
            if (DiagnosticUtils::VerifyDigestFileCreated(m_config.testFilePath))
            {
=======
        
        while ((GetTickCount() - startTime) < m_config.timeoutMs && m_running) {
            // Check for digest output file
            if (DiagnosticUtils::VerifyDigestFileCreated(m_config.testFilePath)) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
                EmitBeacon(BeaconStage::OUTPUT_VERIFIED, S_OK, "Digest file created");
                completed = true;
                break;
            }
            Sleep(100);
        }
<<<<<<< HEAD

        if (!completed)
        {
            OutputDebugStringW(L"[AutoHealer-Diag] Digestion timeout\n");
            EmitBeacon(BeaconStage::ENGINE_COMPLETE, WAIT_TIMEOUT, "Engine execution timeout");

            if (m_config.autoHealEnabled && m_healingAttempts < 3)
            {
                ApplyHealing(HealingStrategy::MESSAGE_REPOST);
            }
        }
        else
        {
            EmitBeacon(BeaconStage::SUCCESS, S_OK, "Full diagnostic cycle complete");
        }
    }
    catch (const std::exception& e)
    {
=======
        
        if (!completed) {
            OutputDebugStringW(L"[AutoHealer-Diag] Digestion timeout\n");
            EmitBeacon(BeaconStage::ENGINE_COMPLETE, WAIT_TIMEOUT, "Engine execution timeout");
            
            if (m_config.autoHealEnabled && m_healingAttempts < 3) {
                ApplyHealing(HealingStrategy::MESSAGE_REPOST);
            }
        } else {
            EmitBeacon(BeaconStage::SUCCESS, S_OK, "Full diagnostic cycle complete");
        }
        
    } catch (const std::exception& e) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        std::string errorMsg = std::string("[AutoHealer-Diag] Exception: ") + e.what();
        OutputDebugStringA(errorMsg.c_str());
    }
}

<<<<<<< HEAD
void IDEDiagnosticAutoHealer::EmitBeacon(BeaconStage stage, HRESULT result, const std::string& data)
{
    EnterCriticalSection(&m_lock);

=======
void IDEDiagnosticAutoHealer::EmitBeacon(BeaconStage stage, HRESULT result, const std::string& data) {
    EnterCriticalSection(&m_lock);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    BeaconCheckpoint checkpoint;
    checkpoint.stage = stage;
    checkpoint.timestamp = GetTickCount();
    checkpoint.result = result;
    checkpoint.diagnosticData = data;
<<<<<<< HEAD

    m_currentStage = stage;
    m_beaconHistory.push_back(checkpoint);

    BeaconStorage::Instance().SaveCheckpoint(stage, result, data);

    // Log beacon
    wchar_t beaconMsg[512];
    swprintf_s(beaconMsg, 512, L"[Beacon] Stage=%d, Result=0x%08X, Data=%hs\n", static_cast<int>(stage), result,
               data.c_str());
    OutputDebugStringW(beaconMsg);

    LeaveCriticalSection(&m_lock);
}

HRESULT IDEDiagnosticAutoHealer::ExecuteIDELaunch()
{
    OutputDebugStringW(L"[AutoHealer] Launching IDE process\n");

    m_ideProcessId = DiagnosticUtils::LaunchIDEProcess(m_config.ideExePath);

    if (m_ideProcessId == 0)
    {
        OutputDebugStringW(L"[AutoHealer] Failed to launch IDE\n");
        return static_cast<HRESULT>(0x80070001);  // E_PROCESS_CREATION_FAILED
    }

    wchar_t msg[256];
    swprintf_s(msg, 256, L"[AutoHealer] IDE launched with PID: %lu\n", m_ideProcessId);
    OutputDebugStringW(msg);

    return S_OK;
}

void IDEDiagnosticAutoHealer::ApplyHealing(HealingStrategy strategy)
{
    EnterCriticalSection(&m_lock);

    if (m_healingAttempts >= 5)
    {
=======
    
    m_currentStage = stage;
    m_beaconHistory.push_back(checkpoint);
    
    BeaconStorage::Instance().SaveCheckpoint(stage, result, data);
    
    // Log beacon
    wchar_t beaconMsg[512];
    swprintf_s(beaconMsg, 512, L"[Beacon] Stage=%d, Result=0x%08X, Data=%hs\n", 
               static_cast<int>(stage), result, data.c_str());
    OutputDebugStringW(beaconMsg);
    
    LeaveCriticalSection(&m_lock);
}

HRESULT IDEDiagnosticAutoHealer::ExecuteIDELaunch() {
    OutputDebugStringW(L"[AutoHealer] Launching IDE process\n");
    
    m_ideProcessId = DiagnosticUtils::LaunchIDEProcess(m_config.ideExePath);
    
    if (m_ideProcessId == 0) {
        OutputDebugStringW(L"[AutoHealer] Failed to launch IDE\n");
        return E_PROCESS_CREATION_FAILED;
    }
    
    wchar_t msg[256];
    swprintf_s(msg, 256, L"[AutoHealer] IDE launched with PID: %lu\n", m_ideProcessId);
    OutputDebugStringW(msg);
    
    return S_OK;
}

void IDEDiagnosticAutoHealer::ApplyHealing(HealingStrategy strategy) {
    EnterCriticalSection(&m_lock);
    
    if (m_healingAttempts >= 5) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        OutputDebugStringW(L"[AutoHealer] Max healing attempts reached\n");
        LeaveCriticalSection(&m_lock);
        return;
    }
<<<<<<< HEAD

    m_appliedHealings.push_back(strategy);
    m_healingAttempts++;

    LeaveCriticalSection(&m_lock);

    wchar_t msg[256];
    swprintf_s(msg, 256, L"[AutoHealer] Applying healing strategy: %d (attempt %d)\n", static_cast<int>(strategy),
               m_healingAttempts.load());
    OutputDebugStringW(msg);

    switch (strategy)
    {
=======
    
    m_appliedHealings.push_back(strategy);
    m_healingAttempts++;
    
    LeaveCriticalSection(&m_lock);
    
    wchar_t msg[256];
    swprintf_s(msg, 256, L"[AutoHealer] Applying healing strategy: %d (attempt %d)\n", 
               static_cast<int>(strategy), m_healingAttempts);
    OutputDebugStringW(msg);
    
    switch (strategy) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        case HealingStrategy::HOTKEY_RESEND:
            ExecuteHotkeyResend();
            break;
        case HealingStrategy::FILE_REOPEN:
            ExecuteFileReopen();
            break;
        case HealingStrategy::MESSAGE_REPOST:
            ExecuteMessageRepost();
            break;
        case HealingStrategy::WINDOW_REFOCUS:
            ExecuteWindowRefocus();
            break;
        case HealingStrategy::PROCESS_RESTART:
            ExecuteProcessRestart();
            break;
        default:
            break;
    }
}

<<<<<<< HEAD
void IDEDiagnosticAutoHealer::ExecuteHotkeyResend()
{
    OutputDebugStringW(L"[AutoHealer-Heal] Resending hotkey\n");
    Sleep(1000);
    if (m_ideMainWindow)
    {
=======
void IDEDiagnosticAutoHealer::ExecuteHotkeyResend() {
    OutputDebugStringW(L"[AutoHealer-Heal] Resending hotkey\n");
    Sleep(1000);
    if (m_ideMainWindow) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        SetFocus(m_ideMainWindow);
        DiagnosticUtils::SendHotkey(m_ideMainWindow, 'D', true, true, false);
    }
}

<<<<<<< HEAD
void IDEDiagnosticAutoHealer::ExecuteFileReopen()
{
    OutputDebugStringW(L"[AutoHealer-Heal] Reopening file\n");
    Sleep(500);
    if (m_ideMainWindow)
    {
=======
void IDEDiagnosticAutoHealer::ExecuteFileReopen() {
    OutputDebugStringW(L"[AutoHealer-Heal] Reopening file\n");
    Sleep(500);
    if (m_ideMainWindow) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        DiagnosticUtils::OpenFileInEditor(m_ideMainWindow, m_config.testFilePath);
    }
}

<<<<<<< HEAD
void IDEDiagnosticAutoHealer::ExecuteMessageRepost()
{
    OutputDebugStringW(L"[AutoHealer-Heal] Reposting digestion message\n");
    Sleep(500);
    if (m_ideMainWindow)
    {
=======
void IDEDiagnosticAutoHealer::ExecuteMessageRepost() {
    OutputDebugStringW(L"[AutoHealer-Heal] Reposting digestion message\n");
    Sleep(500);
    if (m_ideMainWindow) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        DiagnosticUtils::SendHotkey(m_ideMainWindow, 'D', true, true, false);
    }
}

<<<<<<< HEAD
void IDEDiagnosticAutoHealer::ExecuteWindowRefocus()
{
=======
void IDEDiagnosticAutoHealer::ExecuteWindowRefocus() {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    OutputDebugStringW(L"[AutoHealer-Heal] Refocusing window\n");
    SetForegroundWindow(m_ideMainWindow);
    Sleep(500);
}

<<<<<<< HEAD
void IDEDiagnosticAutoHealer::ExecuteProcessRestart()
{
=======
void IDEDiagnosticAutoHealer::ExecuteProcessRestart() {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    OutputDebugStringW(L"[AutoHealer-Heal] Restarting IDE process\n");
    DiagnosticUtils::TerminateProcessGracefully(m_ideProcessId);
    Sleep(1000);
    ExecuteIDELaunch();
}

<<<<<<< HEAD
std::string IDEDiagnosticAutoHealer::GenerateDiagnosticReport()
{
    EnterCriticalSection(&m_lock);

=======
std::string IDEDiagnosticAutoHealer::GenerateDiagnosticReport() {
    EnterCriticalSection(&m_lock);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::ostringstream report;
    report << "{\n";
    report << "  \"timestamp\": " << GetTickCount() << ",\n";
    report << "  \"totalBeacons\": " << static_cast<int>(m_beaconHistory.size()) << ",\n";
    report << "  \"healingAttempts\": " << m_healingAttempts << ",\n";
    report << "  \"beacons\": [\n";
<<<<<<< HEAD

    for (size_t i = 0; i < m_beaconHistory.size(); ++i)
    {
=======
    
    for (size_t i = 0; i < m_beaconHistory.size(); ++i) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        const auto& checkpoint = m_beaconHistory[i];
        report << "    {\n";
        report << "      \"stage\": " << static_cast<int>(checkpoint.stage) << ",\n";
        report << "      \"timestamp\": " << checkpoint.timestamp << ",\n";
        report << "      \"result\": " << static_cast<int>(checkpoint.result) << ",\n";
        report << "      \"data\": \"" << checkpoint.diagnosticData << "\"\n";
        report << "    }";
<<<<<<< HEAD
        if (i < m_beaconHistory.size() - 1)
            report << ",";
        report << "\n";
    }

    report << "  ],\n";
    report << "  \"appliedHealings\": [\n";

    for (size_t i = 0; i < m_appliedHealings.size(); ++i)
    {
        report << "    " << static_cast<int>(m_appliedHealings[i]);
        if (i < m_appliedHealings.size() - 1)
            report << ",";
        report << "\n";
    }

    report << "  ]\n";
    report << "}\n";

    LeaveCriticalSection(&m_lock);

=======
        if (i < m_beaconHistory.size() - 1) report << ",";
        report << "\n";
    }
    
    report << "  ],\n";
    report << "  \"appliedHealings\": [\n";
    
    for (size_t i = 0; i < m_appliedHealings.size(); ++i) {
        report << "    " << static_cast<int>(m_appliedHealings[i]);
        if (i < m_appliedHealings.size() - 1) report << ",";
        report << "\n";
    }
    
    report << "  ]\n";
    report << "}\n";
    
    LeaveCriticalSection(&m_lock);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return report.str();
}

// ============================================================================
// BEACON STORAGE IMPLEMENTATION
// ============================================================================

<<<<<<< HEAD
void BeaconStorage::SaveCheckpoint(BeaconStage stage, HRESULT result, const std::string& data)
{
    EnterCriticalSection(&m_lock);

=======
void BeaconStorage::SaveCheckpoint(BeaconStage stage, HRESULT result, const std::string& data) {
    EnterCriticalSection(&m_lock);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    BeaconCheckpoint checkpoint;
    checkpoint.stage = stage;
    checkpoint.timestamp = GetTickCount();
    checkpoint.result = result;
    checkpoint.diagnosticData = data;
<<<<<<< HEAD

    m_checkpoints.push_back(checkpoint);

    // Write to file
    std::wstring filePath = GetBeaconFilePath();
    std::wofstream file(filePath.c_str(), std::ios::app);
    if (file.is_open())
    {
        file << L"[" << std::chrono::system_clock::now().time_since_epoch().count() << L"] " << L"Stage="
             << static_cast<int>(stage) << L" Result=0x" << std::hex << result << L"\n";
        file.close();
    }

    LeaveCriticalSection(&m_lock);
}

BeaconCheckpoint BeaconStorage::LoadLastCheckpoint()
{
    EnterCriticalSection(&m_lock);

    BeaconCheckpoint result{};
    if (!m_checkpoints.empty())
    {
        result = m_checkpoints.back();
    }

=======
    
    m_checkpoints.push_back(checkpoint);
    
    // Write to file
    std::wstring filePath = GetBeaconFilePath();
    std::wofstream file(filePath, std::ios::app);
    if (file.is_open()) {
        file << L"[" << std::chrono::system_clock::now().time_since_epoch().count() << L"] "
             << L"Stage=" << static_cast<int>(stage) << L" Result=0x" << std::hex << result << L"\n";
        file.close();
    }
    
    LeaveCriticalSection(&m_lock);
}

BeaconCheckpoint BeaconStorage::LoadLastCheckpoint() {
    EnterCriticalSection(&m_lock);
    
    BeaconCheckpoint result{};
    if (!m_checkpoints.empty()) {
        result = m_checkpoints.back();
    }
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    LeaveCriticalSection(&m_lock);
    return result;
}

<<<<<<< HEAD
std::wstring BeaconStorage::GetBeaconFilePath() const
{
=======
std::wstring BeaconStorage::GetBeaconFilePath() const {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring result = tempPath;
    result += L"ide_beacon.log";
    return result;
}

// ============================================================================
// DIAGNOSTIC UTILS IMPLEMENTATION
// ============================================================================

<<<<<<< HEAD
namespace DiagnosticUtils
{

static std::string wideToUtf8(const std::wstring& w)
{
    if (w.empty())
    {
        return {};
    }
    const int len = static_cast<int>(w.size());
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), len, nullptr, 0, nullptr, nullptr);
    if (n <= 0)
    {
        return {};
    }
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), len, out.data(), n, nullptr, nullptr);
    return out;
}

DWORD LaunchIDEProcess(const std::wstring& exePath)
{
=======
namespace DiagnosticUtils {

DWORD LaunchIDEProcess(const std::wstring& exePath) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
<<<<<<< HEAD

    PROCESS_INFORMATION pi = {};

    if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
    {
        OutputDebugStringW(L"[DiagnosticUtils] CreateProcess failed\n");
        return 0;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return pi.dwProcessId;
}

bool TerminateProcessGracefully(DWORD processId)
{
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (!process)
    {
        return false;
    }

    bool result = TerminateProcess(process, 0) != FALSE;
    CloseHandle(process);

    return result;
}

HWND FindIDEMainWindow(DWORD processId)
{
    struct FindWindowData
    {
        DWORD targetPID;
        HWND result;
    } data = {processId, nullptr};

    EnumWindows(
        [](HWND hwnd, LPARAM lParam) -> BOOL
        {
            auto* data = reinterpret_cast<FindWindowData*>(lParam);
            DWORD pid;
            GetWindowThreadProcessId(hwnd, &pid);

            if (pid == data->targetPID && IsWindowVisible(hwnd))
            {
                wchar_t className[256];
                GetClassNameW(hwnd, className, sizeof(className) / sizeof(wchar_t));

                // Check if it's the main IDE window
                if (wcscmp(className, L"IDEMainWindow") == 0 || wcscmp(className, L"RawrXD_IDE") == 0)
                {
                    data->result = hwnd;
                    return FALSE;  // Stop enumeration
                }
            }

            return TRUE;  // Continue enumeration
        },
        reinterpret_cast<LPARAM>(&data));

    return data.result;
}

bool SendHotkey(HWND hwnd, UINT vk, bool ctrl, bool shift, bool alt)
{
    BYTE keyState[256];
    GetKeyboardState(keyState);

    // Save original state
    BYTE originalState[256];
    memcpy(originalState, keyState, sizeof(keyState));

    // Set modifier keys
    if (ctrl)
        keyState[VK_CONTROL] = 0x80;
    if (shift)
        keyState[VK_SHIFT] = 0x80;
    if (alt)
        keyState[VK_MENU] = 0x80;

    SetKeyboardState(keyState);

    // Simulate key press
    PostMessageW(hwnd, WM_KEYDOWN, vk, 0);
    Sleep(50);
    PostMessageW(hwnd, WM_KEYUP, vk, 0);

    // Restore original state
    SetKeyboardState(originalState);

    return true;
}

bool OpenFileInEditor(HWND hwnd, const std::wstring& filePath)
{
    // Simulate Ctrl+O (Open file dialog)
    PostMessageW(hwnd, WM_KEYDOWN, 'O', 0);
    PostMessageW(hwnd, WM_CHAR, 'O', 0);
    PostMessageW(hwnd, WM_KEYUP, 'O', 0);

    Sleep(500);

    // Send file path to dialog (simulated)
    for (wchar_t c : filePath)
    {
        PostMessageW(hwnd, WM_CHAR, c, 0);
    }

    // Simulate Enter
    PostMessageW(hwnd, WM_KEYDOWN, VK_RETURN, 0);
    PostMessageW(hwnd, WM_KEYUP, VK_RETURN, 0);

    return true;
}

bool VerifyDigestFileCreated(const std::wstring& sourceFile)
{
    std::wstring digestPath = sourceFile + L".digest";

    WIN32_FIND_DATAW findData;
    HANDLE findHandle = FindFirstFileW(digestPath.c_str(), &findData);

    if (findHandle != INVALID_HANDLE_VALUE)
    {
        FindClose(findHandle);
        return true;
    }

    return false;
}

std::string ReadDigestFile(const std::wstring& sourceFile)
{
    std::wstring digestPath = sourceFile + L".digest";

    std::wifstream file(digestPath.c_str());
    if (!file.is_open())
    {
        return "";
    }

    std::wstringstream buffer;
    buffer << file.rdbuf();

    const std::wstring wContent = buffer.str();
    return wideToUtf8(wContent);
}

void LogDiagnostic(const std::string& message)
{
=======
    
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr, FALSE, 0, 
                        nullptr, nullptr, &si, &pi)) {
        OutputDebugStringW(L"[DiagnosticUtils] CreateProcess failed\n");
        return 0;
    }
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return pi.dwProcessId;
}

bool TerminateProcessGracefully(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (!process) {
        return false;
    }
    
    bool result = TerminateProcess(process, 0) != FALSE;
    CloseHandle(process);
    
    return result;
}

HWND FindIDEMainWindow(DWORD processId) {
    struct FindWindowData {
        DWORD targetPID;
        HWND result;
    } data = {processId, nullptr};
    
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* data = reinterpret_cast<FindWindowData*>(lParam);
        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        
        if (pid == data->targetPID && IsWindowVisible(hwnd)) {
            wchar_t className[256];
            GetClassNameW(hwnd, className, sizeof(className) / sizeof(wchar_t));
            
            // Check if it's the main IDE window
            if (wcscmp(className, L"IDEMainWindow") == 0 || wcscmp(className, L"RawrXD_IDE") == 0) {
                data->result = hwnd;
                return FALSE;  // Stop enumeration
            }
        }
        
        return TRUE;  // Continue enumeration
    }, reinterpret_cast<LPARAM>(&data));
    
    return data.result;
}

bool SendHotkey(HWND hwnd, UINT vk, bool ctrl, bool shift, bool alt) {
    BYTE keyState[256];
    GetKeyboardState(keyState);
    
    // Save original state
    BYTE originalState[256];
    memcpy(originalState, keyState, sizeof(keyState));
    
    // Set modifier keys
    if (ctrl) keyState[VK_CONTROL] = 0x80;
    if (shift) keyState[VK_SHIFT] = 0x80;
    if (alt) keyState[VK_MENU] = 0x80;
    
    SetKeyboardState(keyState);
    
    // Real implementation
    SendKeyInput(vk, true);
    Sleep(50);
    SendKeyInput(vk, false);
    
    // Restore original state
    SetKeyboardState(originalState);
    
    return true;
}

void SendKeyInput(WORD vk, bool down) {
    INPUT input = { 0 };
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = vk;
    input.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
    SendInput(1, &input, sizeof(INPUT));
}

bool OpenFileInEditor(HWND hwnd, const std::wstring& filePath) {
    // Real logic using SendInput for Ctrl+O interaction
    // Note: PostMessage is often insufficient for hotkeys handled at low level or by specific frameworks
    // But assuming the app handles WM_KEYDOWN specifically for shortcuts:
    
    // Set Foreground to ensure input goes to window
    SetForegroundWindow(hwnd);
    Sleep(100);

    // Ctrl Down
    SendKeyInput(VK_CONTROL, true);
    // O Down/Up
    SendKeyInput('O', true);
    SendKeyInput('O', false);
    // Ctrl Up
    SendKeyInput(VK_CONTROL, false);
    
    Sleep(1000); // Wait for dialog

    // We can't easily find the dialog hwnd blindly without EnumWindows, 
    // but assuming standard dialog, it keeps focus. 
    // Type path.
    for (wchar_t c : filePath) {
        // Simple char entry. For complex paths/non-ascii, clipboard paste is safer,
        // but this removes the "Simulate" placeholder with real input events.
        INPUT input = { 0 };
        input.type = INPUT_KEYBOARD;
        input.ki.wScan = c;
        input.ki.dwFlags = KEYEVENTF_UNICODE;
        SendInput(1, &input, sizeof(INPUT));
        
        input.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        SendInput(1, &input, sizeof(INPUT));
    }
    
    Sleep(100);
    
    // Enter
    SendKeyInput(VK_RETURN, true);
    SendKeyInput(VK_RETURN, false);
    
    return true;
}

bool VerifyDigestFileCreated(const std::wstring& sourceFile) {
    std::wstring digestPath = sourceFile + L".digest";
    
    WIN32_FIND_DATAW findData;
    HANDLE findHandle = FindFirstFileW(digestPath.c_str(), &findData);
    
    if (findHandle != INVALID_HANDLE_VALUE) {
        FindClose(findHandle);
        return true;
    }
    
    return false;
}

std::string ReadDigestFile(const std::wstring& sourceFile) {
    std::wstring digestPath = sourceFile + L".digest";
    
    std::wifstream file(digestPath);
    if (!file.is_open()) {
        return "";
    }
    
    std::wstringstream buffer;
    buffer << file.rdbuf();
    
    std::wstring wContent = buffer.str();
    std::string content(wContent.begin(), wContent.end());
    
    return content;
}

void LogDiagnostic(const std::string& message) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    std::string formatted = "[Diagnostic] " + message + "\n";
    OutputDebugStringA(formatted.c_str());
}

<<<<<<< HEAD
void LogHealing(const std::string& action, bool success)
{
    std::string formatted = std::string("[Healing] ") + action + " - " + (success ? "SUCCESS" : "FAILED") + "\n";
=======
void LogHealing(const std::string& action, bool success) {
    std::string formatted = std::string("[Healing] ") + action + " - " + 
                           (success ? "SUCCESS" : "FAILED") + "\n";
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    OutputDebugStringA(formatted.c_str());
}

}  // namespace DiagnosticUtils
<<<<<<< HEAD
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
