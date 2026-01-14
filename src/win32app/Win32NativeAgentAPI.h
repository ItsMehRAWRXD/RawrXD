#pragma once

/**
 * @file Win32NativeAgentAPI.h
 * @brief Native Win32 API access layer for Agentic and Autonomous engines
 * 
 * This module provides FULL Win32 API integration for the IDE's agentic capabilities:
 * - Process management (CreateProcess, TerminateProcess, process enumeration)
 * - Thread management (CreateThread, thread pool, synchronization)
 * - Memory operations (VirtualAlloc, VirtualFree, heap management)
 * - File system operations (native file I/O, directory traversal)
 * - Registry access (read/write registry keys)
 * - Service control (service enumeration, start/stop)
 * - System information (hardware info, OS version)
 * - Inter-process communication (pipes, shared memory)
 * - Window management (enumeration, manipulation)
 * - Network operations (socket wrappers)
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsvc.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <unordered_map>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

namespace RawrXD {
namespace Win32Agent {

// ============================================================================
// PROCESS MANAGEMENT
// ============================================================================

struct ProcessInfo {
    DWORD processId;
    DWORD parentProcessId;
    std::wstring processName;
    std::wstring executablePath;
    SIZE_T workingSetSize;
    SIZE_T privateBytes;
    DWORD threadCount;
    DWORD handleCount;
    double cpuUsage;
    FILETIME creationTime;
    bool isElevated;
};

struct ProcessCreateParams {
    std::wstring executablePath;
    std::wstring arguments;
    std::wstring workingDirectory;
    bool createNewConsole = false;
    bool inheritHandles = false;
    bool hiddenWindow = false;
    bool suspended = false;
    DWORD priority = NORMAL_PRIORITY_CLASS;
    std::vector<std::pair<std::wstring, std::wstring>> environment;
};

struct ProcessCreateResult {
    bool success;
    DWORD processId;
    DWORD threadId;
    HANDLE hProcess;
    HANDLE hThread;
    std::wstring errorMessage;
    DWORD exitCode;
};

class ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();
    
    // Process creation
    ProcessCreateResult CreateProcessEx(const ProcessCreateParams& params);
    ProcessCreateResult ExecuteCommand(const std::wstring& command, bool waitForCompletion = false, DWORD timeoutMs = INFINITE);
    ProcessCreateResult ExecutePowerShell(const std::wstring& script, bool waitForCompletion = true);
    ProcessCreateResult ExecuteCommandWithPipes(const std::wstring& command, std::wstring& stdOut, std::wstring& stdErr, DWORD timeoutMs = 30000);
    
    // Process control
    bool TerminateProcess(DWORD processId, DWORD exitCode = 0);
    bool SuspendProcess(DWORD processId);
    bool ResumeProcess(DWORD processId);
    bool SetProcessPriority(DWORD processId, DWORD priority);
    bool InjectDll(DWORD processId, const std::wstring& dllPath);
    
    // Process enumeration
    std::vector<ProcessInfo> EnumerateProcesses();
    ProcessInfo GetProcessInfo(DWORD processId);
    std::vector<DWORD> FindProcessesByName(const std::wstring& name);
    bool IsProcessRunning(DWORD processId);
    bool WaitForProcess(DWORD processId, DWORD timeoutMs = INFINITE);
    DWORD GetProcessExitCode(DWORD processId);
    
    // Process memory
    SIZE_T GetProcessMemoryUsage(DWORD processId);
    bool ReadProcessMemory(DWORD processId, LPVOID address, void* buffer, SIZE_T size);
    bool WriteProcessMemory(DWORD processId, LPVOID address, const void* buffer, SIZE_T size);
    
private:
    std::unordered_map<DWORD, HANDLE> m_processHandles;
    std::mutex m_mutex;
    
    void CleanupHandle(DWORD processId);
    void ReadPipeOutput(HANDLE pipe, std::wstring& output, DWORD timeoutMs);
};

// ============================================================================
// THREAD MANAGEMENT
// ============================================================================

struct ThreadInfo {
    DWORD threadId;
    DWORD ownerProcessId;
    int basePriority;
    int deltaPriority;
    bool suspended;
};

using ThreadCallback = std::function<DWORD(void*)>;

class ThreadManager {
public:
    ThreadManager();
    ~ThreadManager();
    
    // Thread creation
    HANDLE CreateThread(ThreadCallback callback, void* param = nullptr, bool suspended = false);
    HANDLE CreateThreadPoolWork(ThreadCallback callback, void* param = nullptr);
    
    // Thread control
    bool SuspendThread(HANDLE hThread);
    bool ResumeThread(HANDLE hThread);
    bool TerminateThread(HANDLE hThread, DWORD exitCode = 0);
    bool SetThreadPriority(HANDLE hThread, int priority);
    DWORD WaitForThread(HANDLE hThread, DWORD timeoutMs = INFINITE);
    
    // Thread enumeration
    std::vector<ThreadInfo> EnumerateThreads(DWORD processId = 0);
    
    // Synchronization primitives
    HANDLE CreateMutex(const std::wstring& name = L"", bool initialOwner = false);
    HANDLE CreateEvent(const std::wstring& name = L"", bool manualReset = false, bool initialState = false);
    HANDLE CreateSemaphore(const std::wstring& name = L"", LONG initialCount = 0, LONG maxCount = 1);
    
    // Wait functions
    DWORD WaitForSingleObject(HANDLE hObject, DWORD timeoutMs = INFINITE);
    DWORD WaitForMultipleObjects(const std::vector<HANDLE>& handles, bool waitAll, DWORD timeoutMs = INFINITE);
    
private:
    std::vector<HANDLE> m_threads;
    std::vector<HANDLE> m_syncObjects;
    std::mutex m_mutex;
    
    static DWORD WINAPI ThreadProc(LPVOID param);
    
    struct ThreadContext {
        ThreadCallback callback;
        void* param;
    };
};

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

struct MemoryInfo {
    SIZE_T totalPhysical;
    SIZE_T availablePhysical;
    SIZE_T totalVirtual;
    SIZE_T availableVirtual;
    SIZE_T totalPageFile;
    SIZE_T availablePageFile;
    DWORD memoryLoad;
};

class MemoryManager {
public:
    MemoryManager();
    ~MemoryManager();
    
    // Virtual memory
    void* VirtualAlloc(SIZE_T size, DWORD allocationType = MEM_COMMIT | MEM_RESERVE, DWORD protection = PAGE_READWRITE);
    bool VirtualFree(void* address, SIZE_T size = 0, DWORD freeType = MEM_RELEASE);
    bool VirtualProtect(void* address, SIZE_T size, DWORD newProtection, DWORD* oldProtection);
    
    // Heap management
    HANDLE CreateHeap(SIZE_T initialSize = 0, SIZE_T maxSize = 0);
    void* HeapAlloc(HANDLE hHeap, SIZE_T size);
    bool HeapFree(HANDLE hHeap, void* address);
    bool DestroyHeap(HANDLE hHeap);
    
    // Memory-mapped files
    HANDLE CreateFileMapping(HANDLE hFile, SIZE_T size, const std::wstring& name = L"", DWORD protection = PAGE_READWRITE);
    void* MapViewOfFile(HANDLE hMapping, SIZE_T offset = 0, SIZE_T size = 0, DWORD access = FILE_MAP_ALL_ACCESS);
    bool UnmapViewOfFile(void* address);
    
    // System memory info
    MemoryInfo GetSystemMemoryInfo();
    SIZE_T GetProcessMemoryUsage();
    
private:
    std::vector<void*> m_virtualAllocations;
    std::vector<HANDLE> m_heaps;
    std::vector<HANDLE> m_mappings;
    std::vector<void*> m_mappedViews;
    std::mutex m_mutex;
};

// ============================================================================
// FILE SYSTEM OPERATIONS
// ============================================================================

struct FileInfo {
    std::wstring name;
    std::wstring fullPath;
    DWORD attributes;
    ULONGLONG size;
    FILETIME creationTime;
    FILETIME lastAccessTime;
    FILETIME lastWriteTime;
    bool isDirectory;
    bool isHidden;
    bool isReadOnly;
    bool isSystem;
};

struct DriveInfo {
    std::wstring drivePath;
    std::wstring volumeName;
    std::wstring fileSystemName;
    DWORD serialNumber;
    ULONGLONG totalBytes;
    ULONGLONG freeBytes;
    ULONGLONG availableBytes;
    UINT driveType;
};

class FileSystemManager {
public:
    FileSystemManager();
    ~FileSystemManager();
    
    // File operations
    HANDLE CreateFile(const std::wstring& path, DWORD desiredAccess, DWORD shareMode, DWORD creationDisposition);
    bool ReadFile(HANDLE hFile, void* buffer, DWORD bytesToRead, DWORD* bytesRead);
    bool WriteFile(HANDLE hFile, const void* buffer, DWORD bytesToWrite, DWORD* bytesWritten);
    bool DeleteFile(const std::wstring& path);
    bool CopyFile(const std::wstring& source, const std::wstring& dest, bool failIfExists = true);
    bool MoveFile(const std::wstring& source, const std::wstring& dest);
    bool SetFilePointer(HANDLE hFile, LONGLONG distance, DWORD moveMethod);
    LONGLONG GetFileSize(HANDLE hFile);
    void CloseFile(HANDLE hFile);
    
    // Directory operations
    bool CreateDirectory(const std::wstring& path);
    bool CreateDirectoryRecursive(const std::wstring& path);
    bool RemoveDirectory(const std::wstring& path);
    bool RemoveDirectoryRecursive(const std::wstring& path);
    std::vector<FileInfo> EnumerateDirectory(const std::wstring& path, const std::wstring& pattern = L"*");
    std::vector<FileInfo> EnumerateDirectoryRecursive(const std::wstring& path, const std::wstring& pattern = L"*");
    
    // File info
    FileInfo GetFileInfo(const std::wstring& path);
    bool FileExists(const std::wstring& path);
    bool DirectoryExists(const std::wstring& path);
    bool SetFileAttributes(const std::wstring& path, DWORD attributes);
    
    // Drive operations
    std::vector<DriveInfo> EnumerateDrives();
    DriveInfo GetDriveInfo(const std::wstring& drivePath);
    
    // File watching
    HANDLE WatchDirectory(const std::wstring& path, std::function<void(const std::wstring&, DWORD)> callback);
    void StopWatching(HANDLE hWatch);
    
private:
    std::vector<HANDLE> m_fileHandles;
    std::vector<HANDLE> m_watchHandles;
    std::mutex m_mutex;
};

// ============================================================================
// REGISTRY OPERATIONS
// ============================================================================

struct RegistryValue {
    std::wstring name;
    DWORD type;
    std::vector<BYTE> data;
    std::wstring stringValue;
    DWORD dwordValue;
    ULONGLONG qwordValue;
};

class RegistryManager {
public:
    RegistryManager();
    ~RegistryManager();
    
    // Key operations
    HKEY OpenKey(HKEY hRoot, const std::wstring& subKey, REGSAM access = KEY_READ);
    HKEY CreateKey(HKEY hRoot, const std::wstring& subKey);
    bool DeleteKey(HKEY hRoot, const std::wstring& subKey);
    bool DeleteKeyRecursive(HKEY hRoot, const std::wstring& subKey);
    void CloseKey(HKEY hKey);
    
    // Value operations
    RegistryValue GetValue(HKEY hKey, const std::wstring& valueName);
    bool SetStringValue(HKEY hKey, const std::wstring& valueName, const std::wstring& value);
    bool SetDwordValue(HKEY hKey, const std::wstring& valueName, DWORD value);
    bool SetQwordValue(HKEY hKey, const std::wstring& valueName, ULONGLONG value);
    bool SetBinaryValue(HKEY hKey, const std::wstring& valueName, const std::vector<BYTE>& data);
    bool DeleteValue(HKEY hKey, const std::wstring& valueName);
    
    // Enumeration
    std::vector<std::wstring> EnumerateSubKeys(HKEY hKey);
    std::vector<RegistryValue> EnumerateValues(HKEY hKey);
    
    // Helper methods
    std::wstring ReadString(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName);
    DWORD ReadDword(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName);
    bool WriteString(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& value);
    bool WriteDword(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName, DWORD value);
    
private:
    std::vector<HKEY> m_openKeys;
    std::mutex m_mutex;
};

// ============================================================================
// SERVICE CONTROL
// ============================================================================

struct ServiceInfo {
    std::wstring serviceName;
    std::wstring displayName;
    DWORD serviceType;
    DWORD currentState;
    DWORD startType;
    std::wstring binaryPath;
    std::wstring description;
    bool isRunning;
    DWORD processId;
};

class ServiceManager {
public:
    ServiceManager();
    ~ServiceManager();
    
    // Service enumeration
    std::vector<ServiceInfo> EnumerateServices(DWORD serviceType = SERVICE_WIN32);
    ServiceInfo GetServiceInfo(const std::wstring& serviceName);
    
    // Service control
    bool StartService(const std::wstring& serviceName, const std::vector<std::wstring>& args = {});
    bool StopService(const std::wstring& serviceName);
    bool RestartService(const std::wstring& serviceName);
    bool PauseService(const std::wstring& serviceName);
    bool ContinueService(const std::wstring& serviceName);
    
    // Service management
    bool CreateService(const std::wstring& serviceName, const std::wstring& displayName, 
                       const std::wstring& binaryPath, DWORD startType = SERVICE_DEMAND_START);
    bool DeleteService(const std::wstring& serviceName);
    bool SetServiceDescription(const std::wstring& serviceName, const std::wstring& description);
    
    // Status
    DWORD GetServiceState(const std::wstring& serviceName);
    bool WaitForServiceState(const std::wstring& serviceName, DWORD desiredState, DWORD timeoutMs = 30000);
    
private:
    SC_HANDLE m_hSCManager;
    std::mutex m_mutex;
};

// ============================================================================
// SYSTEM INFORMATION
// ============================================================================

struct SystemInfo {
    std::wstring computerName;
    std::wstring userName;
    std::wstring osVersion;
    std::wstring osBuild;
    DWORD processorCount;
    DWORD processorArchitecture;
    SIZE_T pageSize;
    SIZE_T allocationGranularity;
    std::wstring processorName;
    ULONGLONG totalPhysicalMemory;
    ULONGLONG availablePhysicalMemory;
};

struct CpuUsage {
    double totalCpu;
    double kernelCpu;
    double userCpu;
    std::vector<double> perCoreCpu;
};

class SystemInfoManager {
public:
    SystemInfoManager();
    ~SystemInfoManager();
    
    // System info
    SystemInfo GetSystemInfo();
    CpuUsage GetCpuUsage();
    std::wstring GetEnvironmentVariable(const std::wstring& name);
    bool SetEnvironmentVariable(const std::wstring& name, const std::wstring& value);
    std::vector<std::pair<std::wstring, std::wstring>> GetAllEnvironmentVariables();
    
    // System control
    bool Shutdown(bool reboot = false, bool force = false);
    bool LockWorkstation();
    bool SetSystemTime(const SYSTEMTIME& time);
    
    // Performance counters
    ULONGLONG GetSystemUptime();
    ULONGLONG GetIdleTime();
    
private:
    ULONGLONG m_lastIdleTime;
    ULONGLONG m_lastKernelTime;
    ULONGLONG m_lastUserTime;
};

// ============================================================================
// WINDOW MANAGEMENT
// ============================================================================

struct WindowInfo {
    HWND hwnd;
    HWND hwndParent;
    DWORD processId;
    DWORD threadId;
    std::wstring title;
    std::wstring className;
    RECT rect;
    bool isVisible;
    bool isEnabled;
    bool isMinimized;
    bool isMaximized;
    DWORD style;
    DWORD exStyle;
};

class WindowManager {
public:
    WindowManager();
    ~WindowManager();
    
    // Window enumeration
    std::vector<WindowInfo> EnumerateWindows(bool visibleOnly = true);
    std::vector<WindowInfo> FindWindowsByTitle(const std::wstring& title, bool partialMatch = false);
    std::vector<WindowInfo> FindWindowsByClass(const std::wstring& className);
    std::vector<WindowInfo> GetProcessWindows(DWORD processId);
    WindowInfo GetWindowInfo(HWND hwnd);
    
    // Window control
    bool ShowWindow(HWND hwnd, int showCmd);
    bool HideWindow(HWND hwnd);
    bool MinimizeWindow(HWND hwnd);
    bool MaximizeWindow(HWND hwnd);
    bool RestoreWindow(HWND hwnd);
    bool CloseWindow(HWND hwnd);
    bool MoveWindow(HWND hwnd, int x, int y, int width, int height);
    bool SetWindowTitle(HWND hwnd, const std::wstring& title);
    bool SetForegroundWindow(HWND hwnd);
    bool EnableWindow(HWND hwnd, bool enable);
    
    // Window messaging
    LRESULT SendMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    bool PostMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Special windows
    HWND GetDesktopWindow();
    HWND GetForegroundWindow();
    HWND GetActiveWindow();
    
private:
    static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
};

// ============================================================================
// NETWORK OPERATIONS
// ============================================================================

struct NetworkAdapterInfo {
    std::wstring name;
    std::wstring description;
    std::wstring macAddress;
    std::vector<std::wstring> ipAddresses;
    std::vector<std::wstring> dnsServers;
    std::wstring gateway;
    bool isDhcpEnabled;
    bool isConnected;
};

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();
    
    // Adapter info
    std::vector<NetworkAdapterInfo> EnumerateAdapters();
    
    // TCP/UDP sockets
    SOCKET CreateTcpSocket();
    SOCKET CreateUdpSocket();
    bool ConnectSocket(SOCKET sock, const std::wstring& host, USHORT port);
    bool BindSocket(SOCKET sock, USHORT port);
    bool ListenSocket(SOCKET sock, int backlog = SOMAXCONN);
    SOCKET AcceptConnection(SOCKET sock);
    int SendData(SOCKET sock, const void* data, int len);
    int ReceiveData(SOCKET sock, void* buffer, int bufferLen);
    void CloseSocket(SOCKET sock);
    
    // DNS
    std::vector<std::wstring> ResolveHostname(const std::wstring& hostname);
    std::wstring ReverseResolve(const std::wstring& ipAddress);
    
    // Ping
    bool Ping(const std::wstring& host, DWORD timeoutMs = 1000);
    
private:
    bool m_wsaInitialized;
    std::vector<SOCKET> m_sockets;
    std::mutex m_mutex;
};

// ============================================================================
// INTER-PROCESS COMMUNICATION
// ============================================================================

class PipeManager {
public:
    PipeManager();
    ~PipeManager();
    
    // Named pipes
    HANDLE CreateNamedPipe(const std::wstring& pipeName, bool isServer = true);
    bool ConnectNamedPipe(HANDLE hPipe, DWORD timeoutMs = INFINITE);
    HANDLE OpenNamedPipe(const std::wstring& pipeName);
    bool DisconnectNamedPipe(HANDLE hPipe);
    
    // Anonymous pipes
    bool CreateAnonymousPipe(HANDLE& hRead, HANDLE& hWrite);
    
    // Pipe I/O
    bool WritePipe(HANDLE hPipe, const void* data, DWORD size);
    bool ReadPipe(HANDLE hPipe, void* buffer, DWORD bufferSize, DWORD* bytesRead);
    
    void ClosePipe(HANDLE hPipe);
    
private:
    std::vector<HANDLE> m_pipes;
    std::mutex m_mutex;
};

// ============================================================================
// UNIFIED AGENT API INTERFACE
// ============================================================================

/**
 * @class Win32AgentAPI
 * @brief Unified interface providing full Win32 API access to agentic engines
 * 
 * This class aggregates all Win32 managers and provides a single entry point
 * for agentic operations requiring native system access.
 */
class Win32AgentAPI {
public:
    Win32AgentAPI();
    ~Win32AgentAPI();
    
    // Manager accessors
    ProcessManager& GetProcessManager() { return m_processManager; }
    ThreadManager& GetThreadManager() { return m_threadManager; }
    MemoryManager& GetMemoryManager() { return m_memoryManager; }
    FileSystemManager& GetFileSystemManager() { return m_fileSystemManager; }
    RegistryManager& GetRegistryManager() { return m_registryManager; }
    ServiceManager& GetServiceManager() { return m_serviceManager; }
    SystemInfoManager& GetSystemInfoManager() { return m_systemInfoManager; }
    WindowManager& GetWindowManager() { return m_windowManager; }
    NetworkManager& GetNetworkManager() { return m_networkManager; }
    PipeManager& GetPipeManager() { return m_pipeManager; }
    
    // High-level agentic operations
    std::wstring ExecuteShellCommand(const std::wstring& command, DWORD timeoutMs = 30000);
    std::wstring ExecutePowerShellScript(const std::wstring& script, DWORD timeoutMs = 60000);
    bool LaunchApplication(const std::wstring& path, const std::wstring& args = L"");
    bool KillProcess(const std::wstring& processName);
    
    // File operations for agents
    std::wstring ReadTextFile(const std::wstring& path);
    bool WriteTextFile(const std::wstring& path, const std::wstring& content);
    std::vector<std::wstring> ListFiles(const std::wstring& directory, const std::wstring& pattern = L"*");
    std::vector<std::wstring> SearchFiles(const std::wstring& directory, const std::wstring& pattern, bool recursive = true);
    
    // System queries for agents
    std::wstring GetSystemStatus();
    std::vector<std::pair<std::wstring, std::wstring>> GetRunningProcesses();
    std::vector<std::pair<std::wstring, std::wstring>> GetInstalledSoftware();
    
    // Security operations
    bool IsElevated();
    bool RequestElevation();
    
private:
    ProcessManager m_processManager;
    ThreadManager m_threadManager;
    MemoryManager m_memoryManager;
    FileSystemManager m_fileSystemManager;
    RegistryManager m_registryManager;
    ServiceManager m_serviceManager;
    SystemInfoManager m_systemInfoManager;
    WindowManager m_windowManager;
    NetworkManager m_networkManager;
    PipeManager m_pipeManager;
};

// Global instance accessor
Win32AgentAPI& GetWin32AgentAPI();

} // namespace Win32Agent
} // namespace RawrXD
