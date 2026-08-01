#include "ProcessorMetrics.hpp"
#include <iostream>

ProcessorMetrics::ProcessorMetrics() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    m_numProcessors = sysInfo.dwNumberOfProcessors;
    
    FILETIME idleTime, kernelTime, userTime;
    GetSystemTimes(&idleTime, &kernelTime, &userTime);
    
    m_lastCpu.LowPart = idleTime.dwLowDateTime;
    m_lastCpu.HighPart = idleTime.dwHighDateTime;
    m_lastSys.LowPart = kernelTime.dwLowDateTime;
    m_lastSys.HighPart = kernelTime.dwHighDateTime;
    m_lastUser.LowPart = userTime.dwLowDateTime;
    m_lastUser.HighPart = userTime.dwHighDateTime;

    FetchProcessorHardwareDetails();
}

void ProcessorMetrics::FetchProcessorHardwareDetails() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buffer[256];
        DWORD bufferSize = sizeof(buffer);
        if (RegQueryValueExA(hKey, "ProcessorNameString", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            m_processorName = std::string(buffer);
        } else {
            m_processorName = "AMD/Intel x64 Architecture";
        }
        RegCloseKey(hKey);
    } else {
        m_processorName = "Generic x64 Processor Core";
    }
}

CpuSnapshot ProcessorMetrics::SampleCurrentCpuState() {
    FILETIME idleTime, kernelTime, userTime;
    if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
        return { 0.0, m_processorName, m_numProcessors, 0 };
    }

    ULARGE_INTEGER nowIdle, nowKernel, nowUser;
    nowIdle.LowPart = idleTime.dwLowDateTime;
    nowIdle.HighPart = idleTime.dwHighDateTime;
    nowKernel.LowPart = kernelTime.dwLowDateTime;
    nowKernel.HighPart = kernelTime.dwHighDateTime;
    nowUser.LowPart = userTime.dwLowDateTime;
    nowUser.HighPart = userTime.dwHighDateTime;

    ULONGLONG idleDelta = nowIdle.QuadPart - m_lastCpu.QuadPart;
    ULONGLONG kernelDelta = nowKernel.QuadPart - m_lastSys.QuadPart;
    ULONGLONG userDelta = nowUser.QuadPart - m_lastUser.QuadPart;
    ULONGLONG totalSystemTime = kernelDelta + userDelta;

    m_lastCpu = nowIdle;
    m_lastSys = nowKernel;
    m_lastUser = nowUser;

    double cpuPercent = 0.0;
    if (totalSystemTime > 0) {
        cpuPercent = (static_cast<double>(totalSystemTime - idleDelta) * 100.0) / totalSystemTime;
    }

    if (cpuPercent < 0.0) cpuPercent = 0.0;
    if (cpuPercent > 100.0) cpuPercent = 100.0;

    return { cpuPercent, m_processorName, m_numProcessors, m_numProcessors };
}
