#pragma once
#include <string>
#include <windows.h>

struct CpuSnapshot {
    double totalUtilization;
    std::string modelString;
    unsigned int coreCount;
    unsigned int activeThreadCount;
};

class ProcessorMetrics {
private:
    ULARGE_INTEGER m_lastCpu;
    ULARGE_INTEGER m_lastSys;
    ULARGE_INTEGER m_lastUser;
    unsigned int m_numProcessors;
    std::string m_processorName;

    void FetchProcessorHardwareDetails();

public:
    ProcessorMetrics();
    CpuSnapshot SampleCurrentCpuState();
};
