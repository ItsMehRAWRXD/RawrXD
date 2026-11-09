#include "AgentSession.hpp"
#include <windows.h>

void AgentSessionKillTree(void* process) {
    HANDLE proc = static_cast<HANDLE>(process);
    HANDLE job = CreateJobObjectA(nullptr, nullptr);
    if (!job) { TerminateProcess(proc, 1); return; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION lim{};
    lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &lim, sizeof(lim));
    AssignProcessToJobObject(job, proc);
    CloseHandle(job);
}
