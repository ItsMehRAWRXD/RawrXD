// Windows subprocess runner: concurrent stdout/stderr capture, timeout, and exit status.
// Build: cl /nologo /EHsc /std:c++17 tools/rawrxd_msvc_runner.cpp
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <iostream>
#include <cstdlib>

static std::wstring quote(const std::wstring& s) {
    std::wstring out=L"\""; unsigned slash=0;
    for(wchar_t c:s) {
        if(c==L'\\') { ++slash; continue; }
        if(c==L'"') { out.append(slash*2+1,L'\\'); out+=c; slash=0; continue; }
        out.append(slash,L'\\'); slash=0; out+=c;
    }
    out.append(slash*2,L'\\'); out+=L'"'; return out;
}
static void drain(HANDLE pipe, HANDLE output) {
    char buf[8192]; DWORD n;
    while(ReadFile(pipe,buf,sizeof(buf),&n,nullptr) && n) {
        DWORD offset=0;
        while(offset<n) {
            DWORD wrote=0;
            if(!WriteFile(output,buf+offset,n-offset,&wrote,nullptr) || !wrote) break;
            offset+=wrote;
        }
    }
    CloseHandle(pipe);
}
static int run(const std::vector<std::wstring>& argv, DWORD timeout) {
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    HANDLE outRead=nullptr,outWrite=nullptr,errRead=nullptr,errWrite=nullptr;
    if(!CreatePipe(&outRead,&outWrite,&sa,0)) return 125;
    if(!CreatePipe(&errRead,&errWrite,&sa,0)) { CloseHandle(outRead);CloseHandle(outWrite);return 125; }
    SetHandleInformation(outRead,HANDLE_FLAG_INHERIT,0);
    SetHandleInformation(errRead,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdOutput=outWrite; si.hStdError=errWrite;
    si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    std::wstring cmd;
    for(auto& a:argv) { if(!cmd.empty())cmd+=L' ';cmd+=quote(a); }
    std::vector<wchar_t> mutableCmd(cmd.begin(),cmd.end());mutableCmd.push_back(0);
    PROCESS_INFORMATION pi{};
    BOOL created=CreateProcessW(argv[0].c_str(),mutableCmd.data(),nullptr,nullptr,TRUE,
                               CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,nullptr,&si,&pi);
    CloseHandle(outWrite);CloseHandle(errWrite);
    if(!created) {CloseHandle(outRead);CloseHandle(errRead);return 125;}
    HANDLE job=CreateJobObjectW(nullptr,nullptr);
    if(job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits));
        if(!AssignProcessToJobObject(job,pi.hProcess)) {
            // Fail closed: cannot promise descendant cleanup without job membership.
            TerminateProcess(pi.hProcess,125);
            CloseHandle(job);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
            CloseHandle(outRead);CloseHandle(errRead);return 125;
        }
    } else {
        TerminateProcess(pi.hProcess,125);
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
        CloseHandle(outRead);CloseHandle(errRead);return 125;
    }
    std::thread stdoutThread(drain,outRead,GetStdHandle(STD_OUTPUT_HANDLE));
    std::thread stderrThread(drain,errRead,GetStdHandle(STD_ERROR_HANDLE));
    if(ResumeThread(pi.hThread)==static_cast<DWORD>(-1)) {
        TerminateJobObject(job,125);
        WaitForSingleObject(pi.hProcess,INFINITE);
        stdoutThread.join();stderrThread.join();
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(job);
        return 125;
    }
    DWORD wait=WaitForSingleObject(pi.hProcess,timeout);
    int code=125;
    if(wait==WAIT_TIMEOUT) {
        TerminateJobObject(job,124);
        WaitForSingleObject(pi.hProcess,INFINITE);
        code=124;
    } else if(wait==WAIT_OBJECT_0) {
        DWORD exitCode=125;
        if(GetExitCodeProcess(pi.hProcess,&exitCode)) code=static_cast<int>(exitCode);
    } else {
        TerminateJobObject(job,125);
        WaitForSingleObject(pi.hProcess,INFINITE);
    }
    // Ensure descendants cannot retain inherited pipe handles indefinitely.
    TerminateJobObject(job,code==124?124:125);
    stdoutThread.join();stderrThread.join();
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(job);
    return code;
}
int wmain(int argc,wchar_t** argv) {
    if(argc<4 || std::wstring(argv[2])!=L"--") {
        std::wcerr<<L"usage: rawrxd_msvc_runner <timeout_ms> -- <absolute_executable> [args...]\n";
        return 2;
    }
    wchar_t* end=nullptr; unsigned long t=wcstoul(argv[1],&end,10);
    if(!argv[1][0] || *end || !t || t>3600000) return 2;
    std::vector<std::wstring> args(argv+3,argv+argc);
    return run(args,static_cast<DWORD>(t));
}
