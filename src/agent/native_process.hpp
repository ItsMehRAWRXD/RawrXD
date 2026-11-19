#pragma once

#ifndef _WIN32
#error "RawrXD native process execution requires Windows"
#endif

#include <windows.h>
#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

struct NativeProcessResult {
    int exitCode = -1;
    bool success = false;
    bool timedOut = false;
    std::string stdoutOutput;
    std::string stderrOutput;
    std::string error;
};

class NativeProcess {
public:
    static NativeProcessResult execute(const std::string& command,
                                       const std::vector<std::string>& args,
                                       const std::string& workingDir,
                                       int timeoutMs) {
        NativeProcessResult result;
        if (command.empty() || timeoutMs <= 0) { result.error = "INVALID_ARGUMENT"; return result; }
        std::string line = "\"" + command + "\"";
        for (const auto& arg : args) line += " \"" + arg + "\"";
        auto wide = [](const std::string& s) {
            const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
            std::wstring w(static_cast<size_t>(n), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
            return w;
        };
        std::wstring wline = wide(line);
        std::wstring wdir = workingDir.empty() ? L"" : wide(workingDir);
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE outR=nullptr,outW=nullptr,errR=nullptr,errW=nullptr;
        if (!CreatePipe(&outR,&outW,&sa,0) || !CreatePipe(&errR,&errW,&sa,0)) {
            result.error="PIPE_CREATE_FAILED"; return result;
        }
        SetHandleInformation(outR,HANDLE_FLAG_INHERIT,0);
        SetHandleInformation(errR,HANDLE_FLAG_INHERIT,0);
        STARTUPINFOW si{sizeof(si)}; si.dwFlags=STARTF_USESTDHANDLES; si.hStdOutput=outW; si.hStdError=errW; si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
        PROCESS_INFORMATION pi{};
        BOOL created=CreateProcessW(nullptr,wline.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW,nullptr,wdir.empty()?nullptr:wdir.c_str(),&si,&pi);
        CloseHandle(outW); CloseHandle(errW);
        if (!created) { CloseHandle(outR); CloseHandle(errR); result.error="PROCESS_START_FAILED:"+std::to_string(GetLastError()); return result; }
        const auto start=std::chrono::steady_clock::now();
        auto drain=[&](HANDLE h,std::string& dst){ char b[4096]; DWORD n=0,avail=0; while(PeekNamedPipe(h,nullptr,0,nullptr,&avail,nullptr)&&avail){ if(!ReadFile(h,b,(std::min)(avail,DWORD(sizeof b)),&n,nullptr)||!n) break; dst.append(b,n); if(dst.size()>1024*1024){dst.resize(1024*1024);result.error="OUTPUT_LIMIT_EXCEEDED";break;} } };
        bool finished=false;
        while(!finished && result.error.empty()){
            drain(outR,result.stdoutOutput); drain(errR,result.stderrOutput);
            const auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
            if(elapsed>=timeoutMs){result.timedOut=true;result.error="COMMAND_TIMEOUT";TerminateProcess(pi.hProcess,1);break;}
            const DWORD wait=static_cast<DWORD>((std::min)(100LL,static_cast<long long>(timeoutMs)-elapsed));
            const DWORD wr=WaitForSingleObject(pi.hProcess,wait); finished=(wr==WAIT_OBJECT_0); if(wr==WAIT_FAILED) result.error="PROCESS_WAIT_FAILED";
        }
        if(!finished) { TerminateProcess(pi.hProcess,1); WaitForSingleObject(pi.hProcess,5000); }
        drain(outR,result.stdoutOutput); drain(errR,result.stderrOutput);
        DWORD code=1; GetExitCodeProcess(pi.hProcess,&code); result.exitCode=result.error.empty()?static_cast<int>(code):-1;
        result.success=result.error.empty() && code==0;
        if(!result.success && result.error.empty()) result.error=(code==STILL_ACTIVE?"PROCESS_CRASHED":"NONZERO_EXIT_CODE:"+std::to_string(code));
        CloseHandle(outR);CloseHandle(errR);CloseHandle(pi.hThread);CloseHandle(pi.hProcess); return result;
    }
};
