#pragma once
// Windows process runner: concurrent stdout/stderr draining, deadline and process-tree kill.
// Standalone header, no Ollama or GUI dependency.
#ifdef _WIN32
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>
namespace rawrxd::build {
inline std::wstring utf16(const std::string& s) {
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),(int)s.size(),nullptr,0);
    if(n<=0)return {};
    std::wstring out((size_t)n,L'\0');
    if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),(int)s.size(),out.data(),n)!=n)return {};
    return out;
}
inline std::wstring quote(const std::wstring& s) {
    std::wstring out=L"\"";size_t slashes=0;
    for(wchar_t c:s) {
        if(c==L'\\'){++slashes;continue;}
        if(c==L'"'){out.append(slashes*2+1,L'\\');out+=c;slashes=0;continue;}
        out.append(slashes,L'\\');slashes=0;out+=c;
    }
    out.append(slashes*2,L'\\');out+=L'"';return out;
}
struct Result { int code=127; bool timedOut=false; bool launched=false; };
inline Result execute(const std::vector<std::string>& argv, unsigned timeoutMs=120000) {
    Result result;
    if(argv.empty()||timeoutMs==0)return result;
    std::wstring command;
    for(const auto& a:argv){
        auto w=utf16(a);if(w.empty())return result;
        if(!command.empty())command+=L' ';
        command+=quote(w);
    }
    std::vector<wchar_t> mutableCommand(command.begin(),command.end());
    mutableCommand.push_back(L'\0');
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    HANDLE outRead=nullptr,outWrite=nullptr,errRead=nullptr,errWrite=nullptr;
    auto close=[](HANDLE& h){if(h){CloseHandle(h);h=nullptr;}};
    if(!CreatePipe(&outRead,&outWrite,&sa,0))return result;
    if(!CreatePipe(&errRead,&errWrite,&sa,0)){close(outRead);close(outWrite);return result;}
    if(!SetHandleInformation(outRead,HANDLE_FLAG_INHERIT,0)||
       !SetHandleInformation(errRead,HANDLE_FLAG_INHERIT,0)){
        close(outRead);close(outWrite);close(errRead);close(errWrite);return result;
    }
    HANDLE job=CreateJobObjectW(nullptr,nullptr);
    if(!job){close(outRead);close(outWrite);close(errRead);close(errWrite);return result;}
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))){
        close(job);close(outRead);close(outWrite);close(errRead);close(errWrite);return result;
    }
    STARTUPINFOW si{};si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdOutput=outWrite;si.hStdError=errWrite;
    si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    // Suspend until assigned to the kill-on-close job, preventing escaped children.
    BOOL ok=CreateProcessW(nullptr,mutableCommand.data(),nullptr,nullptr,TRUE,
                           CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,nullptr,&si,&pi);
    close(outWrite);close(errWrite);
    if(!ok){close(outRead);close(errRead);close(job);return result;}
    if(!AssignProcessToJobObject(job,pi.hProcess)){
        TerminateProcess(pi.hProcess,127);
        close(pi.hThread);close(pi.hProcess);close(outRead);close(errRead);close(job);
        return result;
    }
    result.launched=true;
    auto drain=[](HANDLE h,FILE* stream){
        char buffer[8192];DWORD n=0;
        while(ReadFile(h,buffer,sizeof(buffer),&n,nullptr)&&n>0){
            fwrite(buffer,1,n,stream);fflush(stream);
        }
    };
    std::thread stdoutThread(drain,outRead,stdout);
    std::thread stderrThread(drain,errRead,stderr);
    if(ResumeThread(pi.hThread)==(DWORD)-1){
        TerminateJobObject(job,127);
    }
    DWORD wait=WaitForSingleObject(pi.hProcess,timeoutMs);
    if(wait==WAIT_TIMEOUT){
        result.timedOut=true;result.code=124;
        TerminateJobObject(job,124);
        WaitForSingleObject(pi.hProcess,INFINITE);
    }else if(wait==WAIT_OBJECT_0){
        DWORD code=127;
        if(GetExitCodeProcess(pi.hProcess,&code))result.code=(int)code;
    }else{
        TerminateJobObject(job,127);
        WaitForSingleObject(pi.hProcess,INFINITE);
    }
    // Closing the job terminates any descendant still holding a pipe handle.
    close(job);
    stdoutThread.join();stderrThread.join();
    close(outRead);close(errRead);close(pi.hThread);close(pi.hProcess);
    return result;
}
}
#endif
