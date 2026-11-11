#include "RawrLiveTools.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <system_error>
#include <limits>
#include <stdexcept>
#include <cwctype>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace rawr::live {
namespace {
std::filesystem::path checked(const std::filesystem::path& root,const std::filesystem::path& candidate){
    std::error_code ec;
    const auto base=std::filesystem::canonical(root,ec);if(ec)throw std::filesystem::filesystem_error("canonical root",root,ec);
    const auto p=std::filesystem::canonical(base/candidate,ec);if(ec)throw std::filesystem::filesystem_error("canonical path",candidate,ec);
    auto r=base.begin(),x=p.begin();
    for(;r!=base.end();++r,++x){if(x==p.end())throw std::runtime_error("target outside workspace");
#ifdef _WIN32
        auto a=r->wstring(),b=x->wstring();
        std::transform(a.begin(),a.end(),a.begin(),::towlower);
        std::transform(b.begin(),b.end(),b.begin(),::towlower);
        if(a!=b)throw std::runtime_error("target outside workspace");
#else
        if(*r!=*x)throw std::runtime_error("target outside workspace");
#endif
    }
    return p;
}
std::string readLimited(const std::filesystem::path& path,size_t max){
    std::error_code ec;
    auto bytes=std::filesystem::file_size(path,ec);
    if(ec||bytes>max)throw std::runtime_error("file too large or inaccessible");
    std::ifstream f(path,std::ios::binary);
    if(!f)throw std::runtime_error("unable to open file");
    std::string text((size_t)bytes,'\0');
    if(bytes>0&&!f.read(text.data(),(std::streamsize)bytes))throw std::runtime_error("short file read");
    return text;
}
std::string preview(std::string_view s,size_t max=350){
    std::string out;out.reserve(std::min(s.size(),max));
    for(size_t i=0;i<s.size()&&i<max;++i){char c=s[i];out+=(c=='\r'||c=='\0')?' ':c;}
    if(s.size()>max)out+=" ... [truncated]";
    return out;
}
#ifdef _WIN32
std::string utf8(const std::wstring& wide){
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),(int)wide.size(),nullptr,0,nullptr,nullptr);
    if(n<=0)return {};
    std::string result((size_t)n,'\0');
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide.data(),(int)wide.size(),result.data(),n,nullptr,nullptr);
    return result;
}
std::wstring quote(std::wstring_view s){
    std::wstring r=L"\"";unsigned bs=0;
    for(wchar_t c:s){if(c==L'\\'){++bs;continue;}if(c==L'"'){r.append(bs*2+1,L'\\');r+=L'"';bs=0;continue;}
        r.append(bs,L'\\');bs=0;r+=c;}
    r.append(bs*2,L'\\');r+=L'"';return r;
}
std::string winError(DWORD n){return "Win32 error "+std::to_string(n);}
std::atomic<uint64_t> tempSeq{0};
void replaceAtomic(const std::filesystem::path& path,const std::string& body){
    const auto temp=path.parent_path()/(path.filename().wstring()+L".rawrlive."+
                           std::to_wstring(GetCurrentProcessId())+L"."+std::to_wstring(++tempSeq));
    HANDLE h=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE)throw std::runtime_error("temporary file creation: "+winError(GetLastError()));
    bool ok=true;size_t written=0;
    while(written<body.size()){
        DWORD done=0;
        DWORD chunk=(DWORD)std::min<size_t>(body.size()-written,1024*1024);
        if(!WriteFile(h,body.data()+written,chunk,&done,nullptr)||done==0){ok=false;break;}
        written+=done;
    }
    if(!FlushFileBuffers(h))ok=false;
    CloseHandle(h);
    if(!ok){DeleteFileW(temp.c_str());throw std::runtime_error("failed to write replacement");}
    if(!ReplaceFileW(path.c_str(),temp.c_str(),nullptr,REPLACEFILE_IGNORE_MERGE_ERRORS,nullptr,nullptr)){
        DWORD err=GetLastError();DeleteFileW(temp.c_str());throw std::runtime_error("ReplaceFileW: "+winError(err));
    }
}
#else
std::atomic<uint64_t> tempSeq{0};
void replaceAtomic(const std::filesystem::path& path,const std::string& body){
    const auto temp=path.parent_path()/(path.filename().string()+".rawrlive."+std::to_string(++tempSeq));
    {std::ofstream f(temp,std::ios::binary|std::ios::trunc);if(!f)throw std::runtime_error("temporary file creation failed");
        f.write(body.data(),(std::streamsize)body.size());f.flush();if(!f){std::filesystem::remove(temp);throw std::runtime_error("write failed");}}
    std::error_code ec;std::filesystem::rename(temp,path,ec);
    if(ec){std::filesystem::remove(temp);throw std::runtime_error("rename failed: "+ec.message());}
}
#endif
}
ToolResult readText(Sink& sink,const std::filesystem::path& workspace,const std::filesystem::path& relativePath,
                    const std::string& worker,size_t maxBytes){
    ToolTrace trace(sink,worker,"read","Read "+relativePath.string(),"max_bytes="+std::to_string(maxBytes));
    try{
        const auto path=checked(workspace,relativePath);
        if(!std::filesystem::is_regular_file(path))throw std::runtime_error("not a regular file");
        auto text=readLimited(path,maxBytes);
        trace.output(preview(text));trace.finish(0,"read="+std::to_string(text.size())+" bytes");
        return {true,0,std::move(text)};
    }catch(const std::exception& ex){trace.finish(1,ex.what());return {false,1,ex.what()};}
}
ToolResult editExact(Sink& sink,const std::filesystem::path& workspace,const std::filesystem::path& relativePath,
                     std::string_view expected,std::string_view replacement,const std::string& worker){
    ToolTrace trace(sink,worker,"edit","Edit "+relativePath.string(),"unique exact replacement");
    try{
        if(expected.empty())throw std::runtime_error("empty search pattern forbidden");
        const auto path=checked(workspace,relativePath);
        if(!std::filesystem::is_regular_file(path))throw std::runtime_error("not a regular file");
        const auto before=readLimited(path,16*1024*1024);
        auto at=before.find(expected);
        if(at==std::string::npos)throw std::runtime_error("expected text not found");
        if(before.find(expected,at+1)!=std::string::npos)throw std::runtime_error("ambiguous: more than one match");
        std::string after;after.reserve(before.size()-expected.size()+replacement.size());
        after+=before.substr(0,at);after.append(replacement);after+=before.substr(at+expected.size());
        replaceAtomic(path,after);
        sink.emit(Event{.worker=worker,.kind="diff",.phase="info",.title="Applied exact replacement: "+relativePath.string(),
                        .detail="- "+preview(expected)+"\n+ "+preview(replacement)});
        trace.finish(0,"verified replacement bytes="+std::to_string(after.size()));
        return {true,0,"written " + relativePath.string()};
    }catch(const std::exception& ex){trace.finish(1,ex.what());return {false,1,ex.what()};}
}
#ifdef _WIN32
ToolResult runProcess(Sink& sink,const std::wstring& exe,const std::wstring& args,
                      const std::wstring& cwd,const std::string& worker,uint32_t timeoutMs){
    ToolTrace trace(sink,worker,"shell","Run "+utf8(exe),utf8(args));
    SECURITY_ATTRIBUTES sa{};sa.nLength=sizeof(sa);sa.bInheritHandle=TRUE;
    HANDLE readPipe=nullptr,writePipe=nullptr;
    if(!CreatePipe(&readPipe,&writePipe,&sa,0)){
        auto msg="CreatePipe: "+winError(GetLastError());trace.finish(1,msg);return {false,1,msg};
    }
    SetHandleInformation(readPipe,HANDLE_FLAG_INHERIT,0);
    HANDLE stdinNull=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,
                                 &sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(stdinNull==INVALID_HANDLE_VALUE){
        DWORD code=GetLastError();CloseHandle(readPipe);CloseHandle(writePipe);
        auto msg="Open NUL stdin: "+winError(code);trace.finish(1,msg);return {false,1,msg};
    }
    STARTUPINFOW si{};si.cb=sizeof(si);si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdInput=stdinNull;si.hStdOutput=writePipe;si.hStdError=writePipe;
    PROCESS_INFORMATION pi{};
    std::wstring cmd=quote(exe)+(args.empty()?L"":L" "+args);
    BOOL started=CreateProcessW(exe.c_str(),cmd.data(),nullptr,nullptr,TRUE,
                                CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,
                                cwd.empty()?nullptr:cwd.c_str(),&si,&pi);
    DWORD startErr=started?0:GetLastError();
    CloseHandle(stdinNull);CloseHandle(writePipe);
    if(!started){CloseHandle(readPipe);auto msg="CreateProcessW: "+winError(startErr);trace.finish(1,msg);return {false,1,msg};}
    HANDLE job=CreateJobObjectW(nullptr,nullptr);
    BOOL jobReady=FALSE;
    if(job){
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        jobReady=SetInformationJobObject(job,JobObjectExtendedLimitInformation,&info,sizeof(info))
                 && AssignProcessToJobObject(job,pi.hProcess);
    }
    if(!jobReady){
        DWORD err=GetLastError();TerminateProcess(pi.hProcess,1);
        WaitForSingleObject(pi.hProcess,INFINITE);
        if(job)CloseHandle(job);
        CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(readPipe);
        auto msg="failed to create isolated process job: "+winError(err);
        trace.finish(1,msg);return {false,1,msg};
    }
    if(ResumeThread(pi.hThread)==(DWORD)-1){
        TerminateJobObject(job,1);WaitForSingleObject(pi.hProcess,INFINITE);
        CloseHandle(job);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);CloseHandle(readPipe);
        auto msg="ResumeThread failed";trace.finish(1,msg);return {false,1,msg};
    }
    std::atomic<bool> timedOut{false};
    std::thread reader([&]{
        char buf[4096];DWORD got=0;
        while(ReadFile(readPipe,buf,sizeof(buf),&got,nullptr)&&got>0){
            trace.output(std::string(buf,got));
        }
    });
    DWORD wait=WaitForSingleObject(pi.hProcess,timeoutMs==0?INFINITE:timeoutMs);
    if(wait==WAIT_TIMEOUT){timedOut=true;TerminateJobObject(job,124);WaitForSingleObject(pi.hProcess,INFINITE);}
    DWORD rc=0;BOOL gotRc=GetExitCodeProcess(pi.hProcess,&rc);
    CloseHandle(job);
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
    // Closing descendants via job object ensures reader drains.
    reader.join();CloseHandle(readPipe);
    int code=timedOut?124:(gotRc?(int)rc:1);
    auto desc=timedOut?"process timeout":(!gotRc?"GetExitCodeProcess failed":"actual process exit code="+std::to_string(code));
    trace.finish(code,desc);
    return {code==0,code,desc};
}
#endif
} // namespace rawr::live
