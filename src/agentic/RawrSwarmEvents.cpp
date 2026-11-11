#include "RawrSwarmEvents.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <limits>
#include <cstdlib>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace rawr::live {
std::string escapeJson(std::string_view s) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out; out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15];
                } else out += static_cast<char>(c);
        }
    }
    return out;
}
std::string utcNow() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t t = system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3)
        << std::setfill('0') << ms.count() << 'Z';
    return out.str();
}
std::string serialize(const Event& e) {
    auto quote = [](std::string_view x) {return '"' + escapeJson(x) + '"';};
    std::string title = e.sensitive ? "[redacted]" : e.title;
    std::string detail = e.sensitive ? "[redacted]" : e.detail;
    return "{\"v\":1,\"ts\":" + quote(e.ts) + ",\"seq\":" + std::to_string(e.seq)
      + ",\"worker\":" + quote(e.worker) + ",\"kind\":" + quote(e.kind)
      + ",\"phase\":" + quote(e.phase) + ",\"title\":" + quote(title)
      + ",\"detail\":" + quote(detail) + ",\"task\":" + quote(e.task)
      + ",\"exit_code\":" + std::to_string(e.exitCode) + ",\"sensitive\":"
      + (e.sensitive ? "true" : "false") + "}\n";
}
namespace {
class Reader {
public:
    explicit Reader(std::string_view s) : s_(s) {}
    void ws(){while(i_<s_.size() && (s_[i_]==' '||s_[i_]=='\t'||s_[i_]=='\r'||s_[i_]=='\n')) ++i_;}
    bool chr(char c){ws();if(i_<s_.size()&&s_[i_]==c){++i_;return true;}return false;}
    bool string(std::string& o) {
        ws(); if(i_>=s_.size() || s_[i_++]!='"') return false;
        o.clear();
        while(i_<s_.size()) {
            unsigned char c = (unsigned char)s_[i_++];
            if(c=='"') return true;
            if(c<0x20) return false;
            if(c!='\\'){o.push_back((char)c);continue;}
            if(i_>=s_.size()) return false;
            char x=s_[i_++];
            switch(x) {
                case '"': case '\\': case '/': o+=x; break;
                case 'b': o+='\b'; break; case 'f': o+='\f'; break;
                case 'n': o+='\n'; break; case 'r': o+='\r'; break; case 't': o+='\t'; break;
                case 'u': {
                    if(i_+4>s_.size())return false;
                    int n=0;
                    for(int j=0;j<4;++j){char h=s_[i_++];n<<=4;if(h>='0'&&h<='9')n|=h-'0';else if(h>='a'&&h<='f')n|=h-'a'+10;else if(h>='A'&&h<='F')n|=h-'A'+10;else return false;}
                    // Schema writer emits raw UTF-8 and only \u00xx for controls.
                    if(n>0x7f)return false;
                    o.push_back((char)n);break;
                }
                default: return false;
            }
        }
        return false;
    }
    bool integer(int64_t& n) {
        ws(); bool neg=false; if(i_<s_.size() && s_[i_]=='-'){neg=true;++i_;}
        if(i_>=s_.size() || s_[i_]<'0' || s_[i_]>'9')return false;
        uint64_t v=0; while(i_<s_.size()&&s_[i_]>='0'&&s_[i_]<='9'){
            unsigned d=(unsigned)(s_[i_++]-'0');
            if(v>(static_cast<uint64_t>(INT64_MAX)-d)/10)return false;
            v=v*10+d;
        }
        n=neg?-(int64_t)v:(int64_t)v; return true;
    }
    bool boolean(bool& b){ws();if(s_.substr(i_,4)=="true"){i_+=4;b=true;return true;}if(s_.substr(i_,5)=="false"){i_+=5;b=false;return true;}return false;}
    bool end(){ws();return i_==s_.size();}
    char peek(){ws();return i_<s_.size()?s_[i_]:0;}
private: std::string_view s_; size_t i_=0;
};
#ifdef _WIN32
std::wstring widen(std::string_view s) {
    int n=MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,s.data(),(int)s.size(),nullptr,0);
    if(n<=0)return {};
    std::wstring r((size_t)n,L'\0');
    if(!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,s.data(),(int)s.size(),r.data(),n))return {};
    return r;
}
std::string sysErr(DWORD code){return "Win32 error " + std::to_string(code);}
#endif
}
bool parse(std::string_view s, Event& out){
    Reader r(s); Event e{}; bool flags[6]={};
    if(!r.chr('{'))return false;
    while(true){
        if(r.chr('}'))break;
        std::string k; if(!r.string(k)||!r.chr(':'))return false;
        if(k=="ts") {if(!r.string(e.ts))return false;flags[0]=true;}
        else if(k=="worker") {if(!r.string(e.worker))return false;flags[1]=true;}
        else if(k=="kind") {if(!r.string(e.kind))return false;flags[2]=true;}
        else if(k=="phase") {if(!r.string(e.phase))return false;flags[3]=true;}
        else if(k=="title") {if(!r.string(e.title))return false;flags[4]=true;}
        else if(k=="detail") {if(!r.string(e.detail))return false;flags[5]=true;}
        else if(k=="task") {if(!r.string(e.task))return false;}
        else if(k=="seq" || k=="v" || k=="exit_code") {
            int64_t n=0;if(!r.integer(n))return false;
            if(k=="seq") {if(n<0)return false;e.seq=(uint64_t)n;}
            if(k=="exit_code") {if(n<INT32_MIN||n>INT32_MAX)return false;e.exitCode=(int)n;}
            if(k=="v" && n!=1)return false;
        } else if(k=="sensitive") {if(!r.boolean(e.sensitive))return false;}
        else { // Additional schema fields permitted only as primitive data.
            if(r.peek()=='"'){std::string ignored;if(!r.string(ignored))return false;}
            else if(r.peek()=='t'||r.peek()=='f'){bool ignored;if(!r.boolean(ignored))return false;}
            else {int64_t ignored;if(!r.integer(ignored))return false;}
        }
        if(r.chr('}'))break;
        if(!r.chr(','))return false;
    }
    for(bool present:flags)if(!present)return false;
    if(!r.end())return false;
    out=std::move(e);return true;
}
Sink::Sink(std::string path):path_(std::move(path)){}
bool Sink::emit(Event e, std::string* error){
    std::lock_guard<std::mutex> lock(mutex_);
    if(e.ts.empty())e.ts=utcNow();
    if(e.worker.empty())e.worker="main";
    if(e.kind.empty()||e.phase.empty()) {if(error)*error="event kind and phase are required";return false;}
    e.seq=++sequence_;
    const std::string record=serialize(e);
#ifdef _WIN32
    auto name=widen(path_);
    if(name.empty()) {if(error)*error="invalid UTF-8 file path";return false;}
    HANDLE h=CreateFileW(name.c_str(), FILE_APPEND_DATA|SYNCHRONIZE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                         nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE){if(error)*error=sysErr(GetLastError());return false;}
    OVERLAPPED ov{}; ov.Offset=0xffffffffu; ov.OffsetHigh=0xffffffffu;
    bool ok=LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK,0,MAXDWORD,MAXDWORD,&ov)!=0;
    if(!ok){if(error)*error="LockFileEx: "+sysErr(GetLastError());CloseHandle(h);return false;}
    DWORD written=0; bool w=WriteFile(h,record.data(),(DWORD)record.size(),&written,nullptr)!=0;
    DWORD code=w?ERROR_SUCCESS:GetLastError();
    if(w && written==record.size())FlushFileBuffers(h);
    UnlockFileEx(h,0,MAXDWORD,MAXDWORD,&ov);CloseHandle(h);
    if(!w||written!=record.size()){if(error)*error="WriteFile: "+sysErr(code);return false;}
#else
    std::ofstream f(path_,std::ios::binary|std::ios::app);
    if(!f){if(error)*error="cannot open event log";return false;}
    f<<record;f.flush();if(!f){if(error)*error="write failure";return false;}
#endif
    return true;
}
ToolTrace::ToolTrace(Sink& sink,std::string worker,std::string kind,std::string title,std::string detail,std::string task)
    :sink_(sink),worker_(std::move(worker)),kind_(std::move(kind)),title_(std::move(title)),task_(std::move(task)) {
    sink_.emit(Event{.worker=worker_,.kind=kind_,.phase="start",.title=title_,.detail=std::move(detail),.task=task_});
}
void ToolTrace::output(std::string chunk,bool sensitive){
    sink_.emit(Event{.worker=worker_,.kind="output",.phase="progress",.title=title_,.detail=std::move(chunk),.task=task_,.sensitive=sensitive});
}
void ToolTrace::reasoningSummary(std::string summary){
    sink_.emit(Event{.worker=worker_,.kind="reason",.phase="info",.title="Model-reported rationale",.detail=std::move(summary),.task=task_});
}
void ToolTrace::finish(int actualExitCode,std::string detail){
    if(finished_)return;finished_=true;
    sink_.emit(Event{.worker=worker_,.kind=kind_,.phase=actualExitCode==0?"ok":"fail",.title=title_,.detail=std::move(detail),.task=task_,.exitCode=actualExitCode});
}
ToolTrace::~ToolTrace(){
    if(!finished_)sink_.emit(Event{.worker=worker_,.kind=kind_,.phase="fail",.title=title_,.detail="Interrupted without verified result; exit code unknown",.task=task_});
}
bool openViewerWindow(const std::string& exe,const std::string& file,std::string* error){
#ifdef _WIN32
    const std::wstring e=widen(exe),f=widen(file);
    if(e.empty()||f.empty()){if(error)*error="invalid path encoding";return false;}
    // Windows command-line quoting, including quotes and trailing backslashes.
    auto quote=[](const std::wstring& s){
        std::wstring r=L"\"";int sl=0;
        for(wchar_t c:s){if(c==L'\\'){++sl;continue;}if(c==L'"'){r.append((size_t)sl*2+1,L'\\');r+=L'"';sl=0;continue;}
            r.append((size_t)sl,L'\\');sl=0;r+=c;}
        r.append((size_t)sl*2,L'\\');r+=L'"';return r;
    };
    std::wstring cmd=quote(e)+L" watch "+quote(f);
    STARTUPINFOW si{};si.cb=sizeof(si); PROCESS_INFORMATION pi{};
    BOOL ok=CreateProcessW(e.c_str(),cmd.data(),nullptr,nullptr,FALSE,CREATE_NEW_CONSOLE,nullptr,nullptr,&si,&pi);
    if(!ok){if(error)*error=sysErr(GetLastError());return false;}
    CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return true;
#else
    (void)exe;(void)file;if(error)*error="openViewerWindow requires Windows";return false;
#endif
}
} // namespace rawr::live
