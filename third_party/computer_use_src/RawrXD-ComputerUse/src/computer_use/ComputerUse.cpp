#include "ComputerUse.h"
#include <algorithm>
#include <chrono>
#include <thread>
#include <sstream>
#include <vector>

namespace rawrxd::computer_use {
namespace {
ActionResult Fail(DWORD code, const wchar_t* message) { return {false, code, message}; }
ActionResult Ok(const wchar_t* message, HWND hwnd = nullptr) { ActionResult r; r.success=true; r.message=message; r.window=hwnd; return r; }
bool IsAlive(HWND h) { return h && IsWindow(h) && IsWindowVisible(h); }
std::wstring Title(HWND h) { int n=GetWindowTextLengthW(h); std::wstring s(static_cast<size_t>(n)+1,L'\0'); int len=GetWindowTextW(h,s.data(),static_cast<int>(s.size())); s.resize(static_cast<size_t>(len)); return s; }
std::wstring Class(HWND h) { wchar_t b[256]{}; GetClassNameW(h,b,256); return b; }
struct SearchContext { const std::wstring* needle; HWND result=nullptr; };
BOOL CALLBACK FindProc(HWND h, LPARAM p) { auto& ctx=*reinterpret_cast<SearchContext*>(p); if(IsAlive(h) && Title(h).find(*ctx.needle)!=std::wstring::npos) { ctx.result=h; return FALSE; } return TRUE; }
struct InspectContext { std::vector<ControlInfo>* controls; };
BOOL CALLBACK ChildProc(HWND h, LPARAM p) { auto& ctx=*reinterpret_cast<InspectContext*>(p); RECT rect{}; GetWindowRect(h,&rect); ctx.controls->push_back({Title(h),Class(h),rect,h}); return ctx.controls->size()<1024; }
bool Send(const std::vector<INPUT>& events) { return !events.empty() && SendInput(static_cast<UINT>(events.size()), const_cast<INPUT*>(events.data()),sizeof(INPUT))==events.size(); }
INPUT Key(WORD vk, DWORD flags=0) { INPUT i{}; i.type=INPUT_KEYBOARD; i.ki.wVk=vk; i.ki.dwFlags=flags; return i; }
INPUT Mouse(DWORD flags, DWORD data=0) { INPUT i{}; i.type=INPUT_MOUSE; i.mi.dwFlags=flags; i.mi.mouseData=data; return i; }
}
ComputerUseEngine::ComputerUseEngine(SafetyPolicy p):policy_(std::move(p)){}
bool ComputerUseEngine::IsTargetAllowed(HWND window) const {
    if(!IsAlive(window)) return false;
    DWORD pid=0; GetWindowThreadProcessId(window,&pid);
    if(!pid || std::find(policy_.allowedProcessIds.begin(),policy_.allowedProcessIds.end(),pid)==policy_.allowedProcessIds.end()) return false;
    return !policy_.requireForeground || GetForegroundWindow()==window || GetAncestor(GetForegroundWindow(),GA_ROOT)==window;
}
ActionResult ComputerUseEngine::Find(const std::wstring& title,DWORD timeout) {
    if(title.empty()) return Fail(ERROR_INVALID_PARAMETER,L"Window title substring required");
    auto start=GetTickCount64();
    do {
        if(cancelled_) return Fail(ERROR_CANCELLED,L"Cancelled");
        SearchContext ctx{&title}; EnumWindows(FindProc,reinterpret_cast<LPARAM>(&ctx));
        if(ctx.result && IsTargetAllowed(ctx.result)) return Ok(L"Window found",ctx.result);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    } while(GetTickCount64()-start<timeout);
    return Fail(ERROR_NOT_FOUND,L"Allowed window not found");
}
ActionResult ComputerUseEngine::Inspect(HWND window) const {
    if(!policy_.allowInspection) return Fail(ERROR_ACCESS_DENIED,L"Inspection denied by policy");
    if(!IsTargetAllowed(window)) return Fail(ERROR_ACCESS_DENIED,L"Window not allowlisted or foreground");
    auto r=Ok(L"Win32 child controls enumerated",window); InspectContext ctx{&r.controls}; EnumChildWindows(window,ChildProc,reinterpret_cast<LPARAM>(&ctx)); return r;
}
ActionResult ComputerUseEngine::Input(const ComputerAction& a) {
    if(!IsTargetAllowed(a.targetWindow)) return Fail(ERROR_ACCESS_DENIED,L"Target window not allowlisted or foreground");
    if(cancelled_) return Fail(ERROR_CANCELLED,L"Cancelled");
    if(a.type==ActionType::Click || a.type==ActionType::MoveMouse || a.type==ActionType::Scroll) {
        if(!policy_.allowMouse) return Fail(ERROR_ACCESS_DENIED,L"Mouse input denied");
        POINT pt=a.position;
        if(!ClientToScreen(a.targetWindow,&pt)) return Fail(GetLastError(),L"ClientToScreen failed");
        RECT bounds{}; GetWindowRect(a.targetWindow,&bounds);
        if(pt.x<bounds.left || pt.x>=bounds.right || pt.y<bounds.top || pt.y>=bounds.bottom) return Fail(ERROR_INVALID_PARAMETER,L"Point outside target window");
        if(!SetCursorPos(pt.x,pt.y)) return Fail(GetLastError(),L"SetCursorPos failed");
        if(a.type==ActionType::Click && !Send({Mouse(MOUSEEVENTF_LEFTDOWN),Mouse(MOUSEEVENTF_LEFTUP)})) return Fail(GetLastError(),L"Click failed");
        if(a.type==ActionType::Scroll && !Send({Mouse(MOUSEEVENTF_WHEEL,static_cast<DWORD>(a.scrollDelta))})) return Fail(GetLastError(),L"Scroll failed");
        return Ok(L"Mouse action sent",a.targetWindow);
    }
    if(a.type==ActionType::KeyPress) {
        if(!policy_.allowKeyboard || !a.virtualKey) return Fail(ERROR_ACCESS_DENIED,L"Keyboard input denied or key missing");
        if(!Send({Key(a.virtualKey),Key(a.virtualKey,KEYEVENTF_KEYUP)})) return Fail(GetLastError(),L"Key failed");
        return Ok(L"Key sent",a.targetWindow);
    }
    if(a.type==ActionType::TypeText) {
        if(!policy_.allowTyping) return Fail(ERROR_ACCESS_DENIED,L"Typing denied");
        if(a.text.size()>4096) return Fail(ERROR_INVALID_PARAMETER,L"Text exceeds per-action limit");
        for(wchar_t c:a.text) {
            if(cancelled_) return Fail(ERROR_CANCELLED,L"Cancelled mid-typing");
            INPUT down{},up{}; down.type=up.type=INPUT_KEYBOARD; down.ki.wScan=up.ki.wScan=static_cast<WORD>(c); down.ki.dwFlags=KEYEVENTF_UNICODE; up.ki.dwFlags=KEYEVENTF_UNICODE|KEYEVENTF_KEYUP;
            if(!Send({down,up})) return Fail(GetLastError(),L"Unicode input failed");
        }
        return Ok(L"Unicode input sent",a.targetWindow);
    }
    return Fail(ERROR_INVALID_FUNCTION,L"Unsupported input action");
}
ActionResult ComputerUseEngine::Launch(const ComputerAction& a) const {
    if(!policy_.allowLaunch) return Fail(ERROR_ACCESS_DENIED,L"Process launch denied");
    if(a.text.empty() || a.text.find(L'"')!=std::wstring::npos) return Fail(ERROR_INVALID_PARAMETER,L"Absolute executable path required, without quotes");
    if(a.text.size()<3 || a.text[1]!=L':' || (a.text[2]!=L'\\' && a.text[2]!=L'/')) return Fail(ERROR_INVALID_PARAMETER,L"Absolute drive path required");
    std::wstring command=L"\""+a.text+L"\""+(a.arguments.empty()?L"":L" "+a.arguments);
    STARTUPINFOW si{}; si.cb=sizeof(si); PROCESS_INFORMATION pi{};
    if(!CreateProcessW(a.text.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&si,&pi)) return Fail(GetLastError(),L"CreateProcessW failed");
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return Ok(L"Process started; caller must separately approve its PID");
}
ActionResult ComputerUseEngine::Execute(const ComputerAction& a) {
    if(cancelled_) return Fail(ERROR_CANCELLED,L"Cancelled");
    switch(a.type) {
        case ActionType::FindWindow: case ActionType::WaitForWindow: return Find(a.text,a.timeoutMs);
        case ActionType::InspectControls: return Inspect(a.targetWindow);
        case ActionType::Screenshot: return Capture(a.targetWindow);
        case ActionType::LaunchProcess: return Launch(a);
        default: return Input(a);
    }
}
std::wstring FormatReceipt(const ComputerAction& a,const ActionResult& r) {
    std::wostringstream s; s<<L"action="<<static_cast<int>(a.type)<<L" success="<<(r.success?1:0)<<L" error="<<r.errorCode<<L" target_pid=";
    DWORD pid=0; if(r.window && IsWindow(r.window)) GetWindowThreadProcessId(r.window,&pid); s<<pid<<L" message="<<r.message;
    // Intentionally omit typed text, launch arguments, screenshots and secrets.
    return s.str();
}
}
