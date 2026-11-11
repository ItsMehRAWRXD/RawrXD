#include "ComputerUseBridge.h"
#include <cstdlib>

namespace rawrxd::computer_use {
namespace {
HWND ParseHwnd(const std::string& s) {
    if (s.empty()) return nullptr;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s.c_str(), &end, 0);
    if (!end || *end) return nullptr;
    return reinterpret_cast<HWND>(static_cast<uintptr_t>(v));
}
ActionType MapType(const std::string& name) {
    if (name == "computer_use.screenshot") return ActionType::Screenshot;
    if (name == "computer_use.find_window") return ActionType::FindWindow;
    if (name == "computer_use.inspect") return ActionType::InspectControls;
    if (name == "computer_use.click") return ActionType::Click;
    if (name == "computer_use.move") return ActionType::MoveMouse;
    if (name == "computer_use.type") return ActionType::TypeText;
    if (name == "computer_use.key") return ActionType::KeyPress;
    if (name == "computer_use.scroll") return ActionType::Scroll;
    if (name == "computer_use.launch") return ActionType::LaunchProcess;
    return ActionType::Screenshot;
}
bool Mutating(ActionType t) {
    return t == ActionType::Click || t == ActionType::MoveMouse ||
           t == ActionType::TypeText || t == ActionType::KeyPress ||
           t == ActionType::Scroll || t == ActionType::LaunchProcess;
}
}

std::wstring ComputerUseBridge::Utf8ToWide(const std::string& s) const {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

std::string ComputerUseBridge::WideToUtf8(const std::wstring& s) const {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

ComputerAction ComputerUseBridge::ParseAction(const rawrxd::tools::Request& r) const {
    ComputerAction a;
    a.type = MapType(r.name);
    auto get = [&](const char* k) {
        auto it = r.args.find(k);
        return it == r.args.end() ? std::string() : it->second;
    };
    a.targetWindow = ParseHwnd(get("hwnd"));
    a.text = Utf8ToWide(get("text").empty() ? get("title") : get("text"));
    if (a.type == ActionType::LaunchProcess) {
        a.text = Utf8ToWide(get("path"));
        a.arguments = Utf8ToWide(get("arguments"));
    }
    a.position.x = get("x").empty() ? 0 : std::atoi(get("x").c_str());
    a.position.y = get("y").empty() ? 0 : std::atoi(get("y").c_str());
    a.virtualKey = static_cast<WORD>(get("vk").empty() ? 0 : std::atoi(get("vk").c_str()));
    a.scrollDelta = get("delta").empty() ? 0 : std::atoi(get("delta").c_str());
    a.timeoutMs = get("timeout_ms").empty() ? 5000u
        : static_cast<DWORD>(std::atoi(get("timeout_ms").c_str()));
    (void)Mutating(a.type);
    return a;
}
}
