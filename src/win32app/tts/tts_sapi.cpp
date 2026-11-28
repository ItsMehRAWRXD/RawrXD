#include "tts_sapi.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <sapi.h>

#include <codecvt>
#include <cstdio>
#include <locale>

namespace rawrxd::tts {

namespace {

std::wstring ToWide(const std::string& s) {
    if (s.empty()) return L"";
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string ToUtf8(const WCHAR* w) {
    if (!w) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n - 1, nullptr, nullptr);
    return s;
}

}  // namespace

bool TtsEngine::initialize(std::string& err) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        err = "CoInitializeEx failed (0x" + [&]{ char b[16]; std::snprintf(b, sizeof(b), "%08lX", static_cast<unsigned long>(hr)); return std::string(b); }() + ")";
        return false;
    }
    ISpVoice* v = nullptr;
    hr = CoCreateInstance(CLSID_SpVoice, nullptr, CLSCTX_ALL, IID_ISpVoice, reinterpret_cast<void**>(&v));
    if (FAILED(hr) || !v) {
        err = "CoCreateInstance(SpVoice) failed (is SAPI installed?)";
        if (v) v->Release();
        CoUninitialize();
        return false;
    }
    voice_ = v;
    return true;
}

void TtsEngine::shutdown() {
    if (voice_) {
        static_cast<ISpVoice*>(voice_)->Release();
        voice_ = nullptr;
    }
    CoUninitialize();
}

std::vector<Voice> TtsEngine::voices() const {
    std::vector<Voice> out;
    // Enumerate installed SAPI voices from the registry (robust; avoids the
    // ISpObjectTokenEnum COM type that varies across SDK versions). Each token
    // subkey's default value is the human-readable voice description.
    HKEY hTokens = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Speech\\Voices\\Tokens",
                      0, KEY_READ, &hTokens) != ERROR_SUCCESS) {
        return out;
    }
    for (DWORD i = 0;; ++i) {
        WCHAR name[512];
        DWORD nameLen = static_cast<DWORD>(sizeof(name) / sizeof(name[0]));
        if (RegEnumKeyExW(hTokens, i, name, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        HKEY hSub = nullptr;
        if (RegOpenKeyExW(hTokens, name, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            WCHAR desc[512] = {};
            DWORD descLen = static_cast<DWORD>(sizeof(desc));
            if (RegQueryValueExW(hSub, L"", nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(desc), &descLen) == ERROR_SUCCESS) {
                Voice v;
                v.name = ToUtf8(desc);
                if (!v.name.empty()) out.push_back(std::move(v));
            }
            RegCloseKey(hSub);
        }
    }
    RegCloseKey(hTokens);
    return out;
}

bool TtsEngine::speak(const std::string& text, std::string& err) {
    if (!voice_) { err = "not initialized"; return false; }
    const std::wstring w = ToWide(text);
    if (w.empty()) { err = "empty text"; return false; }
    ULONG streamPos = 0;
    const HRESULT hr = static_cast<ISpVoice*>(voice_)->Speak(w.c_str(), SPF_DEFAULT, &streamPos);
    if (FAILED(hr)) {
        err = "Speak failed (0x" + [&]{ char b[16]; std::snprintf(b, sizeof(b), "%08lX", static_cast<unsigned long>(hr)); return std::string(b); }() + ")";
        return false;
    }
    return true;
}

void TtsEngine::stop() {
    if (voice_) static_cast<ISpVoice*>(voice_)->Speak(L"", SPF_PURGEBEFORESPEAK, nullptr);
}

bool TtsEngine::isSpeaking() const {
    if (!voice_) return false;
    SPVOICESTATUS st{};
    if (SUCCEEDED(static_cast<ISpVoice*>(voice_)->GetStatus(&st, nullptr))) {
        return st.dwRunningState == SPRS_IS_SPEAKING;
    }
    return false;
}

}  // namespace rawrxd::tts