#include "rawrxd/tts/TtsEngine.h"

#if defined(_WIN32)
#include <windows.h>
#include <sapi.h>
#include <sphelper.h>
#endif

namespace rawrxd::tts {

#if defined(_WIN32)

struct TtsEngine::Impl {
    ISpVoice* voice = nullptr;
    bool comReady = false;
    std::string lastError;

    ~Impl() {
        if (voice) voice->Release();
        if (comReady) CoUninitialize();
    }
};

TtsEngine::TtsEngine() : impl_(new Impl()) {}

TtsEngine::~TtsEngine() { delete impl_; }

bool TtsEngine::initialize(std::string& error) {
    if (!impl_) return false;
    if (impl_->voice) return true;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        error = "CoInitializeEx failed";
        impl_->lastError = error;
        return false;
    }
    impl_->comReady = true;

    hr = CoCreateInstance(CLSID_SpVoice, nullptr, CLSCTX_ALL, IID_ISpVoice,
                          reinterpret_cast<void**>(&impl_->voice));
    if (FAILED(hr) || !impl_->voice) {
        error = "SAPI ISpVoice unavailable (no installed TTS voice)";
        impl_->lastError = error;
        return false;
    }
    return true;
}

std::vector<VoiceInfo> TtsEngine::voices() const {
    // Voice enumeration requires the full token API; the product path uses the
    // SAPI default voice. Callers that need enumeration can add it explicitly.
    return {};
}

bool TtsEngine::speak(const std::string& text, float rate, float volume,
                      std::string& error) {
    if (!initialize(error)) return false;
    if (!impl_ || !impl_->voice || text.empty()) {
        error = "nothing to speak";
        return false;
    }
    impl_->voice->SetRate(static_cast<long>(rate * 10.0f));
    impl_->voice->SetVolume(static_cast<USHORT>(volume * 100.0f));

    int wlen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (wlen <= 0) { error = "invalid UTF-8 text"; return false; }
    std::wstring wtext(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wtext.data(), wlen);

    HRESULT hr = impl_->voice->Speak(wtext.c_str(), SPF_ASYNC, nullptr);
    if (FAILED(hr)) {
        error = "ISpVoice::Speak failed";
        impl_->lastError = error;
        return false;
    }
    return true;
}

void TtsEngine::stop() {
    if (impl_ && impl_->voice) impl_->voice->Speak(L"", SPF_PURGEBEFORESPEAK, nullptr);
}

TtsStatus TtsEngine::status() const {
    TtsStatus s;
    if (!impl_ || !impl_->voice) {
        s.error = impl_ ? impl_->lastError : "not initialized";
        return s;
    }
    s.available = true;
    SPVOICESTATUS st{};
    if (SUCCEEDED(impl_->voice->GetStatus(&st, nullptr))) {
        s.speaking = st.dwRunningState == 1;
    }
    s.error = impl_->lastError;
    return s;
}

#else

struct TtsEngine::Impl {};
TtsEngine::TtsEngine() : impl_(new Impl()) {}
TtsEngine::~TtsEngine() { delete impl_; }
bool TtsEngine::initialize(std::string& error) { error = "TTS requires Windows SAPI"; return false; }
std::vector<VoiceInfo> TtsEngine::voices() const { return {}; }
bool TtsEngine::speak(const std::string&, float, float, std::string& error) { error = "TTS requires Windows SAPI"; return false; }
void TtsEngine::stop() {}
TtsStatus TtsEngine::status() const { return {}; }

#endif

} // namespace rawrxd::tts