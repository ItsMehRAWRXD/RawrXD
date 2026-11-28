#include "rawrxd/stt/SttEngine.h"

#if defined(_WIN32)
#include <windows.h>
#include <sapi.h>
#include <sphelper.h>
#include <atomic>
#include <thread>
#endif

namespace rawrxd::stt {

#if defined(_WIN32)

struct SttEngine::Impl {
    ISpRecoContext* context = nullptr;
    ISpRecoGrammar* grammar = nullptr;
    ISpRecognizer* recognizer = nullptr;
    bool comReady = false;
    std::atomic<bool> listening{false};
    std::thread worker;
    Callback callback;
    std::string lastError;

    ~Impl() { listening.store(false); if (worker.joinable()) worker.join(); if (grammar) grammar->Release(); if (context) context->Release();
              if (recognizer) recognizer->Release(); if (comReady) CoUninitialize(); }

    void run() {
        while (listening.load()) {
            SPEVENT events[16]{};
            ULONG got = 0;
            ULONGLONG next = 0;
            if (FAILED(context->GetEvents(16, events, &got)) || got == 0) {
                Sleep(20);
                continue;
            }
            for (ULONG i = 0; i < got; ++i) {
                if (events[i].eEventId == SPEI_SENTENCE_BOUNDARY && events[i].lParam && callback) {
                    ISpRecoResult* result = reinterpret_cast<ISpRecoResult*>(events[i].lParam);
                    WCHAR* text = nullptr;
                    if (SUCCEEDED(result->GetText(0, -1, TRUE, &text, nullptr)) && text) {
                        int len = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
                        if (len > 0) {
                            std::string out(static_cast<size_t>(len - 1), '\0');
                            WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), len, nullptr, nullptr);
                            callback(out);
                        }
                        CoTaskMemFree(text);
                    }
                    result->Release();
                }
            }
        }
    }
};

SttEngine::SttEngine() : impl_(new Impl()) {}
SttEngine::~SttEngine() { delete impl_; }

bool SttEngine::initialize(std::string& error) {
    if (!impl_) return false;
    if (impl_->context) return true;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) { error = "CoInitializeEx failed"; return false; }
    impl_->comReady = true;

    hr = CoCreateInstance(CLSID_SpSharedRecognizer, nullptr, CLSCTX_ALL,
                          IID_ISpRecognizer, reinterpret_cast<void**>(&impl_->recognizer));
    if (FAILED(hr) || !impl_->recognizer) { error = "no SAPI recognizer installed"; return false; }

    hr = impl_->recognizer->CreateRecoContext(&impl_->context);
    if (FAILED(hr) || !impl_->context) { error = "CreateRecoContext failed"; return false; }

    hr = impl_->context->CreateGrammar(1, &impl_->grammar);
    if (FAILED(hr) || !impl_->grammar) { error = "CreateGrammar failed"; return false; }

    hr = impl_->grammar->LoadDictation(nullptr, static_cast<SPLOADOPTIONS>(0));
    if (FAILED(hr)) { error = "LoadDictation failed"; return false; }

    return true;
}

bool SttEngine::start(Callback callback, std::string& error) {
    if (!initialize(error)) return false;
    if (impl_->listening.load()) return true;
    impl_->callback = std::move(callback);
    if (FAILED(impl_->grammar->SetDictationState(SPRS_ACTIVE))) {
        error = "SetDictationState failed";
        return false;
    }
    impl_->listening.store(true);
    impl_->worker = std::thread([this] { impl_->run(); });
    return true;
}

void SttEngine::stop() {
    if (!impl_) return;
    impl_->listening.store(false);
    if (impl_->worker.joinable()) impl_->worker.join();
    if (impl_->grammar) impl_->grammar->SetDictationState(SPRS_INACTIVE);
}

bool SttEngine::listening() const {
    return impl_ && impl_->listening.load();
}

#else

struct SttEngine::Impl {};
SttEngine::SttEngine() : impl_(new Impl()) {}
SttEngine::~SttEngine() { delete impl_; }
bool SttEngine::initialize(std::string& error) { error = "STT requires Windows SAPI"; return false; }
bool SttEngine::start(Callback, std::string& error) { error = "STT requires Windows SAPI"; return false; }
void SttEngine::stop() {}
bool SttEngine::listening() const { return false; }

#endif

} // namespace rawrxd::stt