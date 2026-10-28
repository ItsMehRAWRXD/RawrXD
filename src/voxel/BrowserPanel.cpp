// ============================================================================
// BrowserPanel.cpp — the WebView2 host.
//
// The browser runtime is loaded from WebView2Loader.dll at run time, the
// same way the IDE loads it, so there is no import library to ship and the
// panel works wherever the loader can be found.
//
// The three COM callbacks below are the whole of the plumbing: one for
// the environment, one for the controller and one for the messages from
// the page.
// ============================================================================

#include "BrowserPanel.hpp"

#include <fstream>
#include <sstream>

namespace sunshine {

namespace {

std::wstring widen(const std::string& text) {
    if (text.empty()) return std::wstring();
    const int size = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                         static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                         out.data(), size);
    return out;
}

std::string narrow(const std::wstring& text) {
    if (text.empty()) return std::string();
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                         static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                         out.data(), size, nullptr, nullptr);
    return out;
}

} // namespace

// The base of the COM callbacks. It holds the reference count and the
// identity of the object.
template <typename T>
struct CallbackBase : public T {
    ULONG refs = 1;

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(T)) {
            *out = static_cast<T*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG count = --refs;
        if (count == 0) delete this;
        return count;
    }
};

namespace {

// A small reader for the fields of the commands. The page only sends flat
// objects with numbers and strings, so a full parser is not needed, and a
// small one cannot be got wrong in a way that matters.
bool findNumber(const std::string& text, const std::string& key, float& out) {
    const std::string needle = "\"" + key + "\"";
    const size_t at = text.find(needle);
    if (at == std::string::npos) return false;
    size_t i = text.find(':', at + needle.size());
    if (i == std::string::npos) return false;
    ++i;
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
    if (i >= text.size()) return false;
    try {
        out = std::stof(text.substr(i));
    } catch (...) {
        return false;
    }
    return true;
}

bool findString(const std::string& text, const std::string& key, std::string& out) {
    const std::string needle = "\"" + key + "\"";
    const size_t at = text.find(needle);
    if (at == std::string::npos) return false;
    size_t i = text.find(':', at + needle.size());
    if (i == std::string::npos) return false;
    ++i;
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
    if (i >= text.size() || text[i] != '"') return false;
    ++i;
    const size_t end = text.find('"', i);
    if (end == std::string::npos) return false;
    out = text.substr(i, end - i);
    return true;
}

} // namespace

// The message handler. The page sends JSON commands and the panel queues
// them for the engine.
struct PanelMessageHandler : CallbackBase<ICoreWebView2WebMessageReceivedEventHandler> {
    BrowserPanel* panel = nullptr;

    HRESULT STDMETHODCALLTYPE Invoke(ICoreWebView2* sender,
                                     ICoreWebView2WebMessageReceivedEventArgs* args) override {
        (void)sender;
        if (!panel || !args) return S_OK;

        LPWSTR json = nullptr;
        if (FAILED(args->get_WebMessageAsJson(&json)) || !json) return S_OK;

        const std::string text = narrow(json);
        CoTaskMemFree(json);

        std::string type;
        if (!findString(text, "type", type)) return S_OK;

        BrowserCommand command;
        command.type = type;
        command.valid = true;
        findNumber(text, "forward", command.forward);
        findNumber(text, "strafe", command.strafe);
        findNumber(text, "rise", command.rise);
        findNumber(text, "turnX", command.turnX);
        findNumber(text, "turnY", command.turnY);

        if (type == "ready") {
            panel->pageReady_ = true;
        }
        panel->commands_.push_back(command);
        return S_OK;
    }
};

// The controller callback. It sets the page up when the controller is
// ready.
//
// It comes before the environment callback because the environment
// callback creates one of these, and a type has to be complete before it
// can be allocated.
struct ControllerHandler : CallbackBase<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> {
    BrowserPanel* panel = nullptr;
    HWND parent = nullptr;
    RECT bounds{};

    HRESULT STDMETHODCALLTYPE Invoke(HRESULT hr, ICoreWebView2Controller* controller) override {
        if (FAILED(hr) || !controller) {
            if (panel) panel->lastError_ = "the browser controller could not be created";
            return S_OK;
        }
        if (!panel) return S_OK;

        panel->controller_ = controller;
        controller->AddRef();

        ICoreWebView2* webview = nullptr;
        if (FAILED(controller->get_CoreWebView2(&webview)) || !webview) {
            panel->lastError_ = "the browser page could not be reached";
            return S_OK;
        }
        panel->webview_ = webview;
        webview->AddRef();

        // Scripts and web messages have to be on for the bridge to work.
        ICoreWebView2Settings* settings = nullptr;
        if (SUCCEEDED(webview->get_Settings(&settings)) && settings) {
            settings->put_IsScriptEnabled(TRUE);
            settings->put_IsWebMessageEnabled(TRUE);
            settings->put_AreDefaultScriptDialogsEnabled(FALSE);
            settings->put_AreDevToolsEnabled(TRUE);
            settings->Release();
        }

        controller->put_Bounds(bounds);
        controller->put_IsVisible(TRUE);

        auto* messageHandler = new PanelMessageHandler();
        messageHandler->panel = panel;
        EventRegistrationToken token{};
        webview->add_WebMessageReceived(messageHandler, &token);
        messageHandler->Release();

        return S_OK;
    }
};

// The environment callback. It creates the controller when the
// environment is ready.
struct EnvironmentHandler : CallbackBase<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler> {
    BrowserPanel* panel = nullptr;
    HWND parent = nullptr;
    RECT bounds{};

    HRESULT STDMETHODCALLTYPE Invoke(HRESULT hr, ICoreWebView2Environment* env) override {
        if (FAILED(hr) || !env) {
            if (panel) {
                char text[160];
                snprintf(text, sizeof(text),
                         "the browser environment could not be created (%08x)",
                         static_cast<unsigned>(hr));
                panel->lastError_ = text;
            }
            return S_OK;
        }
        if (!panel) return S_OK;

        panel->environment_ = env;
        env->AddRef();

        // The browser version, for the receipt.
        LPWSTR version = nullptr;
        if (SUCCEEDED(env->get_BrowserVersionString(&version)) && version) {
            panel->browserVersion_ = narrow(version);
            CoTaskMemFree(version);
        }

        auto* controllerHandler = new ControllerHandler();
        controllerHandler->panel = panel;
        controllerHandler->parent = parent;
        controllerHandler->bounds = bounds;

        env->CreateCoreWebView2Controller(parent, controllerHandler);
        return S_OK;
    }
};

BrowserPanel::~BrowserPanel() {
    destroy();
}

void BrowserPanel::destroy() {
    if (webview_) {
        webview_->Release();
        webview_ = nullptr;
    }
    if (controller_) {
        controller_->Close();
        controller_->Release();
        controller_ = nullptr;
    }
    if (environment_) {
        environment_->Release();
        environment_ = nullptr;
    }
    if (comInitialised_) {
        CoUninitialize();
        comInitialised_ = false;
    }
    pageReady_ = false;
}

bool BrowserPanel::create(HWND parent, RECT bounds, const std::wstring& userDataFolder,
                          std::string& error) {
    // The browser is a COM object, and COM has to be initialised on the
    // thread that makes it. Without this the environment is refused with
    // CO_E_NOTINITIALIZED, which is 0x800401F0.
    if (!comInitialised_) {
        const HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
            error = "the thread could not be prepared for the browser";
            return false;
        }
        comInitialised_ = true;
    }

    // The loader is found next to the executable, in the working
    // directory, or in the webview2 folder of the tree.
    const char* candidates[] = {
        "WebView2Loader.dll",
        "..\\WebView2Loader.dll",
        "..\\..\\webview2\\build\\native\\x64\\WebView2Loader.dll",
        "..\\..\\..\\Ship\\webview2\\build\\native\\x64\\WebView2Loader.dll",
    };

    HMODULE loader = nullptr;
    for (const char* candidate : candidates) {
        loader = LoadLibraryA(candidate);
        if (loader) break;
    }
    if (!loader) {
        // The folder of the executable is tried as well, because the
        // working directory is not always the folder of the executable.
        wchar_t path[MAX_PATH] = {0};
        const DWORD length = GetModuleFileNameW(nullptr, path, MAX_PATH);
        if (length > 0 && length < MAX_PATH) {
            std::wstring directory(path, path + length);
            const size_t slash = directory.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                directory = directory.substr(0, slash);
                directory += L"\\WebView2Loader.dll";
                loader = LoadLibraryW(directory.c_str());
            }
        }
    }
    if (!loader) {
        error = "WebView2Loader.dll could not be found";
        return false;
    }

    auto createEnvironment = reinterpret_cast<CreateCoreWebView2EnvironmentWithOptionsFunc>(
        GetProcAddress(loader, "CreateCoreWebView2EnvironmentWithOptions"));
    if (!createEnvironment) {
        error = "WebView2Loader.dll does not export the entry point";
        return false;
    }

    auto* handler = new EnvironmentHandler();
    handler->panel = this;
    handler->parent = parent;
    handler->bounds = bounds;

    const HRESULT hr = createEnvironment(nullptr, userDataFolder.c_str(), nullptr, handler);
    handler->Release();

    if (FAILED(hr)) {
        error = "the browser environment could not be started: " +
                std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    return true;
}

void BrowserPanel::setBounds(RECT bounds) {
    if (controller_) controller_->put_Bounds(bounds);
}

bool BrowserPanel::loadHtml(const std::string& html, std::string& error) {
    if (!webview_) {
        error = "the browser is not ready";
        return false;
    }
    const HRESULT hr = webview_->NavigateToString(widen(html).c_str());
    if (FAILED(hr)) {
        error = "the page could not be loaded: " + std::to_string(static_cast<unsigned>(hr));
        return false;
    }
    return true;
}

bool BrowserPanel::loadFile(const std::string& path, std::string& error) {
    if (!webview_) {
        error = "the browser is not ready";
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        error = "the page could not be read: " + path;
        return false;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return loadHtml(buffer.str(), error);
}

bool BrowserPanel::postJson(const std::string& json) {
    if (!webview_) return false;
    const HRESULT hr = webview_->PostWebMessageAsJson(widen(json).c_str());
    return SUCCEEDED(hr);
}

bool BrowserPanel::executeScript(const std::string& script) {
    if (!webview_) return false;
    const HRESULT hr = webview_->ExecuteScript(widen(script).c_str(), nullptr);
    return SUCCEEDED(hr);
}

std::vector<BrowserCommand> BrowserPanel::takeCommands() {
    std::vector<BrowserCommand> out;
    out.swap(commands_);
    return out;
}

} // namespace sunshine
