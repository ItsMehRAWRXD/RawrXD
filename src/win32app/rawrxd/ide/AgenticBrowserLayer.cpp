#undef NOINTERFACE
#include <windows.h>
#include "AgenticBrowserLayer.hpp"

#include <exdisp.h>
#include <olectl.h>
#include <objbase.h>
#include <oaidl.h>
#include <ocidl.h>
#include <oleidl.h>
#include <objidl.h>

#undef CreateWindow

namespace RawrXD {
namespace Ide {
namespace {

class BrowserSite : public IOleClientSite, public IOleInPlaceSite {
public:
    explicit BrowserSite(HWND parent) : m_parent(parent) {}
    virtual ~BrowserSite() = default;

    HRESULT __stdcall QueryInterface(REFIID riid, void** ppv) {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IOleClientSite) {
            *ppv = static_cast<IOleClientSite*>(this); AddRef(); return S_OK;
        }
        if (riid == IID_IOleInPlaceSite || riid == IID_IOleWindow) {
            *ppv = static_cast<IOleInPlaceSite*>(this); AddRef(); return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG __stdcall AddRef() { return ++m_ref; }
    ULONG __stdcall Release() { const ULONG n = --m_ref; if (!n) delete this; return n; }

    HRESULT __stdcall SaveObject() { return S_OK; }
    HRESULT __stdcall GetMoniker(DWORD, DWORD, IMoniker**) { return E_NOTIMPL; }
    HRESULT __stdcall GetContainer(IOleContainer**) { return E_NOTIMPL; }
    HRESULT __stdcall ShowObject() { return S_OK; }
    HRESULT __stdcall OnShowWindow(BOOL) { return S_OK; }
    HRESULT __stdcall RequestNewObjectLayout() { return E_NOTIMPL; }

    HRESULT __stdcall GetWindow(HWND* phwnd) { if (phwnd) *phwnd = m_parent; return S_OK; }
    HRESULT __stdcall ContextSensitiveHelp(BOOL) { return E_NOTIMPL; }
    HRESULT __stdcall CanInPlaceActivate() { return S_OK; }
    HRESULT __stdcall OnInPlaceActivate() { return S_OK; }
    HRESULT __stdcall OnUIActivate() { return S_OK; }
    HRESULT __stdcall GetWindowContext(IOleInPlaceFrame** ppFrame, IOleInPlaceUIWindow** ppDoc,
                                       LPRECT, LPRECT, LPOLEINPLACEFRAMEINFO) {
        if (ppFrame) *ppFrame = nullptr;
        if (ppDoc) *ppDoc = nullptr;
        return E_NOTIMPL;
    }
    HRESULT __stdcall Scroll(SIZE) { return E_NOTIMPL; }
    HRESULT __stdcall OnPosRectChange(LPCRECT) { return S_OK; }
    HRESULT __stdcall OnInPlaceDeactivate() { return S_OK; }
    HRESULT __stdcall OnUIDeactivate(BOOL) { return S_OK; }
    HRESULT __stdcall DiscardUndoState() { return S_OK; }
    HRESULT __stdcall DeactivateAndUndo() { return S_OK; }

private:
    HWND m_parent = nullptr;
    ULONG m_ref = 1;
};

} // namespace

struct AgenticBrowserLayer::Impl {
    HWND hwnd = nullptr;
    IWebBrowser2* browser = nullptr;
    IOleObject* ole = nullptr;
    BrowserSite* site = nullptr;

    ~Impl() {
        if (browser) browser->Stop();
        if (ole) ole->Close(static_cast<OLECLOSE>(1));
        if (browser) browser->Release();
        if (ole) ole->Release();
        if (site) site->Release();
    }
};

AgenticBrowserLayer::AgenticBrowserLayer() : impl_(new Impl()) {}
AgenticBrowserLayer::~AgenticBrowserLayer() { delete impl_; }

void AgenticBrowserLayer::setBounds(const RECT& rc) {
    if (impl_ && impl_->hwnd)
        MoveWindow(impl_->hwnd, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, TRUE);
}

HWND AgenticBrowserLayer::CreateHost(HWND hParent, HINSTANCE) {
    if (!impl_) return nullptr;
    if (impl_->hwnd) return impl_->hwnd;
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return nullptr;
    if (FAILED(CoCreateInstance(CLSID_WebBrowser, nullptr, CLSCTX_ALL, IID_IWebBrowser2,
                                reinterpret_cast<void**>(&impl_->browser))) || !impl_->browser)
        return nullptr;
    if (FAILED(impl_->browser->QueryInterface(IID_IOleObject,
                                              reinterpret_cast<void**>(&impl_->ole))) || !impl_->ole)
        return nullptr;
    impl_->site = new BrowserSite(hParent);
    impl_->ole->SetClientSite(impl_->site);
    RECT rc{0, 0, 200, 100};
    impl_->ole->DoVerb(OLEIVERB_SHOW, nullptr, impl_->site, 0, hParent, &rc);
    IOleWindow* win = nullptr;
    if (SUCCEEDED(impl_->ole->QueryInterface(IID_IOleWindow,
                                             reinterpret_cast<void**>(&win))) && win) {
        win->GetWindow(&impl_->hwnd);
        win->Release();
    }
    impl_->browser->put_Visible(VARIANT_TRUE);
    return impl_->hwnd;
}

bool AgenticBrowserLayer::Navigate(const std::wstring& url) {
    if (!impl_ || !impl_->browser) return false;
    BSTR b = SysAllocString(url.c_str());
    VARIANT empty{};
    const HRESULT hr = impl_->browser->Navigate(b, &empty, &empty, &empty, &empty);
    SysFreeString(b);
    return SUCCEEDED(hr);
}

bool AgenticBrowserLayer::Back() { return impl_ && impl_->browser && SUCCEEDED(impl_->browser->GoBack()); }
bool AgenticBrowserLayer::Forward() { return impl_ && impl_->browser && SUCCEEDED(impl_->browser->GoForward()); }
bool AgenticBrowserLayer::Reload() { return impl_ && impl_->browser && SUCCEEDED(impl_->browser->Refresh()); }
bool AgenticBrowserLayer::Stop() { return impl_ && impl_->browser && SUCCEEDED(impl_->browser->Stop()); }
bool AgenticBrowserLayer::Focus() { if (impl_ && impl_->hwnd) SetFocus(impl_->hwnd); return impl_ && impl_->hwnd; }

std::wstring AgenticBrowserLayer::CurrentUrl() {
    if (!impl_ || !impl_->browser) return std::wstring();
    BSTR url = nullptr;
    std::wstring out;
    if (SUCCEEDED(impl_->browser->get_LocationURL(&url)) && url) {
        out = url;
        SysFreeString(url);
    }
    return out;
}

void AgenticBrowserLayer::Shutdown() {
    if (impl_) impl_->~Impl();
    impl_ = nullptr;
}

} // namespace Ide
} // namespace RawrXD