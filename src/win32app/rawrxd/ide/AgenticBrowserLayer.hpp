#pragma once

#include <windows.h>
#include <exdisp.h>
#include <exedit.h>
#include <mshtmhst.h>
#include <olectl.h>
#include <string>

namespace RawrXD {
namespace Ide {

// Native IWebBrowser2 host (no Qt, no new external product deps — the WebBrowser
// control ships with Windows). Real rendering/navigation via the OS HTML control.
class AgenticBrowserLayer;

class BrowserSite : public IOleClientSite, public IOleInPlaceSite, public IOleInPlaceFrame {
public:
    explicit BrowserSite(HWND parent) : m_parent(parent) {}
    // IUnknown
    HRESULT QueryInterface(REFIID riid, void** pp) override {
        if (riid == IID_IUnknown || riid == IID_IOleClientSite) { *pp = static_cast<IOleClientSite*>(this); AddRef(); return S_OK; }
        if (riid == IID_IOleInPlaceSite) { *pp = static_cast<IOleInPlaceSite*>(this); AddRef(); return S_OK; }
        if (riid == IID_IOleInPlaceFrame) { *pp = static_cast<IOleInPlaceFrame*>(this); AddRef(); return S_OK; }
        *pp = nullptr; return E_NOINTERFACE;
    }
    ULONG AddRef() override { return ++m_ref; }
    ULONG Release() override { if (--m_ref == 0) { delete this; return 0; } return m_ref; }
    // IOleClientSite
    HRESULT SaveObject() override { return E_NOTIMPL; }
    HRESULT GetMoniker(DWORD, DWORD, IMoniker**) override { return E_NOTIMPL; }
    HRESULT GetContainer(IOleContainer**) override { return E_NOTIMPL; }
    HRESULT ShowObject(DWORD) override { return S_OK; }
    HRESULT OnShowWindow(BOOL) override { return S_OK; }
    HRESULT RequestNewObjectLayout() override { return E_NOTIMPL; }
    // IOleInPlaceSite
    HRESULT GetWindow(HWND* ph) override { if (ph) *ph = m_parent; return S_OK; }
    HRESULT ContextSensitiveHelp(BOOL) override { return E_NOTIMPL; }
    HRESULT CanInPlaceActivate() override { return S_OK; }
    HRESULT OnInPlaceActivate() override { return S_OK; }
    HRESULT OnUIActivate() override { return S_OK; }
    HRESULT GetWindowContext(IOleInPlaceFrame** ppFrame, IOleInPlaceUIWindow** ppDoc, LPRECT, LPRECT, LPRECT, LPRECT) override {
        if (ppFrame) { AddRef(); *ppFrame = this; } else if (ppFrame) *ppFrame = nullptr;
        if (ppDoc) *ppDoc = nullptr;
        return S_OK;
    }
    HRESULT Scroll(SIZE) override { return S_OK; }
    HRESULT OnUIDeactivate(BOOL) override { return S_OK; }
    HRESULT OnInPlaceDeactivate() override { return S_OK; }
    HRESULT DiscardUndoState() override { return S_OK; }
    HRESULT DeactivateAndUndo() override { return S_OK; }
    HRESULT OnPosRectChange(LPCRECT) override { return S_OK; }
    // IOleInPlaceFrame
    HRESULT GetBorder(LPRECT lprectBorder) override { if (lprectBorder) GetClientRect(m_parent, lprectBorder); return S_OK; }
    HRESULT RequestBorderSpace(LPCBORDERWIDTHS) override { return E_NOTIMPL; }
    HRESULT SetBorderSpace(LPCBORDERWIDTHS) override { return S_OK; }
    HRESULT SetActiveObject(IOleInPlaceActiveObject*, LPCSTR) override { return S_OK; }
    HRESULT InsertMenus(HMENU, LPOLEMENUGROUPWIDTHS, HANDLE*) override { return S_OK; }
    HRESULT SetMenu(HMENU, HOLEMENU, HWND) override { return S_OK; }
    HRESULT RemoveMenus(HMENU) override { return S_OK; }
    HRESULT SetStatusText(LPCOLESTR) override { return S_OK; }
    HRESULT EnableModeless(BOOL) override { return S_OK; }
    HRESULT TranslateAccelerator(LPMSG, WORD) override { return S_FALSE; }
private:
    HWND m_parent; ULONG m_ref = 1;
};

class AgenticBrowserLayer {
public:
    AgenticBrowserLayer() = default;
    ~AgenticBrowserLayer() { Destroy(); }

    HWND CreateHost(HWND hParent, HINSTANCE) {
        if (m_hwnd) return m_hwnd;
        if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED))) return nullptr;
        if (FAILED(CoCreateInstance(CLSID_WebBrowser, nullptr, CLSCTX_ALL,
                                    IID_IWebBrowser2, reinterpret_cast<void**>(&m_browser))) || !m_browser)
            return nullptr;
        if (FAILED(m_browser->QueryInterface(IID_IOleObject, reinterpret_cast<void**>(&m_ole))) || !m_ole)
            return nullptr;
        m_site = new BrowserSite(hParent);
        m_ole->SetClientSite(m_site);
        m_ole->SetHostNames(L"RawrXD", L"AgenticBrowser");
        m_ole->DoVerb(OLEIVERB_SHOW, nullptr, m_site, 0, hParent, nullptr);
        m_browser->get_HWND(reinterpret_cast<SHANDLE_PTR*>(&m_hwnd));
        if (m_hwnd) {
            SetParent(m_hwnd, hParent);
            ShowWindow(m_hwnd, SW_SHOW);
        }
        return m_hwnd;
    }

    void setBounds(const RECT& rc) {
        if (m_hwnd) MoveWindow(m_hwnd, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, TRUE);
    }

    bool Navigate(const std::wstring& url) {
        if (!m_browser) return false;
    VARIANT v; VariantInit(&v);
    VARIANT nav{}; VariantInit(&nav);
    return SUCCEEDED(m_browser->Navigate(v.bstrVal ? v.bstrVal : SysAllocString(url.c_str()), &nav, &nav, &nav, &nav));
    }
    bool GoBack()     { return m_browser && SUCCEEDED(m_browser->GoBack()); }
    bool GoForward()  { return m_browser && SUCCEEDED(m_browser->GoForward()); }
    bool Refresh()    { return m_browser && SUCCEEDED(m_browser->Refresh()); }
    bool Stop()       { return m_browser && SUCCEEDED(m_browser->Stop()); }
    bool Focus()      { if (m_hwnd) SetFocus(m_hwnd); return m_hwnd != nullptr; }

    void Destroy() {
        if (m_ole) { m_ole->Close(OLECLOSE_NOSIGNAL); m_ole->Release(); m_ole = nullptr; }
        if (m_browser) { m_browser->Release(); m_browser = nullptr; }
        if (m_hwnd) { DestroyWindow(m_hwnd); m_hwnd = nullptr; }
        m_site = nullptr;  // BrowserSite self-deletes on Release via m_ole teardown
    }

private:
    HWND m_hwnd = nullptr;
    IWebBrowser2* m_browser = nullptr;
    IOleObject* m_ole = nullptr;
    BrowserSite* m_site = nullptr;
};

} // namespace Ide
} // namespace RawrXD