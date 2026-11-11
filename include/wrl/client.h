#pragma once

// ============================================================================
// wrl/client.h — Minimal Microsoft::WRL::ComPtr shim
//
// Windows SDK 10.0.26100.0 does not ship wrl/client.h. This header provides a
// dependency-free ComPtr implementation sufficient for RawrXD's DirectX/Direct2D
// usage in TransparentRenderer.h/cpp. It implements the COM smart-pointer
// contract (AddRef/Release semantics, GetAddressOf for output parameters,
// Attach/Detach for ownership transfer, As<> for QueryInterface).
// ============================================================================

#include <windows.h>
#include <cstddef>
#include <utility>

namespace Microsoft {
namespace WRL {

template <typename T>
class ComPtr {
public:
    typedef T* PtrType;

    // ---- Constructors ----
    ComPtr() noexcept : m_ptr(nullptr) {}

    ComPtr(std::nullptr_t) noexcept : m_ptr(nullptr) {}

    explicit ComPtr(T* other) noexcept : m_ptr(other) {
        if (m_ptr) m_ptr->AddRef();
    }

    ComPtr(const ComPtr& other) noexcept : m_ptr(other.m_ptr) {
        if (m_ptr) m_ptr->AddRef();
    }

    ComPtr(ComPtr&& other) noexcept : m_ptr(other.m_ptr) {
        other.m_ptr = nullptr;
    }

    template <typename U>
    explicit ComPtr(U* other) noexcept : m_ptr(other) {
        if (m_ptr) m_ptr->AddRef();
    }

    template <typename U>
    ComPtr(const ComPtr<U>& other) noexcept : m_ptr(other.Get()) {
        if (m_ptr) m_ptr->AddRef();
    }

    template <typename U>
    ComPtr(ComPtr<U>&& other) noexcept : m_ptr(other.Detach()) {}

    // ---- Destructor ----
    ~ComPtr() noexcept {
        Reset();
    }

    // ---- Assignment ----
    ComPtr& operator=(const ComPtr& other) noexcept {
        if (this != &other) {
            Reset();
            m_ptr = other.m_ptr;
            if (m_ptr) m_ptr->AddRef();
        }
        return *this;
    }

    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            Reset();
            m_ptr = other.m_ptr;
            other.m_ptr = nullptr;
        }
        return *this;
    }

    template <typename U>
    ComPtr& operator=(const ComPtr<U>& other) noexcept {
        Reset();
        m_ptr = other.Get();
        if (m_ptr) m_ptr->AddRef();
        return *this;
    }

    template <typename U>
    ComPtr& operator=(ComPtr<U>&& other) noexcept {
        Reset();
        m_ptr = other.Detach();
        return *this;
    }

    ComPtr& operator=(T* other) noexcept {
        if (m_ptr != other) {
            Reset();
            m_ptr = other;
            if (m_ptr) m_ptr->AddRef();
        }
        return *this;
    }

    ComPtr& operator=(std::nullptr_t) noexcept {
        Reset();
        m_ptr = nullptr;
        return *this;
    }

    // ---- Observers ----
    T* Get() const noexcept { return m_ptr; }

    T** GetAddressOf() noexcept {
        Reset();
        return &m_ptr;
    }

    T** ReleaseAndGetAddressOf() noexcept {
        Reset();
        return &m_ptr;
    }

    T* Detach() noexcept {
        T* ptr = m_ptr;
        m_ptr = nullptr;
        return ptr;
    }

    HRESULT Attach(T* other) noexcept {
        Reset();
        m_ptr = other;
        return S_OK;
    }

    // ---- Modifiers ----
    void Reset() noexcept {
        if (m_ptr) {
            m_ptr->Release();
            m_ptr = nullptr;
        }
    }

    void Swap(ComPtr& other) noexcept {
        T* tmp = m_ptr;
        m_ptr = other.m_ptr;
        other.m_ptr = tmp;
    }

    // ---- Operators ----
    T* operator->() const noexcept { return m_ptr; }

    T& operator*() const noexcept { return *m_ptr; }

    T** operator&() noexcept {
        Reset();
        return &m_ptr;
    }

    operator T*() const noexcept { return m_ptr; }
    operator bool() const noexcept { return m_ptr != nullptr; }
    bool operator!() const noexcept { return m_ptr == nullptr; }

    bool operator==(T* other) const noexcept { return m_ptr == other; }
    bool operator!=(T* other) const noexcept { return m_ptr != other; }
    bool operator==(std::nullptr_t) const noexcept { return m_ptr == nullptr; }
    bool operator!=(std::nullptr_t) const noexcept { return m_ptr != nullptr; }

    // ---- QueryInterface ----
    template <typename U>
    HRESULT As(ComPtr<U>& other) const noexcept {
        if (!m_ptr) {
            other.Reset();
            return E_NOINTERFACE;
        }
        return m_ptr->QueryInterface(__uuidof(U), reinterpret_cast<void**>(other.ReleaseAndGetAddressOf()));
    }

    // As(REFIID, void**) - matches IID_PPV_ARGS(&ptr) call pattern
    HRESULT As(REFIID riid, void** pp) const noexcept {
        if (!m_ptr || !pp) return E_NOINTERFACE;
        return m_ptr->QueryInterface(riid, pp);
    }

    // As(U** pp) - matches raw pointer address pattern &ptr and IDXGIDevice** pp
    template <typename U>
    HRESULT As(U** pp) const noexcept {
        if (!m_ptr || !pp) return E_NOINTERFACE;
        return m_ptr->QueryInterface(__uuidof(U), reinterpret_cast<void**>(pp));
    }

private:
    T* m_ptr;
};

// Helper: Make<ComPtr<T>>(args...) - allocate and wrap
template <typename T, typename... Args>
ComPtr<T> Make(Args&&... args) {
    return ComPtr<T>(new T(std::forward<Args>(args)...));
}

} // namespace WRL
} // namespace Microsoft
