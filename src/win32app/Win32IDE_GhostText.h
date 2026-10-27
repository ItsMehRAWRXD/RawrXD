#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>
#include <string>

class NativeGhostTextController {
public:
    using Request = std::function<void(const std::string&, std::function<void(const std::string&, bool)>)>;

    NativeGhostTextController() = default;
    ~NativeGhostTextController();

    bool attach(HWND host, HWND editor, Request request,
                std::string promptPrefix = {});
    void detach();
    void onEditorChanged();
    bool handleMessage(UINT message, WPARAM wParam, LPARAM lParam);
    bool accept();
    void dismiss();
    bool active() const { return !m_completion.empty(); }
    bool attachedTo(HWND target) const { return target && m_editor == target; }

private:
    static LRESULT CALLBACK editorProc(HWND, UINT, WPARAM, LPARAM);
    void requestCompletion();
    void showCompletion(const std::string& completion, uint64_t generation);
    void positionHint();
    std::string editorText() const;

    HWND m_host = nullptr;
    HWND m_editor = nullptr;
    HWND m_hint = nullptr;
    WNDPROC m_originalProc = nullptr;
    Request m_request;
    std::string m_promptPrefix;
    std::string m_completion;
    std::string m_snapshot;
    uint64_t m_generation = 0;
    UINT_PTR m_timer = 0;
};

