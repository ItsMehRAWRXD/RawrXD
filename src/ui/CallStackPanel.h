#pragma once
// UI::CallStackPanel — debugger call-stack panel state (native, no Qt).
#ifndef RAWRXD_UI_CALLSTACK_PANEL_H
#define RAWRXD_UI_CALLSTACK_PANEL_H

#include <cstdint>
#include <string>
#include <vector>

namespace UI {

struct CallStackFrame {
    uint64_t rip = 0;
    std::string module;
    std::string symbol;
};

class CallStackPanel {
public:
    void setFrames(const std::vector<CallStackFrame>& frames) { m_frames = frames; }
    const std::vector<CallStackFrame>& frames() const { return m_frames; }
    void clear() { m_frames.clear(); }
    bool empty() const { return m_frames.empty(); }

private:
    std::vector<CallStackFrame> m_frames;
};

}  // namespace UI

#endif