#pragma once
#include "../context/file_window.hpp"
#include <cstdint>
#include <string>
namespace rawr::product {

enum class IdeEv : uint8_t { Open = 0, Edit = 1, Cursor = 2, Save = 3, Diag = 4 };

struct EditorEvent {
    IdeEv kind = IdeEv::Edit;
    EditorSnap snap;
    uint64_t tick = 0;
};

struct TaskStatus {
    const char* name = "";
    const char* state = "idle"; // idle|index|infer|tool|done|fail
    uint32_t pct = 0;
};

inline const char* StatusLine(const TaskStatus& t) {
    if (t.state[0] == 'i' && t.state[1] == 'd') return "idle";
    return t.state;
}

} // namespace rawr::product
