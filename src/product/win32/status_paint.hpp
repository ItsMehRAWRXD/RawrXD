#pragma once
#include "../ide/editor_event.hpp"
#include "../runtime/event_bus.hpp"
#include <string>
namespace rawr::product {

inline std::string PaintStatusLine(const TaskStatus& t) {
    std::string s = "[";
    s += t.name ? t.name : "";
    s += "] ";
    s += StatusLine(t);
    s += " ";
    s += std::to_string(t.pct);
    s += "%";
    return s;
}

inline std::string PaintFromBus(const EventBus& bus) {
    if (bus.q.empty()) return PaintStatusLine(TaskStatus{"idle", "idle", 0});
    const Ev& e = bus.q.back();
    const char* st = "idle";
    if (e.kind == EvKind::Infer) st = "infer";
    else if (e.kind == EvKind::Index) st = "index";
    else if (e.kind == EvKind::Tool) st = "tool";
    else if (e.kind == EvKind::Fail) st = "fail";
    TaskStatus t{e.name.c_str(), st, st[0] == 'f' ? 0u : 50u};
    return PaintStatusLine(t);
}

} // namespace rawr::product
