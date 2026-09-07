#pragma once
#include "../../win32app/ProductGhostBind.hpp"
#include "../complete/ghost_text.hpp"
#include "../ide/editor_event.hpp"
#include "../runtime/event_bus.hpp"
#include "ghost_overlay.hpp"
#include <string>
namespace rawr::product {

struct Chrome {
    Document doc;
    GhostOverlay overlay;
    Win32GhostView ghost;
    TaskStatus status;
    EventBus* bus = nullptr;

    bool receiveCandidate(const Candidate& c) {
        ProductGhostCopy cp{};
        cp.text = c.text.c_str();
        cp.gen = doc.gen;
        cp.id = c.id;
        cp.line = (int)doc.line;
        cp.col = (int)doc.col;
        if (!BindProductGhost(ghost, cp)) return false;
        overlay.ghost.text = ghost.content;
        overlay.ghost.gen = ghost.gen;
        overlay.ghost.stale = 0;
        overlay.ghost.accepted = 0;
        overlay.painted = 0;
        overlay.docMutated = 0;
        if (bus) bus->push(EvKind::Infer, doc.gen, "candidate", c.text.c_str());
        status = TaskStatus{"complete", "done", 100};
        return true;
    }

    bool paintGhost() {
        if (!GhostViewMayPaint(ghost, doc.gen)) return false;
        overlay.painted = 1;
        return true;
    }

    bool accept() {
        if (!GhostViewMayPaint(ghost, doc.gen)) return false;
        bool ok = overlay.acceptInto(doc);
        if (ok) ghost.accepted = true;
        ghost.visible = false;
        if (bus) bus->push(EvKind::Editor, doc.gen, "accept",
                           ok ? overlay.ghost.text.c_str() : "stale");
        return ok;
    }

    void typeChar(char c) {
        doc.typeChar(c);
        ReflectGhostGen(ghost, doc.gen);
        overlay.onDocGen(doc.gen);
        if (!ghost.visible && bus)
            bus->push(EvKind::Editor, doc.gen, "stale", "type");
    }

    std::string statusPaint() const {
        std::string s = status.name;
        s += ":";
        s += StatusLine(status);
        s += " ";
        s += std::to_string(status.pct);
        return s;
    }
};

} // namespace rawr::product
