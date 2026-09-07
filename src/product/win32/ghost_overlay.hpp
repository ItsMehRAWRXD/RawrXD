#pragma once
#include "../complete/ghost_text.hpp"
#include "document.hpp"
namespace rawr::product {

struct GhostOverlay {
    GhostText ghost;
    int painted = 0;
    int docMutated = 0;

    bool receive(uint64_t docGen, const Candidate& c) {
        ghost = MakeGhost(docGen, c);
        painted = 0;
        docMutated = 0;
        return !ghost.text.empty();
    }

    bool paint() {
        if (ghost.stale || ghost.text.empty()) return false;
        painted = 1;
        return true;
    }

    void onDocGen(uint64_t liveGen) {
        GhostOnGen(ghost, liveGen);
        if (ghost.stale) painted = 0;
    }

    bool acceptInto(Document& doc) {
        if (!GhostAcceptLive(ghost, doc.gen)) return false;
        size_t at = doc.caret;
        if (!doc.apply(DocTxn{at, ghost.text})) return false;
        docMutated = 1;
        painted = 0;
        return true;
    }

    void reject() {
        GhostReject(ghost);
        painted = 0;
        docMutated = 0;
    }
};

} // namespace rawr::product
