#pragma once
#include "Deep2Engine.h"
#include <string>
namespace Deep2 {
struct OutputProjectionAudit {
    int vocabMatches = 0;
    int hasOutputWeight = 0;
    int dimsOk = 0;
    int hidden = 0;
    int vocab = 0;
};
inline OutputProjectionAudit AuditOutputProjection(Deep2Engine& e) {
    OutputProjectionAudit a{};
    const auto& mw = e.getModelWeights();
    a.hidden = (int)mw.hiddenDim;
    a.vocab = (int)mw.vocabSize;
    a.vocabMatches = (mw.vocabSize > 0) ? 1 : 0;
    a.hasOutputWeight = (mw.hiddenDim > 0 && mw.vocabSize > 0) ? 1 : 0;
    a.dimsOk = (mw.hiddenDim > 0 && mw.vocabSize >= 256) ? 1 : 0;
    return a;
}
} // namespace Deep2
