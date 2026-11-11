// ============================================================================
// inlay_hints_provider.h — Inlay Hints Interface
// ============================================================================

#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace LanguageServices {

enum class InlayHintKind {
    Type,
    Parameter,
    Chaining,
    ClosureReturn,
    Declaration
};

struct InlayHint {
    int line;
    int column;
    InlayHintKind kind;
    std::string label;
    std::string tooltip;
};

class InlayHintsProvider {
public:
    std::vector<InlayHint> provideHints(const std::string& filePath,
                                        const std::string& content,
                                        int startLine = 0,
                                        int endLine = -1);
    void clearCache(const std::string& filePath = "");
    void setEnabled(bool enabled);
};

} // namespace LanguageServices
} // namespace RawrXD
