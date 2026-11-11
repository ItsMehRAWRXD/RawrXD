#include "prompt_template_engine.h"

namespace RawrXD {
namespace Prompt {

PromptTemplateEngine& PromptTemplateEngine::Global() {
    static PromptTemplateEngine instance;
    return instance;
}

void PromptTemplateEngine::registerBuiltins() {
    // Built-in templates registered lazily
}

void PromptTemplateEngine::registerTemplate(const PromptTemplate& tmpl) {
    (void)tmpl;
}

void PromptTemplateEngine::removeTemplate(const std::string& id) {
    (void)id;
}

std::vector<std::string> PromptTemplateEngine::listTemplates() {
    return {};
}

} // namespace Prompt
} // namespace RawrXD
