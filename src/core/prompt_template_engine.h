#pragma once

#include <string>
#include <vector>
#include <map>

namespace RawrXD {
namespace Prompt {

enum class TemplateType {
    SYSTEM,
    USER,
    CUSTOM,
    TOOL,
    COMPLETION
};

struct PromptTemplate {
    std::string id;
    std::string name;
    TemplateType type = TemplateType::CUSTOM;
    std::string templateText;
    std::string systemPrompt;
    int maxTokens = 4096;
    float temperature = 0.4f;
    std::vector<std::string> requiredVars;
};

class PromptTemplateEngine {
public:
    static PromptTemplateEngine& Global();
    void registerBuiltins();
    void registerTemplate(const PromptTemplate& tmpl);
    void removeTemplate(const std::string& id);
    std::vector<std::string> listTemplates();
};

} // namespace Prompt
} // namespace RawrXD
