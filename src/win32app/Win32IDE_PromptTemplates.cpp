// =============================================================================
// Win32IDE_PromptTemplates.cpp — A4 prompt templates (TOP50 A4).
// =============================================================================
// User-defined system prompts, project scope (.rawrxd/prompt_templates.json in
// the workspace) overriding global scope (%APPDATA%/RawrXD/prompt_templates.json).
// applyPromptTemplate() sets the active system prompt; submitAgentPrompt()
// prepends it to the next agent message.
// =============================================================================
#include "Win32IDE.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

std::string GlobalTemplatePath() {
    const char* appdata = std::getenv("APPDATA");
    return std::string(appdata ? appdata : ".") +
           "/RawrXD/prompt_templates.json";
}

}  // namespace

std::vector<Win32IDE::PromptTemplate> Win32IDE::listPromptTemplates() const {
    std::vector<PromptTemplate> out;
    auto load = [&out](const std::string& path, const std::string& scope) {
        std::ifstream in(path);
        if (!in) return;
        try {
            nlohmann::json j;
            in >> j;
            if (!j.is_array()) return;
            for (const auto& t : j) {
                PromptTemplate p;
                p.name = t.value("name", "");
                p.body = t.value("body", "");
                p.scope = scope;
                if (!p.name.empty()) out.push_back(std::move(p));
            }
        } catch (...) {
        }
    };
    load(GlobalTemplatePath(), "global");
    load(m_gitRepoPath + "/.rawrxd/prompt_templates.json", "project");
    return out;
}

bool Win32IDE::savePromptTemplate(const std::string& name,
                                  const std::string& body,
                                  const std::string& scope) {
    if (name.empty() || body.empty()) return false;
    const std::string path = (scope == "project")
        ? m_gitRepoPath + "/.rawrxd/prompt_templates.json"
        : GlobalTemplatePath();
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path(), ec);
    nlohmann::json j = nlohmann::json::array();
    std::ifstream in(path);
    if (in) {
        try { in >> j; } catch (...) { j = nlohmann::json::array(); }
    }
    if (!j.is_array()) j = nlohmann::json::array();
    bool replaced = false;
    for (auto& t : j) {
        if (t.value("name", "") == name) {
            t["body"] = body;
            replaced = true;
            break;
        }
    }
    if (!replaced) j.push_back({{"name", name}, {"body", body}});
    std::ofstream out(path);
    if (!out) return false;
    out << j.dump(2);
    return true;
}

bool Win32IDE::applyPromptTemplate(const std::string& name) {
    for (const auto& t : listPromptTemplates()) {
        if (t.name == name) {
            m_activeSystemPrompt = t.body;
            appendToOutput("[Prompt] Active system prompt: " + name + " (" +
                           t.scope + ")\n");
            return true;
        }
    }
    appendToOutput("[Prompt] Template not found: " + name + "\n");
    return false;
}