// ============================================================================
// DocGenerator.cpp - Documentation Generator Implementation
// ============================================================================

#include "DocGenerator.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <iostream>
#include <regex>

namespace fs = std::filesystem;
namespace Sovereign {

DocGenerator::DocGenerator() = default;
DocGenerator::~DocGenerator() { Shutdown(); }

bool DocGenerator::Initialize(const DocConfig& config) {
    config_ = config;
    fs::create_directories(config_.outputDir);
    initialized_ = true;
    return true;
}

void DocGenerator::Shutdown() { initialized_ = false; }

std::vector<DocPage> DocGenerator::GenerateAPIDocs(const std::vector<std::string>& sourceFiles) {
    std::vector<DocPage> pages;
    
    for (const auto& file : sourceFiles) {
        std::ifstream f(file);
        if (!f) continue;
        
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        
        // Extract class declarations
        std::regex classRegex(R"(class\s+(\w+))");
        std::smatch match;
        std::string::const_iterator searchStart(content.cbegin());
        
        while (std::regex_search(searchStart, content.cend(), match, classRegex)) {
            DocPage page;
            page.title = match[1];
            page.filename = SanitizeFilename(match[1]) + "_api.md";
            page.type = DocType::API;
            
            DocSection overview;
            overview.title = "Overview";
            overview.content = "Class: `" + match[1] + "`\n\nDefined in: `" + file + "`";
            overview.level = 1;
            page.sections.push_back(overview);
            
            // Extract methods
            std::string classContext = match.suffix().str();
            std::regex methodRegex(R"((\w+)\s+(\w+)\s*\(([^)]*)\))");
            std::smethod_match;
            std::string::const_iterator methodStart(classContext.cbegin());
            
            DocSection methods;
            methods.title = "Methods";
            methods.level = 1;
            
            while (std::regex_search(methodStart, classContext.cend(), method_match, methodRegex)) {
                DocSection method;
                method.title = method_match[2];
                method.content = "Returns: `" + method_match[1] + "`\n\nParameters: `" + method_match[3] + "`";
                method.level = 2;
                methods.subsections.push_back(method);
                methodStart = method_match.suffix().first;
            }
            
            page.sections.push_back(methods);
            pages.push_back(page);
            stats_.totalPages++;
            
            searchStart = match.suffix().first;
        }
    }
    
    return pages;
}

DocPage DocGenerator::GenerateClassDoc(const std::string& className, const std::vector<std::string>& methods, const std::vector<std::string>& fields) {
    DocPage page;
    page.title = className;
    page.filename = SanitizeFilename(className) + "_class.md";
    page.type = DocType::API;
    
    DocSection overview;
    overview.title = "Class: " + className;
    overview.content = "## Overview\n\n`" + className + "` provides core functionality for the Sovereign IDE.";
    overview.level = 1;
    page.sections.push_back(overview);
    
    DocSection methodSection;
    methodSection.title = "Methods";
    methodSection.level = 1;
    for (const auto& m : methods) {
        DocSection ms;
        ms.title = m;
        ms.content = "Description of `" + m + "`.";
        ms.level = 2;
        methodSection.subsections.push_back(ms);
    }
    page.sections.push_back(methodSection);
    
    if (!fields.empty()) {
        DocSection fieldSection;
        fieldSection.title = "Fields";
        fieldSection.level = 1;
        for (const auto& f : fields) {
            DocSection fs;
            fs.title = f;
            fs.content = "Field `" + f + "`.";
            fs.level = 2;
            fieldSection.subsections.push_back(fs);
        }
        page.sections.push_back(fieldSection);
    }
    
    stats_.totalPages++;
    return page;
}

DocPage DocGenerator::GenerateUserManual() {
    DocPage page;
    page.title = "User Manual";
    page.filename = "user_manual.md";
    page.type = DocType::USER_MANUAL;
    
    DocSection intro;
    intro.title = "Introduction";
    intro.content = "Welcome to the Sovereign IDE User Manual.\n\nSovereign is a native x64 autonomous development environment.";
    intro.level = 1;
    page.sections.push_back(intro);
    
    DocSection install;
    install.title = "Installation";
    install.content = "## System Requirements\n\n- Windows 10/11 x64\n- 8GB RAM (16GB+ recommended)\n- AVX2-capable CPU\n\n## Installation Steps\n\n1. Download the latest release\n2. Run the installer\n3. Launch Sovereign IDE";
    install.level = 1;
    page.sections.push_back(install);
    
    DocSection quickstart;
    quickstart.title = "Quick Start";
    quickstart.content = "## Opening a Workspace\n\nFile > Open Folder (Ctrl+K Ctrl+O)\n\n## Running Your First Task\n\nType a command in the agent chat panel.\n\nExample: `audit workspace`";
    quickstart.level = 1;
    page.sections.push_back(quickstart);
    
    DocSection features;
    features.title = "Features";
    features.level = 1;
    
    std::vector<std::pair<std::string, std::string>> featureList = {
        {"Agent Modes", "Ask, Plan, Edit, and Agent modes for different workflows."},
        {"Multi-Session", "Multiple concurrent chat sessions with context persistence."},
        {"Tool System", "Built-in tools for file operations, git, terminal, and debugging."},
        {"Extension System", "Community and custom extensions for additional capabilities."},
        {"Model Support", "Local and cloud model support with automatic switching."},
        {"Memory System", "Long-term memory for persistent project context."}
    };
    
    for (const auto& [name, desc] : featureList) {
        DocSection fs;
        fs.title = name;
        fs.content = desc;
        fs.level = 2;
        features.subsections.push_back(fs);
    }
    page.sections.push_back(features);
    
    stats_.totalPages++;
    return page;
}

DocPage DocGenerator::GenerateQuickStart() {
    DocPage page;
    page.title = "Quick Start Guide";
    page.filename = "quickstart.md";
    page.type = DocType::USER_MANUAL;
    
    DocSection step1;
    step1.title = "Step 1: Launch Sovereign";
    step1.content = "Run `SovereignIDE.exe` or `rawrxd.exe` from the command line.";
    step1.level = 1;
    page.sections.push_back(step1);
    
    DocSection step2;
    step2.title = "Step 2: Load a Model";
    step2.content = "Click the model selector in the status bar and choose a GGUF model file.\n\nOr connect to a remote Ollama/OpenAI-compatible endpoint.";
    step2.level = 1;
    page.sections.push_back(step2);
    
    DocSection step3;
    step3.title = "Step 3: Open a Workspace";
    step3.content = "Use File > Open Folder to select your project directory.\n\nThe workspace will be indexed automatically.";
    step3.level = 1;
    page.sections.push_back(step3);
    
    DocSection step4;
    step4.title = "Step 4: Run Your First Task";
    step4.content = "Type a command in the agent panel:\n\n```\naudit workspace\n```\n\nThe agent will scan, analyze, and report on your project.";
    step4.level = 1;
    page.sections.push_back(step4);
    
    stats_.totalPages++;
    return page;
}

DocPage DocGenerator::GenerateArchitectureDocs() {
    DocPage page;
    page.title = "Architecture Overview";
    page.filename = "architecture.md";
    page.type = DocType::ARCHITECTURE;
    
    DocSection overview;
    overview.title = "System Architecture";
    overview.content = "Sovereign IDE is built on a layered architecture:\n\n```\n+------------------+\n|   User Interface  |\n+------------------+\n|   Agent Layer     |\n+------------------+\n|   Tool Layer      |\n+------------------+\n|   Inference Engine|\n+------------------+\n|   Native Runtime  |\n+------------------+\n```";
    overview.level = 1;
    page.sections.push_back(overview);
    
    DocSection layers;
    layers.title = "Layer Descriptions";
    layers.level = 1;
    
    std::vector<std::pair<std::string, std::string>> layerDesc = {
        {"Native Runtime", "x64 MASM/C++ runtime with zero external dependencies. Handles memory management, threading, and system calls."},
        {"Inference Engine", "GGUF model loader, tokenizer, transformer stack, KV cache, and sampling. Supports Q4_K_M through FP8 quantization."},
        {"Tool Layer", "File system, git, terminal, debugger, and MCP tools. Sandboxed execution with permission management."},
        {"Agent Layer", "Planner, reviewer, builder, and specialized agents. Autonomous task execution with telemetry feedback."},
        {"User Interface", "D3D12/Vulkan renderer, syntax highlighting, panels, and input handling."}
    };
    
    for (const auto& [name, desc] : layerDesc) {
        DocSection ls;
        ls.title = name;
        ls.content = desc;
        ls.level = 2;
        layers.subsections.push_back(ls);
    }
    page.sections.push_back(layers);
    
    stats_.totalPages++;
    return page;
}

DocPage DocGenerator::GenerateContributingGuide() {
    DocPage page;
    page.title = "Contributing Guide";
    page.filename = "CONTRIBUTING.md";
    page.type = DocType::CONTRIBUTING;
    
    DocSection intro;
    intro.title = "How to Contribute";
    intro.content = "We welcome contributions! Here's how to get started.";
    intro.level = 1;
    page.sections.push_back(intro);
    
    DocSection setup;
    setup.title = "Development Setup";
    setup.content = "1. Clone the repository\n2. Install VS2022 with C++ tools\n3. Run `build_pipeline.bat`\4. Verify tests pass with `ctest`";
    setup.level = 1;
    page.sections.push_back(setup);
    
    DocSection pr;
    pr.title = "Pull Request Process";
    pr.content = "1. Create a feature branch\n2. Make your changes\n3. Add tests\n4. Run the full test suite\n5. Submit a PR with a clear description";
    pr.level = 1;
    page.sections.push_back(pr);
    
    DocSection style;
    style.title = "Code Style";
    style.content = "- Follow the existing code style\n- Use meaningful names\n- Add comments for complex logic\n- Keep functions focused and small\n- Include unit tests for new features";
    style.level = 1;
    page.sections.push_back(style);
    
    stats_.totalPages++;
    return page;
}

bool DocGenerator::WriteDocs(const std::vector<DocPage>& pages) {
    for (const auto& page : pages) {
        if (!WriteDocPage(page)) return false;
    }
    return true;
}

bool DocGenerator::WriteDocPage(const DocPage& page) {
    std::string path = config_.outputDir + "/" + page.filename;
    std::ofstream file(path);
    if (!file) return false;
    
    if (config_.format == DocFormat::MARKDOWN) {
        file << RenderToMarkdown(page);
    } else if (config_.format == DocFormat::HTML) {
        file << RenderToHTML(page);
    }
    
    return true;
}

std::string DocGenerator::RenderToMarkdown(const DocPage& page) {
    std::stringstream md;
    md << "# " << page.title << "\n\n";
    
    for (const auto& section : page.sections) {
        md << RenderSection(section);
    }
    
    // Count words
    std::string content = md.str();
    stats_.totalWords += std::count(content.begin(), content.end(), ' ') + 1;
    stats_.totalSections += page.sections.size();
    
    return md.str();
}

std::string DocGenerator::RenderToHTML(const DocPage& page) {
    std::stringstream html;
    html << "<!DOCTYPE html>\n<html>\n<head>\n<title>" << page.title << "</title>\n";
    html << "<style>body{font-family:-apple-system,sans-serif;max-width:800px;margin:auto;padding:2em}</style>\n";
    html << "</head>\n<body>\n";
    html << "<h1>" << page.title << "</h1>\n";
    html << RenderToMarkdown(page);
    html << "</body>\n</html>\n";
    return html.str();
}

std::string DocGenerator::RenderSection(const DocSection& section, int depth) const {
    std::stringstream md;
    std::string prefix(depth + 1, '#');
    md << prefix << " " << section.title << "\n\n";
    md << section.content << "\n\n";
    
    for (const auto& sub : section.subsections) {
        md << RenderSection(sub, depth + 1);
    }
    
    return md.str();
}

std::string DocGenerator::SanitizeFilename(const std::string& name) const {
    std::string result = name;
    for (auto& c : result) {
        if (!isalnum(c) && c != '_' && c != '-') c = '_';
    }
    return result;
}

} // namespace Sovereign
