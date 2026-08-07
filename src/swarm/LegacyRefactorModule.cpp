#include "LegacyRefactorModule.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <functional>

namespace rawrxd {
namespace swarm {

void LegacyRefactorModule::registerPattern(const CodePattern& pattern) {
    patterns_.push_back(pattern);
}

void LegacyRefactorModule::unregisterPattern(const std::string& name) {
    patterns_.erase(
        std::remove_if(patterns_.begin(), patterns_.end(),
            [&name](const CodePattern& p) { return p.name == name; }),
        patterns_.end()
    );
}

std::vector<CodePattern> LegacyRefactorModule::getPatternsForLanguage(const std::string& language) const {
    std::vector<CodePattern> result;
    for (const auto& pattern : patterns_) {
        if (std::find(pattern.languages.begin(), pattern.languages.end(), language) != pattern.languages.end()) {
            result.push_back(pattern);
        }
    }
    return result;
}

CodeMetrics LegacyRefactorModule::analyzeFile(const std::string& path) {
    CodeMetrics metrics;
    std::string content = readFile(path);
    
    if (content.empty()) return metrics;
    
    // Count lines
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        metrics.linesOfCode++;
        if (line.find("//") != std::string::npos || 
            line.find("/*") != std::string::npos ||
            line.find("*") != std::string::npos) {
            metrics.linesOfComments++;
        }
    }
    
    // Count functions (simplified)
    std::regex funcRegex(R"((\w+)\s+(\w+)\s*\([^)]*\)\s*\{)");
    auto funcBegin = std::sregex_iterator(content.begin(), content.end(), funcRegex);
    auto funcEnd = std::sregex_iterator();
    metrics.functionCount = std::distance(funcBegin, funcEnd);
    
    // Count classes (simplified)
    std::regex classRegex(R"(class\s+(\w+))");
    auto classBegin = std::sregex_iterator(content.begin(), content.end(), classRegex);
    auto classEnd = std::sregex_iterator();
    metrics.classCount = std::distance(classBegin, classEnd);
    
    // Calculate complexity
    metrics.cyclomaticComplexity = calculateCyclomaticComplexity(content);
    
    // Find code smells
    metrics.codeSmells = findCodeSmells(path);
    
    return metrics;
}

CodeMetrics LegacyRefactorModule::analyzeProject(const std::string& rootPath) {
    CodeMetrics total;
    
    for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            if (ext == ".cpp" || ext == ".hpp" || ext == ".h" ||
                ext == ".js" || ext == ".ts" ||
                ext == ".py" || ext == ".java") {
                auto fileMetrics = analyzeFile(entry.path().string());
                total.linesOfCode += fileMetrics.linesOfCode;
                total.linesOfComments += fileMetrics.linesOfComments;
                total.functionCount += fileMetrics.functionCount;
                total.classCount += fileMetrics.classCount;
                total.cyclomaticComplexity += fileMetrics.cyclomaticComplexity;
                total.codeSmells.insert(total.codeSmells.end(), 
                                        fileMetrics.codeSmells.begin(), 
                                        fileMetrics.codeSmells.end());
            }
        }
    }
    
    return total;
}

std::vector<std::string> LegacyRefactorModule::findCodeSmells(const std::string& path) {
    std::vector<std::string> smells;
    std::string content = readFile(path);
    
    // Long functions
    std::regex longFuncRegex(R"((\w+)\s+(\w+)\s*\([^)]*\)\s*\{([^}]|\n){500,}\})");
    if (std::regex_search(content, longFuncRegex)) {
        smells.push_back("Long function detected (>500 chars)");
    }
    
    // Deep nesting
    std::regex deepNestingRegex(R"(\{[^\}]*\{[^\}]*\{[^\}]*\{)");
    if (std::regex_search(content, deepNestingRegex)) {
        smells.push_back("Deep nesting detected (>3 levels)");
    }
    
    // Magic numbers
    std::regex magicNumberRegex(R"([^\w](\d{3,})[^\w])");
    auto magicBegin = std::sregex_iterator(content.begin(), content.end(), magicNumberRegex);
    auto magicEnd = std::sregex_iterator();
    if (std::distance(magicBegin, magicEnd) > 5) {
        smells.push_back("Multiple magic numbers detected");
    }
    
    // TODO comments
    std::regex todoRegex(R"((TODO|FIXME|XXX|HACK)[^\n]*)");
    auto todoBegin = std::sregex_iterator(content.begin(), content.end(), todoRegex);
    auto todoEnd = std::sregex_iterator();
    int todoCount = std::distance(todoBegin, todoEnd);
    if (todoCount > 0) {
        smells.push_back(std::to_string(todoCount) + " TODO/FIXME comments found");
    }
    
    return smells;
}

std::map<std::string, DependencyNode> LegacyRefactorModule::buildDependencyGraph(const std::string& rootPath) {
    std::map<std::string, DependencyNode> graph;
    
    // Find all source files
    for (const auto& entry : std::filesystem::recursive_directory_iterator(rootPath)) {
        if (!entry.is_regular_file()) continue;
        
        auto ext = entry.path().extension().string();
        if (ext != ".cpp" && ext != ".hpp" && ext != ".h" &&
            ext != ".js" && ext != ".ts" &&
            ext != ".py") continue;
        
        std::string path = entry.path().string();
        DependencyNode node;
        node.path = path;
        
        std::string content = readFile(path);
        
        // Extract imports/includes
        std::regex includeRegex(R"(#include\s+[\"\u003c]([^\"\u003e]+)[\"\u003e])");
        auto incBegin = std::sregex_iterator(content.begin(), content.end(), includeRegex);
        auto incEnd = std::sregex_iterator();
        for (auto it = incBegin; it != incEnd; ++it) {
            node.imports.push_back(it->str(1));
        }
        
        // Extract JS/TS imports
        std::regex jsImportRegex(R"(import\s+.*?\s+from\s+['\"]([^'\"]+)['\"])");
        auto jsBegin = std::sregex_iterator(content.begin(), content.end(), jsImportRegex);
        auto jsEnd = std::sregex_iterator();
        for (auto it = jsBegin; it != jsEnd; ++it) {
            node.imports.push_back(it->str(1));
        }
        
        // Extract Python imports
        std::regex pyImportRegex(R"(import\s+(\w+)|from\s+(\w+)\s+import)");
        auto pyBegin = std::sregex_iterator(content.begin(), content.end(), pyImportRegex);
        auto pyEnd = std::sregex_iterator();
        for (auto it = pyBegin; it != pyEnd; ++it) {
            if (!it->str(1).empty()) node.imports.push_back(it->str(1));
            if (!it->str(2).empty()) node.imports.push_back(it->str(2));
        }
        
        graph[path] = node;
    }
    
    // Build dependency relationships
    for (auto& [path, node] : graph) {
        for (const auto& imp : node.imports) {
            // Find which file provides this import
            for (auto& [otherPath, otherNode] : graph) {
                if (otherPath != path) {
                    auto filename = std::filesystem::path(otherPath).filename().string();
                    if (imp.find(filename) != std::string::npos ||
                        filename.find(imp) != std::string::npos) {
                        node.dependsOn.push_back(otherPath);
                        otherNode.dependedBy.push_back(path);
                    }
                }
            }
        }
    }
    
    // Calculate depths
    std::function<void(const std::string&, int)> calcDepth = [&](const std::string& p, int d) {
        if (graph[p].depth < d) graph[p].depth = d;
        for (const auto& dep : graph[p].dependedBy) {
            calcDepth(dep, d + 1);
        }
    };
    
    for (auto& [path, node] : graph) {
        if (node.dependsOn.empty()) {
            calcDepth(path, 0);
        }
    }
    
    return graph;
}

std::vector<std::string> LegacyRefactorModule::findCircularDependencies(
    const std::map<std::string, DependencyNode>& graph) {
    
    std::vector<std::string> circular;
    std::set<std::string> visited;
    std::set<std::string> recStack;
    
    std::function<bool(const std::string&)> hasCycle = [&](const std::string& node) -> bool {
        visited.insert(node);
        recStack.insert(node);
        
        auto it = graph.find(node);
        if (it != graph.end()) {
            for (const auto& dep : it->second.dependsOn) {
                if (visited.find(dep) == visited.end()) {
                    if (hasCycle(dep)) return true;
                } else if (recStack.find(dep) != recStack.end()) {
                    circular.push_back(node + " -> " + dep);
                    return true;
                }
            }
        }
        
        recStack.erase(node);
        return false;
    };
    
    for (const auto& [path, _] : graph) {
        if (visited.find(path) == visited.end()) {
            hasCycle(path);
        }
    }
    
    return circular;
}

std::vector<RefactorOperation> LegacyRefactorModule::generateRefactorPlan(const std::string& targetPath) {
    std::vector<RefactorOperation> plan;
    
    // Analyze file
    auto metrics = analyzeFile(targetPath);
    auto smells = findCodeSmells(targetPath);
    
    // Generate operations based on smells
    for (const auto& smell : smells) {
        RefactorOperation op;
        op.targetFile = targetPath;
        op.description = "Fix: " + smell;
        
        if (smell.find("Long function") != std::string::npos) {
            op.type = RefactorOperation::EXTRACT;
        } else if (smell.find("TODO") != std::string::npos) {
            op.type = RefactorOperation::MODERNIZE;
        } else if (smell.find("magic") != std::string::npos) {
            op.type = RefactorOperation::MODERNIZE;
        } else {
            op.type = RefactorOperation::OPTIMIZE;
        }
        
        plan.push_back(op);
    }
    
    return plan;
}

std::vector<RefactorOperation> LegacyRefactorModule::modernizeCpp(const std::string& path, 
                                                                    int fromStandard, int toStandard) {
    std::vector<RefactorOperation> ops;
    std::string content = readFile(path);
    
    if (fromStandard < 11 && toStandard >= 11) {
        // C++11 modernization
        RefactorOperation op;
        op.type = RefactorOperation::MODERNIZE;
        op.targetFile = path;
        op.description = "Modernize to C++11";
        
        // Replace NULL with nullptr
        std::regex nullRegex(R"(\bNULL\b)");
        if (std::regex_search(content, nullRegex)) {
            RefactorOperation nullOp = op;
            nullOp.description = "Replace NULL with nullptr";
            ops.push_back(nullOp);
        }
        
        // Use auto
        std::regex iteratorRegex(R"((\w+)::iterator\s+(\w+)\s*=\s*(\w+)\.begin\(\))");
        if (std::regex_search(content, iteratorRegex)) {
            RefactorOperation autoOp = op;
            autoOp.description = "Use auto for iterator declarations";
            ops.push_back(autoOp);
        }
    }
    
    if (fromStandard < 14 && toStandard >= 14) {
        // C++14 modernization
        RefactorOperation op;
        op.type = RefactorOperation::MODERNIZE;
        op.targetFile = path;
        op.description = "Modernize to C++14";
        ops.push_back(op);
    }
    
    if (fromStandard < 17 && toStandard >= 17) {
        // C++17 modernization
        RefactorOperation op;
        op.type = RefactorOperation::MODERNIZE;
        op.targetFile = path;
        op.description = "Modernize to C++17";
        ops.push_back(op);
    }
    
    return ops;
}

std::vector<RefactorOperation> LegacyRefactorModule::removeUnusedCode(const std::string& path) {
    std::vector<RefactorOperation> ops;
    std::string content = readFile(path);
    
    // Find unused includes
    std::regex includeRegex(R"(#include\s+[\"\u003c]([^\"\u003e]+)[\"\u003e])");
    auto incBegin = std::sregex_iterator(content.begin(), content.end(), includeRegex);
    auto incEnd = std::sregex_iterator();
    
    for (auto it = incBegin; it != incEnd; ++it) {
        std::string header = it->str(1);
        // Check if header symbols are used (simplified)
        std::string headerBase = header.substr(0, header.find('.'));
        std::regex usageRegex("\\b" + headerBase + "::|#define.*" + headerBase);
        if (!std::regex_search(content, usageRegex)) {
            RefactorOperation op;
            op.type = RefactorOperation::DELETE_UNUSED;
            op.targetFile = path;
            op.description = "Remove unused include: " + header;
            ops.push_back(op);
        }
    }
    
    return ops;
}

bool LegacyRefactorModule::applyOperation(RefactorOperation& op) {
    // Backup file
    if (!backupFile(op.targetFile)) {
        op.errorMessage = "Failed to create backup";
        return false;
    }
    
    std::string content = readFile(op.targetFile);
    op.beforeCode = content;
    
    // Apply transformation based on type
    std::string newContent = content;
    
    switch (op.type) {
        case RefactorOperation::MODERNIZE:
            if (op.description.find("NULL") != std::string::npos) {
                newContent = std::regex_replace(content, std::regex(R"(\bNULL\b)"), "nullptr");
            }
            break;
        case RefactorOperation::DELETE_UNUSED:
            // Remove unused includes
            break;
        default:
            break;
    }
    
    op.afterCode = newContent;
    
    if (writeFile(op.targetFile, newContent)) {
        op.applied = true;
        history_.push_back(op);
        redoStack_.clear();
        return true;
    }
    
    op.errorMessage = "Failed to write file";
    return false;
}

bool LegacyRefactorModule::undoLastOperation() {
    if (history_.empty()) return false;
    
    RefactorOperation op = history_.back();
    history_.pop_back();
    
    // Restore original content
    writeFile(op.targetFile, op.beforeCode);
    
    redoStack_.push_back(op);
    return true;
}

bool LegacyRefactorModule::redoLastOperation() {
    if (redoStack_.empty()) return false;
    
    RefactorOperation op = redoStack_.back();
    redoStack_.pop_back();
    
    writeFile(op.targetFile, op.afterCode);
    history_.push_back(op);
    return true;
}

std::string LegacyRefactorModule::readFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) return "";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

bool LegacyRefactorModule::writeFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) return false;
    
    file << content;
    return file.good();
}

bool LegacyRefactorModule::backupFile(const std::string& path) {
    std::string backupPath = path + ".backup";
    try {
        std::filesystem::copy_file(path, backupPath, 
            std::filesystem::copy_options::overwrite_existing);
        return true;
    } catch (...) {
        return false;
    }
}

int LegacyRefactorModule::calculateCyclomaticComplexity(const std::string& code) {
    int complexity = 1; // Base complexity
    
    // Count decision points
    std::regex ifRegex(R"(\bif\s*\()");
    std::regex forRegex(R"(\bfor\s*\()");
    std::regex whileRegex(R"(\bwhile\s*\()");
    std::regex caseRegex(R"(\bcase\s+)");
    std::regex catchRegex(R"(\bcatch\s*\()");
    std::regex andRegex(R"(\u0026\u0026|\|\|)");
    std::regex ternaryRegex(R"(\?[^?:]*:)");
    
    complexity += std::distance(std::sregex_iterator(code.begin(), code.end(), ifRegex),
                                std::sregex_iterator());
    complexity += std::distance(std::sregex_iterator(code.begin(), code.end(), forRegex),
                                std::sregex_iterator());
    complexity += std::distance(std::sregex_iterator(code.begin(), code.end(), whileRegex),
                                std::sregex_iterator());
    complexity += std::distance(std::sregex_iterator(code.begin(), code.end(), caseRegex),
                                std::sregex_iterator());
    complexity += std::distance(std::sregex_iterator(code.begin(), code.end(), catchRegex),
                                std::sregex_iterator());
    complexity += std::distance(std::sregex_iterator(code.begin(), code.end(), andRegex),
                                std::sregex_iterator());
    complexity += std::distance(std::sregex_iterator(code.begin(), code.end(), ternaryRegex),
                                std::sregex_iterator());
    
    return complexity;
}

} // namespace swarm
} // namespace rawrxd
