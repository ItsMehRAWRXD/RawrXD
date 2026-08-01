// ============================================================================
// RefactoringEngine.hpp - Automated Code Refactoring
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>

namespace RawrXD {
namespace IDE {

struct RefactoringAction {
    std::string name;
    std::string description;
    enum Kind {
        Rename,
        ExtractFunction,
        ExtractVariable,
        InlineVariable,
        ChangeSignature,
        MoveToFile,
        ConvertToModern,
        AddOverride,
        RemoveUnused,
        OrganizeIncludes
    };
    Kind kind;
    std::string filePath;
    size_t targetLine;
    size_t targetColumn;
    std::map<std::string, std::string> parameters;
};

struct RefactoringResult {
    bool success;
    std::string message;
    std::vector<std::string> modifiedFiles;
    std::string diff;
};

class RefactoringEngine {
public:
    RefactoringEngine();
    ~RefactoringEngine();

    // Available refactorings
    std::vector<RefactoringAction> GetAvailableActions(const std::string& filePath, size_t line, size_t column);
    bool IsActionAvailable(RefactoringAction::Kind kind, const std::string& filePath, size_t line);
    
    // Execute refactoring
    RefactoringResult Execute(const RefactoringAction& action);
    
    // Specific refactorings
    RefactoringResult RenameSymbol(const std::string& filePath, size_t line, size_t column,
                                    const std::string& newName);
    RefactoringResult ExtractFunction(const std::string& filePath, size_t startLine, size_t endLine,
                                       const std::string& newName);
    RefactoringResult ExtractVariable(const std::string& filePath, size_t line, size_t column,
                                       const std::string& newName);
    RefactoringResult OrganizeIncludes(const std::string& filePath);
    RefactoringResult RemoveUnusedIncludes(const std::string& filePath);
    
    // Preview
    std::string Preview(const RefactoringAction& action);
    
    // Undo
    bool CanUndo();
    RefactoringResult Undo();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
