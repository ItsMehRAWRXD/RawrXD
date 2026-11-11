// IDEPlugin.h — minimal language-plugin type surface for Win32IDE_LanguagePlugin.cpp
#pragma once

#include <string>

namespace IDEPlugin {

enum class TokenType {
    Default = 0,
    Keyword,
    BuiltinType,
    String,
    Comment,
    Number,
    Preprocessor,
    Operator,
    Function,
    Bracket,
    Identifier
};

struct SyntaxToken {
    TokenType type = TokenType::Default;
    int start = 0;
    int length = 0;
    std::string text;
};

enum class CompletionItemKind {
    Text = 0,
    Method,
    Function,
    Constructor,
    Field,
    Variable,
    Class,
    Interface,
    Module,
    Property,
    Keyword,
    Snippet
};

struct CompletionItem {
    std::string label;
    std::string detail;
    std::string documentation;
    std::string insertText;
    CompletionItemKind kind = CompletionItemKind::Text;
};

struct Diagnostic {
    std::string source;
    int line = 1;
    int column = 1;
    std::string message;
    std::string severity;
};

}  // namespace IDEPlugin
