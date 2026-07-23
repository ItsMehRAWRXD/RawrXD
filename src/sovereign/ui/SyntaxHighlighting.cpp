// ============================================================================
// SyntaxHighlighting.cpp - GPU-Accelerated Syntax Highlighting Implementation
// ============================================================================

#include "SyntaxHighlighting.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <iostream>

namespace Sovereign {

SyntaxHighlighting::SyntaxHighlighting() = default;
SyntaxHighlighting::~SyntaxHighlighting() = default;

bool SyntaxHighlighting::Initialize() {
    InitializeDefaultColorScheme();
    InitializeDefaultLanguages();
    return true;
}

void SyntaxHighlighting::Shutdown() { languages_.clear(); }

void SyntaxHighlighting::InitializeDefaultColorScheme() {
    colorScheme_[HighlightTokenType::KEYWORD] = 0xFF569CD6;
    colorScheme_[HighlightTokenType::TYPE] = 0xFF4EC9B0;
    colorScheme_[HighlightTokenType::FUNCTION] = 0xFFDCDCAA;
    colorScheme_[HighlightTokenType::VARIABLE] = 0xFF9CDCFE;
    colorScheme_[HighlightTokenType::CONSTANT] = 0xFF4FC1FF;
    colorScheme_[HighlightTokenType::STRING] = 0xFFCE9178;
    colorScheme_[HighlightTokenType::COMMENT] = 0xFF6A9955;
    colorScheme_[HighlightTokenType::NUMBER] = 0xFFB5CEA8;
    colorScheme_[HighlightTokenType::OPERATOR] = 0xFFD4D4D4;
    colorScheme_[HighlightTokenType::PREPROCESSOR] = 0xFFC586C0;
    colorScheme_[HighlightTokenType::ANNOTATION] = 0xFFC8E6C9;
    colorScheme_[HighlightTokenType::NAMESPACE] = 0xFFDCDCAA;
    colorScheme_[HighlightTokenType::CLASS] = 0xFF4EC9B0;
    colorScheme_[HighlightTokenType::METHOD] = 0xFFDCDCAA;
    colorScheme_[HighlightTokenType::PLAIN_TEXT] = 0xFFD4D4D4;
}

void SyntaxHighlighting::RegisterLanguage(const LanguageDefinition& lang) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& ext : lang.extensions) {
        languages_[ext] = lang;
    }
}

LanguageDefinition SyntaxHighlighting::GetLanguage(const std::string& extension) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = languages_.find(extension);
    if (it != languages_.end()) return it->second;
    return {};
}

std::string SyntaxHighlighting::DetectLanguage(const std::string& filename) const {
    auto dot = filename.find_last_of('.');
    if (dot == std::string::npos) return "txt";
    std::string ext = filename.substr(dot);
    std::lock_guard<std::mutex> lock(mutex_);
    if (languages_.find(ext) != languages_.end()) return ext;
    return "txt";
}

std::vector<HighlightLine> SyntaxHighlighting::Highlight(const std::string& code, const std::string& language) {
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<HighlightLine> result;
    
    LanguageDefinition lang;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = languages_.find(language);
        if (it != languages_.end()) lang = it->second;
        else return result;
    }
    
    std::istringstream stream(code);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        HighlightLine hl;
        hl.lineNumber = lineNum;
        hl.text = line;
        hl.tokens = TokenizeLine(line, lang);
        result.push_back(hl);
        lineNum++;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    stats_.totalLines += lineNum;
    stats_.totalFiles++;
    
    return result;
}

std::vector<HighlightToken> SyntaxHighlighting::TokenizeLine(const std::string& line, const LanguageDefinition& lang) {
    std::vector<HighlightToken> tokens;
    if (line.empty()) return tokens;
    
    // Check for comments
    if (!lang.lineComment.first.empty()) {
        auto commentPos = line.find(lang.lineComment.first);
        if (commentPos != std::string::npos) {
            HighlightToken comment;
            comment.type = HighlightTokenType::COMMENT;
            comment.start = commentPos;
            comment.length = line.size() - commentPos;
            comment.color = GetColor(HighlightTokenType::COMMENT);
            comment.italic = true;
            tokens.push_back(comment);
            
            // Tokenize before comment
            std::string codePart = line.substr(0, commentPos);
            auto codeTokens = TokenizeLine(codePart, lang);
            tokens.insert(tokens.begin(), codeTokens.begin(), codeTokens.end());
            return tokens;
        }
    }
    
    // Tokenize by words
    std::regex wordRegex(R"(\b\w+\b|[{}()\[\];:.,<>=!+\-*/%&|^~]|"[^"]*"|'[^']*'|\d+\.?\d*)");
    std::sregex_iterator iter(line.begin(), line.end(), wordRegex);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        std::string word = iter->str();
        HighlightToken token;
        token.start = iter->position();
        token.length = word.size();
        token.color = GetColor(HighlightTokenType::PLAIN_TEXT);
        token.bold = false;
        token.italic = false;
        
        // Check keywords
        bool matched = false;
        for (const auto& [kw, type] : lang.keywords) {
            if (word == kw) {
                token.type = type;
                token.color = GetColor(type);
                token.bold = true;
                matched = true;
                break;
            }
        }
        
        if (!matched) {
            // Check types
            for (const auto& [t, type] : lang.types) {
                if (word == t) {
                    token.type = type;
                    token.color = GetColor(type);
                    matched = true;
                    break;
                }
            }
        }
        
        if (!matched) {
            // Check patterns
            for (const auto& [pattern, type] : lang.patterns) {
                if (std::regex_match(word, pattern)) {
                    token.type = type;
                    token.color = GetColor(type);
                    matched = true;
                    break;
                }
            }
        }
        
        if (!matched) {
            // Check strings
            for (const auto& delim : lang.stringDelimiters) {
                if (word.size() >= 2 && word.front() == delim[0] && word.back() == delim[0]) {
                    token.type = HighlightTokenType::STRING;
                    token.color = GetColor(HighlightTokenType::STRING);
                    matched = true;
                    break;
                }
            }
        }
        
        if (!matched) {
            // Check numbers
            if (std::regex_match(word, std::regex(R"(\d+\.?\d*)"))) {
                token.type = HighlightTokenType::NUMBER;
                token.color = GetColor(HighlightTokenType::NUMBER);
                matched = true;
            }
        }
        
        if (!matched) {
            token.type = HighlightTokenType::PLAIN_TEXT;
        }
        
        tokens.push_back(token);
        stats_.totalTokens++;
    }
    
    return tokens;
}

void SyntaxHighlighting::InitializeDefaultLanguages() {
    AddCPPLanguage();
    AddPythonLanguage();
    AddJavaScriptLanguage();
    AddMASMLanguage();
}

void SyntaxHighlighting::AddCPPLanguage() {
    LanguageDefinition cpp;
    cpp.name = "C++";
    cpp.extensions = {".cpp", ".hpp", ".h", ".c", ".cc", ".cxx", ".hxx"};
    cpp.caseSensitive = true;
    cpp.lineComment = {"//", ""};
    cpp.blockComment = {"/*", "*/"};
    cpp.stringDelimiters = {"\"", "'"};
    
    cpp.keywords = {
        {"auto", HighlightTokenType::KEYWORD}, {"break", HighlightTokenType::KEYWORD},
        {"case", HighlightTokenType::KEYWORD}, {"catch", HighlightTokenType::KEYWORD},
        {"class", HighlightTokenType::KEYWORD}, {"const", HighlightTokenType::KEYWORD},
        {"constexpr", HighlightTokenType::KEYWORD}, {"continue", HighlightTokenType::KEYWORD},
        {"decltype", HighlightTokenType::KEYWORD}, {"default", HighlightTokenType::KEYWORD},
        {"delete", HighlightTokenType::KEYWORD}, {"do", HighlightTokenType::KEYWORD},
        {"else", HighlightTokenType::KEYWORD}, {"enum", HighlightTokenType::KEYWORD},
        {"explicit", HighlightTokenType::KEYWORD}, {"export", HighlightTokenType::KEYWORD},
        {"extern", HighlightTokenType::KEYWORD}, {"false", HighlightTokenType::CONSTANT},
        {"for", HighlightTokenType::KEYWORD}, {"friend", HighlightTokenType::KEYWORD},
        {"goto", HighlightTokenType::KEYWORD}, {"if", HighlightTokenType::KEYWORD},
        {"inline", HighlightTokenType::KEYWORD}, {"mutable", HighlightTokenType::KEYWORD},
        {"namespace", HighlightTokenType::KEYWORD}, {"new", HighlightTokenType::KEYWORD},
        {"noexcept", HighlightTokenType::KEYWORD}, {"nullptr", HighlightTokenType::CONSTANT},
        {"operator", HighlightTokenType::KEYWORD}, {"override", HighlightTokenType::KEYWORD},
        {"private", HighlightTokenType::KEYWORD}, {"protected", HighlightTokenType::KEYWORD},
        {"public", HighlightTokenType::KEYWORD}, {"register", HighlightTokenType::KEYWORD},
        {"return", HighlightTokenType::KEYWORD}, {"static", HighlightTokenType::KEYWORD},
        {"struct", HighlightTokenType::KEYWORD}, {"switch", HighlightTokenType::KEYWORD},
        {"template", HighlightTokenType::KEYWORD}, {"this", HighlightTokenType::KEYWORD},
        {"throw", HighlightTokenType::KEYWORD}, {"true", HighlightTokenType::CONSTANT},
        {"try", HighlightTokenType::KEYWORD}, {"typedef", HighlightTokenType::KEYWORD},
        {"typename", HighlightTokenType::KEYWORD}, {"union", HighlightTokenType::KEYWORD},
        {"using", HighlightTokenType::KEYWORD}, {"virtual", HighlightTokenType::KEYWORD},
        {"void", HighlightTokenType::TYPE}, {"volatile", HighlightTokenType::KEYWORD},
        {"while", HighlightTokenType::KEYWORD}
    };
    
    cpp.types = {
        {"int", HighlightTokenType::TYPE}, {"long", HighlightTokenType::TYPE},
        {"float", HighlightTokenType::TYPE}, {"double", HighlightTokenType::TYPE},
        {"char", HighlightTokenType::TYPE}, {"bool", HighlightTokenType::TYPE},
        {"short", HighlightTokenType::TYPE}, {"unsigned", HighlightTokenType::TYPE},
        {"signed", HighlightTokenType::TYPE}, {"size_t", HighlightTokenType::TYPE},
        {"uint32_t", HighlightTokenType::TYPE}, {"uint64_t", HighlightTokenType::TYPE},
        {"int32_t", HighlightTokenType::TYPE}, {"int64_t", HighlightTokenType::TYPE},
        {"string", HighlightTokenType::TYPE}, {"vector", HighlightTokenType::TYPE},
        {"map", HighlightTokenType::TYPE}, {"set", HighlightTokenType::TYPE},
        {"shared_ptr", HighlightTokenType::TYPE}, {"unique_ptr", HighlightTokenType::TYPE},
        {"optional", HighlightTokenType::TYPE}, {"variant", HighlightTokenType::TYPE},
        {"any", HighlightTokenType::TYPE}, {"function", HighlightTokenType::TYPE}
    };
    
    cpp.patterns = {
        {std::regex(R"(#\w+)"), HighlightTokenType::PREPROCESSOR},
        {std::regex(R"(\b[A-Z][A-Z0-9_]+\b)"), HighlightTokenType::CONSTANT}
    };
    
    RegisterLanguage(cpp);
}

void SyntaxHighlighting::AddPythonLanguage() {
    LanguageDefinition py;
    py.name = "Python";
    py.extensions = {".py", ".pyw", ".pyx"};
    py.caseSensitive = true;
    py.lineComment = {"#", ""};
    py.stringDelimiters = {"\"", "'", "\"\"\"", "'''"};
    
    py.keywords = {
        {"False", HighlightTokenType::CONSTANT}, {"None", HighlightTokenType::CONSTANT},
        {"True", HighlightTokenType::CONSTANT}, {"and", HighlightTokenType::KEYWORD},
        {"as", HighlightTokenType::KEYWORD}, {"assert", HighlightTokenType::KEYWORD},
        {"async", HighlightTokenType::KEYWORD}, {"await", HighlightTokenType::KEYWORD},
        {"break", HighlightTokenType::KEYWORD}, {"class", HighlightTokenType::KEYWORD},
        {"continue", HighlightTokenType::KEYWORD}, {"def", HighlightTokenType::KEYWORD},
        {"del", HighlightTokenType::KEYWORD}, {"elif", HighlightTokenType::KEYWORD},
        {"else", HighlightTokenType::KEYWORD}, {"except", HighlightTokenType::KEYWORD},
        {"finally", HighlightTokenType::KEYWORD}, {"for", HighlightTokenType::KEYWORD},
        {"from", HighlightTokenType::KEYWORD}, {"global", HighlightTokenType::KEYWORD},
        {"if", HighlightTokenType::KEYWORD}, {"import", HighlightTokenType::KEYWORD},
        {"in", HighlightTokenType::KEYWORD}, {"is", HighlightTokenType::KEYWORD},
        {"lambda", HighlightTokenType::KEYWORD}, {"nonlocal", HighlightTokenType::KEYWORD},
        {"not", HighlightTokenType::KEYWORD}, {"or", HighlightTokenType::KEYWORD},
        {"pass", HighlightTokenType::KEYWORD}, {"raise", HighlightTokenType::KEYWORD},
        {"return", HighlightTokenType::KEYWORD}, {"try", HighlightTokenType::KEYWORD},
        {"while", HighlightTokenType::KEYWORD}, {"with", HighlightTokenType::KEYWORD},
        {"yield", HighlightTokenType::KEYWORD}
    };
    
    RegisterLanguage(py);
}

void SyntaxHighlighting::AddJavaScriptLanguage() {
    LanguageDefinition js;
    js.name = "JavaScript";
    js.extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs"};
    js.caseSensitive = true;
    js.lineComment = {"//", ""};
    js.blockComment = {"/*", "*/"};
    js.stringDelimiters = {"\"", "'", "`"};
    
    js.keywords = {
        {"async", HighlightTokenType::KEYWORD}, {"await", HighlightTokenType::KEYWORD},
        {"break", HighlightTokenType::KEYWORD}, {"case", HighlightTokenType::KEYWORD},
        {"catch", HighlightTokenType::KEYWORD}, {"class", HighlightTokenType::KEYWORD},
        {"const", HighlightTokenType::KEYWORD}, {"continue", HighlightTokenType::KEYWORD},
        {"debugger", HighlightTokenType::KEYWORD}, {"default", HighlightTokenType::KEYWORD},
        {"delete", HighlightTokenType::KEYWORD}, {"do", HighlightTokenType::KEYWORD},
        {"else", HighlightTokenType::KEYWORD}, {"export", HighlightTokenType::KEYWORD},
        {"extends", HighlightTokenType::KEYWORD}, {"false", HighlightTokenType::CONSTANT},
        {"finally", HighlightTokenType::KEYWORD}, {"for", HighlightTokenType::KEYWORD},
        {"function", HighlightTokenType::KEYWORD}, {"if", HighlightTokenType::KEYWORD},
        {"import", HighlightTokenType::KEYWORD}, {"in", HighlightTokenType::KEYWORD},
        {"instanceof", HighlightTokenType::KEYWORD}, {"let", HighlightTokenType::KEYWORD},
        {"new", HighlightTokenType::KEYWORD}, {"null", HighlightTokenType::CONSTANT},
        {"return", HighlightTokenType::KEYWORD}, {"super", HighlightTokenType::KEYWORD},
        {"switch", HighlightTokenType::KEYWORD}, {"this", HighlightTokenType::KEYWORD},
        {"throw", HighlightTokenType::KEYWORD}, {"true", HighlightTokenType::CONSTANT},
        {"try", HighlightTokenType::KEYWORD}, {"typeof", HighlightTokenType::KEYWORD},
        {"undefined", HighlightTokenType::CONSTANT}, {"var", HighlightTokenType::KEYWORD},
        {"void", HighlightTokenType::KEYWORD}, {"while", HighlightTokenType::KEYWORD},
        {"with", HighlightTokenType::KEYWORD}, {"yield", HighlightTokenType::KEYWORD}
    };
    
    RegisterLanguage(js);
}

void SyntaxHighlighting::AddMASMLanguage() {
    LanguageDefinition asm;
    asm.name = "MASM x64";
    asm.extensions = {".asm", ".masm", ".inc"};
    asm.caseSensitive = false;
    asm.lineComment = {";", ""};
    asm.stringDelimiters = {"\"", "'"};
    
    asm.keywords = {
        {"proc", HighlightTokenType::KEYWORD}, {"endp", HighlightTokenType::KEYWORD},
        {"frame", HighlightTokenType::KEYWORD}, {"endprolog", HighlightTokenType::KEYWORD},
        {"push", HighlightTokenType::KEYWORD}, {"pop", HighlightTokenType::KEYWORD},
        {"mov", HighlightTokenType::KEYWORD}, {"add", HighlightTokenType::KEYWORD},
        {"sub", HighlightTokenType::KEYWORD}, {"mul", HighlightTokenType::KEYWORD},
        {"div", HighlightTokenType::KEYWORD}, {"imul", HighlightTokenType::KEYWORD},
        {"idiv", HighlightTokenType::KEYWORD}, {"cmp", HighlightTokenType::KEYWORD},
        {"jmp", HighlightTokenType::KEYWORD}, {"je", HighlightTokenType::KEYWORD},
        {"jne", HighlightTokenType::KEYWORD}, {"jg", HighlightTokenType::KEYWORD},
        {"jl", HighlightTokenType::KEYWORD}, {"jge", HighlightTokenType::KEYWORD},
        {"jle", HighlightTokenType::KEYWORD}, {"call", HighlightTokenType::KEYWORD},
        {"ret", HighlightTokenType::KEYWORD}, {"xor", HighlightTokenType::KEYWORD},
        {"and", HighlightTokenType::KEYWORD}, {"or", HighlightTokenType::KEYWORD},
        {"shl", HighlightTokenType::KEYWORD}, {"shr", HighlightTokenType::KEYWORD},
        {"lea", HighlightTokenType::KEYWORD}, {"test", HighlightTokenType::KEYWORD},
        {"inc", HighlightTokenType::KEYWORD}, {"dec", HighlightTokenType::KEYWORD},
        {"neg", HighlightTokenType::KEYWORD}, {"not", HighlightTokenType::KEYWORD},
        {"include", HighlightTokenType::PREPROCESSOR}, {"includelib", HighlightTokenType::PREPROCESSOR},
        {"extern", HighlightTokenType::KEYWORD}, {"public", HighlightTokenType::KEYWORD},
        {"option", HighlightTokenType::KEYWORD}, {"align", HighlightTokenType::KEYWORD},
        {"assume", HighlightTokenType::KEYWORD}, {"comment", HighlightTokenType::KEYWORD},
        {"echo", HighlightTokenType::KEYWORD}, {"else", HighlightTokenType::KEYWORD},
        {"endif", HighlightTokenType::KEYWORD}, {"end", HighlightTokenType::KEYWORD},
        {"equ", HighlightTokenType::KEYWORD}, {"= ", HighlightTokenType::KEYWORD},
        {"typedef", HighlightTokenType::KEYWORD}, {"struct", HighlightTokenType::KEYWORD},
        {"ends", HighlightTokenType::KEYWORD}, {"union", HighlightTokenType::KEYWORD},
        {"data", HighlightTokenType::KEYWORD}, {"code", HighlightTokenType::KEYWORD},
        {"const", HighlightTokenType::KEYWORD}, {"dq", HighlightTokenType::KEYWORD},
        {"dd", HighlightTokenType::KEYWORD}, {"dw", HighlightTokenType::KEYWORD},
        {"db", HighlightTokenType::KEYWORD}, {"proto", HighlightTokenType::KEYWORD}
    };
    
    asm.types = {
        {"qword", HighlightTokenType::TYPE}, {"dword", HighlightTokenType::TYPE},
        {"word", HighlightTokenType::TYPE}, {"byte", HighlightTokenType::TYPE},
        {"real4", HighlightTokenType::TYPE}, {"real8", HighlightTokenType::TYPE},
        {"sqword", HighlightTokenType::TYPE}, {"sword", HighlightTokenType::TYPE},
        {"sbyte", HighlightTokenType::TYPE}
    };
    
    RegisterLanguage(asm);
}

void SyntaxHighlighting::SetColorScheme(const std::unordered_map<HighlightTokenType, uint32_t>& colors) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [type, color] : colors) {
        colorScheme_[type] = color;
    }
}

uint32_t SyntaxHighlighting::GetColor(HighlightTokenType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = colorScheme_.find(type);
    return it != colorScheme_.end() ? it->second : 0xFFD4D4D4;
}

} // namespace Sovereign
