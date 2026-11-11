// RawrXD-Script Compiler Driver
// Phase 1: Bytecode Spec + C++ Parser
// Main entry point for rawrxd-js compiler

#include "../lexer/lexer.hpp"
#include "../parser/parser.hpp"
#include "../bytecode/bytecode.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

using namespace RawrXD::Script;

// Command line options
struct CompilerOptions {
    std::string input_file;
    std::string output_file;
    bool emit_ast = false;
    bool emit_disassembly = false;
    bool verbose = false;
    bool strict_mode = false;
    std::string target = "rawr";  // Output format: rawr, asm, c
};

void PrintUsage(const char* program_name) {
    std::cout << "RawrXD-Script Compiler v1.0 (Phase 1)\n"
              << "Usage: " << program_name << " [options] <input.js>\n\n"
              << "Options:\n"
              << "  -o <file>       Output file (default: input.rawr)\n"
              << "  --emit-ast       Print AST to stdout\n"
              << "  --emit-asm       Print disassembly to stdout\n"
              << "  --strict         Enable strict mode\n"
              << "  --target <type> Output format: rawr, asm (default: rawr)\n"
              << "  -v, --verbose    Verbose output\n"
              << "  -h, --help       Show this help\n";
}

CompilerOptions ParseArgs(int argc, char* argv[]) {
    CompilerOptions options;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            exit(0);
        } else if (arg == "-o" && i + 1 < argc) {
            options.output_file = argv[++i];
        } else if (arg == "--emit-ast") {
            options.emit_ast = true;
        } else if (arg == "--emit-asm") {
            options.emit_disassembly = true;
        } else if (arg == "--strict") {
            options.strict_mode = true;
        } else if (arg == "--target" && i + 1 < argc) {
            options.target = argv[++i];
        } else if (arg == "-v" || arg == "--verbose") {
            options.verbose = true;
        } else if (arg[0] != '-') {
            options.input_file = arg;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            PrintUsage(argv[0]);
            exit(1);
        }
    }
    
    return options;
}

std::string ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void WriteFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create file: " + filename);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// AST printer for debugging
class ASTPrinter : public ASTVisitor {
public:
    int indent = 0;
    
    void PrintIndent() {
        for (int i = 0; i < indent; ++i) std::cout << "  ";
    }
    
    void Visit(const NumberLiteralExpr& node) override {
        PrintIndent(); std::cout << "NumberLiteral: " << node.value << "\n";
    }
    
    void Visit(const StringLiteralExpr& node) override {
        PrintIndent(); std::cout << "StringLiteral: \"" << node.value << "\"\n";
    }
    
    void Visit(const BooleanLiteralExpr& node) override {
        PrintIndent(); std::cout << "BooleanLiteral: " << (node.value ? "true" : "false") << "\n";
    }
    
    void Visit(const NullLiteralExpr& node) override {
        PrintIndent(); std::cout << "NullLiteral\n";
    }
    
    void Visit(const UndefinedLiteralExpr& node) override {
        PrintIndent(); std::cout << "UndefinedLiteral\n";
    }
    
    void Visit(const IdentifierExpr& node) override {
        PrintIndent(); std::cout << "Identifier: " << node.name << "\n";
    }
    
    void Visit(const BinaryExpr& node) override {
        PrintIndent(); std::cout << "BinaryExpr: " << node.op << "\n";
        ++indent;
        // Visit left and right
        --indent;
    }
    
    void Visit(const UnaryExpr& node) override {
        PrintIndent(); std::cout << "UnaryExpr: " << node.op << "\n";
    }
    
    void Visit(const AssignmentExpr& node) override {
        PrintIndent(); std::cout << "AssignmentExpr: " << node.op << "\n";
    }
    
    void Visit(const CallExpr& node) override {
        PrintIndent(); std::cout << "CallExpr\n";
    }
    
    void Visit(const MemberExpr& node) override {
        PrintIndent(); std::cout << "MemberExpr (computed=" << node.computed << ")\n";
    }
    
    void Visit(const ArrayExpr& node) override {
        PrintIndent(); std::cout << "ArrayExpr [" << node.elements.size() << " elements]\n";
    }
    
    void Visit(const ObjectExpr& node) override {
        PrintIndent(); std::cout << "ObjectExpr [" << node.properties.size() << " properties]\n";
    }
    
    void Visit(const FunctionExpr& node) override {
        PrintIndent(); std::cout << "FunctionExpr";
        if (node.name) std::cout << ": " << *node.name;
        std::cout << " [" << node.params.size() << " params]\n";
    }
    
    void Visit(const ConditionalExpr& node) override {
        PrintIndent(); std::cout << "ConditionalExpr\n";
    }
    
    void Visit(const UpdateExpr& node) override {
        PrintIndent(); std::cout << "UpdateExpr: " << node.op << " (prefix=" << node.prefix << ")\n";
    }
    
    void Visit(const NewExpr& node) override {
        PrintIndent(); std::cout << "NewExpr\n";
    }
    
    void Visit(const ThisExpr& node) override {
        PrintIndent(); std::cout << "ThisExpr\n";
    }
    
    void Visit(const ExpressionStmt& node) override {
        PrintIndent(); std::cout << "ExpressionStmt\n";
    }
    
    void Visit(const BlockStmt& node) override {
        PrintIndent(); std::cout << "BlockStmt [" << node.body.size() << " statements]\n";
        ++indent;
        for (const auto& stmt : node.body) {
            // Visit each statement
        }
        --indent;
    }
    
    void Visit(const IfStmt& node) override {
        PrintIndent(); std::cout << "IfStmt\n";
    }
    
    void Visit(const WhileStmt& node) override {
        PrintIndent(); std::cout << "WhileStmt\n";
    }
    
    void Visit(const ForStmt& node) override {
        PrintIndent(); std::cout << "ForStmt\n";
    }
    
    void Visit(const ReturnStmt& node) override {
        PrintIndent(); std::cout << "ReturnStmt\n";
    }
    
    void Visit(const BreakStmt& node) override {
        PrintIndent(); std::cout << "BreakStmt\n";
    }
    
    void Visit(const ContinueStmt& node) override {
        PrintIndent(); std::cout << "ContinueStmt\n";
    }
    
    void Visit(const SwitchStmt& node) override {
        PrintIndent(); std::cout << "SwitchStmt [" << node.cases.size() << " cases]\n";
    }
    
    void Visit(const TryStmt& node) override {
        PrintIndent(); std::cout << "TryStmt\n";
    }
    
    void Visit(const ThrowStmt& node) override {
        PrintIndent(); std::cout << "ThrowStmt\n";
    }
    
    void Visit(const VariableDecl& node) override {
        PrintIndent(); std::cout << "VariableDecl: " << node.kind << " [" << node.declarations.size() << " vars]\n";
    }
    
    void Visit(const FunctionDecl& node) override {
        PrintIndent(); std::cout << "FunctionDecl: " << node.name << " [" << node.params.size() << " params]\n";
    }
    
    void Visit(const Program& node) override {
        PrintIndent(); std::cout << "Program [" << node.body.size() << " statements]\n";
        ++indent;
        for (const auto& stmt : node.body) {
            // Visit each statement
        }
        --indent;
    }
};

int main(int argc, char* argv[]) {
    try {
        CompilerOptions options = ParseArgs(argc, argv);
        
        if (options.input_file.empty()) {
            std::cerr << "Error: No input file specified\n\n";
            PrintUsage(argv[0]);
            return 1;
        }
        
        // Set default output file
        if (options.output_file.empty()) {
            fs::path input_path(options.input_file);
            options.output_file = input_path.stem().string() + ".rawr";
        }
        
        if (options.verbose) {
            std::cout << "RawrXD-Script Compiler v1.0\n"
                      << "Input:  " << options.input_file << "\n"
                      << "Output: " << options.output_file << "\n"
                      << "Target: " << options.target << "\n\n";
        }
        
        // Read source file
        std::string source = ReadFile(options.input_file);
        
        if (options.verbose) {
            std::cout << "Source: " << source.size() << " bytes\n";
        }
        
        // Phase 1: Lexical Analysis
        Lexer lexer;
        LexerResult lex_result = lexer.Tokenize(source);
        
        if (!lex_result.Success()) {
            std::cerr << "Lexer Error [" << lex_result.errorLine << ":" << lex_result.errorColumn << "]: "
                      << lex_result.errorMessage << "\n";
            return 1;
        }
        
        if (options.verbose) {
            std::cout << "Tokens: " << lex_result.tokens.size() << "\n";
        }
        
        // Phase 2: Parsing
        Parser parser;
        ParserResult parse_result = parser.ParseTokens(std::move(lex_result.tokens));
        
        if (!parse_result.success) {
            std::cerr << "Parser Error [" << parse_result.errorLine << ":" << parse_result.errorColumn << "]: "
                      << parse_result.errorMessage << "\n";
            return 1;
        }
        
        if (options.verbose) {
            std::cout << "Parsing: OK\n";
        }
        
        // Print AST if requested
        if (options.emit_ast) {
            std::cout << "\n=== Abstract Syntax Tree ===\n";
            ASTPrinter printer;
            // parse_result.ast->Accept(printer);
            std::cout << "\n";
        }
        
        // Phase 3: Bytecode Generation (placeholder for now)
        // In full implementation, this would traverse the AST and emit bytecode
        Bytecode::BytecodeModule module;
        module.SetStrictMode(options.strict_mode);
        
        // Add placeholder instruction
        module.AppendInstruction(Bytecode::Instruction(
            Bytecode::Opcode::OP_NOP, 0, 0, 0));
        
        if (options.verbose) {
            std::cout << "Bytecode: " << module.GetCode().size() << " instructions\n";
        }
        
        // Print disassembly if requested
        if (options.emit_disassembly) {
            std::cout << "\n=== Bytecode Disassembly ===\n";
            std::cout << module.Disassemble() << "\n";
        }
        
        // Phase 4: Output
        if (options.target == "rawr") {
            std::vector<uint8_t> bytecode = module.Serialize();
            WriteFile(options.output_file, bytecode);
            
            if (options.verbose) {
                std::cout << "Output: " << bytecode.size() << " bytes\n";
            }
        } else if (options.target == "asm") {
            std::string disasm = module.Disassemble();
            std::ofstream out(options.output_file);
            out << disasm;
            
            if (options.verbose) {
                std::cout << "Output: " << disasm.size() << " chars\n";
            }
        }
        
        std::cout << "Compilation successful: " << options.output_file << "\n";
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
