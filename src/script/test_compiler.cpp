// Test the bytecode compiler

#include "compiler/compiler.hpp"
#include "parser/parser.hpp"
#include "lexer/lexer.hpp"
#include <cstdio>

using namespace RawrXD::Script;

int main() {
    printf("RawrXD-Script Bytecode Compiler Test\n");
    printf("====================================\n\n");
    
    // Test case: 2 + 3
    const char* source = "2 + 3";
    printf("Source: %s\n\n", source);
    
    // Step 1: Lex
    Lexer lexer;
    LexerResult lexResult = lexer.Tokenize(source);
    if (!lexResult.Success()) {
        printf("Lexer error: %s\n", lexResult.errorMessage.c_str());
        return 1;
    }
    printf("✓ Lexer: %zu tokens\n", lexResult.tokens.size());
    
    // Step 2: Parse
    Parser parser;
    ParserResult parseResult = parser.ParseTokens(std::move(lexResult.tokens));
    if (!parseResult.success) {
        printf("Parser error: %s\n", parseResult.errorMessage.c_str());
        return 1;
    }
    printf("✓ Parser: AST built\n");
    
    // Step 3: Compile to bytecode
    Compiler compiler;
    CompileResult compileResult = compiler.Compile(parseResult.ast.get());
    if (!compileResult.success) {
        printf("Compiler error: %s\n", compileResult.errorMessage.c_str());
        return 1;
    }
    printf("✓ Compiler: Bytecode generated\n\n");
    
    // Step 4: Dump bytecode
    printf("Bytecode Output:\n");
    printf("  Constants: %zu\n", compileResult.module.constants.size());
    for (size_t i = 0; i < compileResult.module.constants.size(); i++) {
        printf("    [%zu] = %f\n", i, compileResult.module.constants[i]);
    }
    
    printf("\n  Code (%zu bytes):\n", compileResult.module.code.size());
    for (size_t i = 0; i < compileResult.module.code.size(); i++) {
        printf("    [%zu] = 0x%02X\n", i, compileResult.module.code[i]);
    }
    
    printf("\n✓ Bytecode compilation successful!\n");
    return 0;
}
