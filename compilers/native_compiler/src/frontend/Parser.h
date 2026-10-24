// The C parser of the RawrXD native compiler.
//
// The parser turns the token stream of the preprocessor into a syntax tree.
// It does not look at types: it records what was written down, and the
// semantic analysis decides what it means. The two are kept apart on
// purpose, because a type error and a syntax error are different problems
// and are repaired in different ways.
//
// The grammar is the one from C11, restricted to what a C program needs to
// be compiled: translation units, functions, declarations, the statements
// and the expressions, with pointers, arrays, structs, enums and calls.
//
// The expression grammar is handled with one precedence table, so the
// precedence and the associativity of every operator live in one place
// instead of in a dozen nested functions.
//
// Every node of the tree carries the range of source it came from, so a
// later stage can point at the exact text that has to change.

#ifndef RAWR_COMPILER_PARSER_H
#define RAWR_COMPILER_PARSER_H

#include "common/Diagnostics.h"
#include "common/SourceManager.h"
#include "frontend/AST.h"
#include "frontend/Token.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

namespace rawr {

class Parser {
public:
    Parser(SourceManager* sources, DiagnosticEngine* diags, AST* ast);

    // Parses a token stream into a translation unit. Returns false when an
    // error was reported.
    bool parse_translation_unit(const Vector<Token>& tokens);

    ASTNode* translation_unit() const { return unit_; }
    uint32 error_count() const { return errors_; }

private:
    // ---- the token stream ----
    const Token& peek(size_type ahead = 0) const;
    const Token& advance();
    bool check(TokenKind kind) const;
    bool check_at(size_type ahead, TokenKind kind) const;
    // True when the token stream is exhausted.
    //
    // The stream does not hold an end of file token: the lexer stops when
    // the input ends, and the last token is the last one there is. A loop
    // that waits for an end of file token would therefore never stop.
    bool at_end() const { return pos_ >= tokens_.size(); }
    // Consumes the token when it has the kind, and reports nothing.
    bool match(TokenKind kind);
    // Consumes the token when it has the kind, and reports an error when it
    // does not.
    const Token& expect(TokenKind kind, const char* what);

    // ---- diagnostics ----
    void error(const SourceLoc& loc, const char* code, const char* message);
    void error_at_current(const char* code, const char* message);
    SourceSpan span_from(size_type first_token, size_type last_token) const;
    SourceSpan span_of_current() const;

    // ---- declarations ----
    ASTNode* parse_external_declaration();
    ASTNode* parse_declaration();
    ASTNode* parse_function_definition(ASTNode* declaration);
    // Parses the declaration specifiers, for example "static const int".
    bool parse_declaration_specifiers(Vector<ASTNode*>* out);
    ASTNode* parse_struct_or_union_specifier(bool is_union);
    ASTNode* parse_enum_specifier();
    Vector<ASTNode*> parse_struct_declarator_list();
    // Parses a declarator and returns the chain.
    struct DeclaratorStep {
        ASTNodeKind kind = ASTNodeKind::DeclaratorPointer;
        ASTNode* size = nullptr;
        Vector<ASTNode*> parameters;
        SourceSpan span;
    };
    struct Declarator {
        String name;
        Vector<DeclaratorStep> steps;   // in the order the constructors apply
        SourceSpan span;
    };
    bool parse_declarator(Declarator* out);
    void parse_declarator_suffixes(Vector<DeclaratorStep>* steps);
    ASTNode* build_declarator_chain(const Declarator& declarator, const SourceSpan& span);
    void parse_parameter_list(Vector<ASTNode*>* out);
    ASTNode* parse_type_name();
    ASTNode* parse_initializer();

    // ---- statements ----
    ASTNode* parse_statement();
    ASTNode* parse_compound_statement();
    ASTNode* parse_if_statement();
    ASTNode* parse_while_statement();
    ASTNode* parse_do_statement();
    ASTNode* parse_for_statement();
    ASTNode* parse_switch_statement();
    ASTNode* parse_case_statement();
    ASTNode* parse_return_statement();
    ASTNode* parse_expression_statement();

    // ---- expressions ----
    ASTNode* parse_expression();
    ASTNode* parse_assignment_expression();
    ASTNode* parse_conditional_expression();
    ASTNode* parse_binary_expression(uint32 min_precedence);
    ASTNode* parse_cast_expression();
    ASTNode* parse_unary_expression();
    ASTNode* parse_postfix_expression();
    ASTNode* parse_primary_expression();
    ASTNode* parse_argument_list(Vector<ASTNode*>* out);

    // Skips the tokens until the end of the current statement, so that the
    // parser can carry on after an error.
    void skip_to_statement_end();

    SourceManager* sources_ = nullptr;
    DiagnosticEngine* diags_ = nullptr;
    AST* ast_ = nullptr;

    Vector<Token> tokens_;
    size_type pos_ = 0;
    ASTNode* unit_ = nullptr;
    uint32 errors_ = 0;
};

} // namespace rawr

#endif // RAWR_COMPILER_PARSER_H
