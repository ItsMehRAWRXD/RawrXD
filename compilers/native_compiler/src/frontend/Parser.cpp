#include "frontend/Parser.h"

#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;
using rawrstd::Vector;
using rawrstd::size_type;
using rawrstd::int64;

// ---------------------------------------------------------------------------
// The tables
// ---------------------------------------------------------------------------

// The precedence of the binary operators. A higher number binds tighter.
static uint32 binary_precedence(TokenKind kind) {
    switch (kind) {
        case TokenKind::PipePipe: return 1;
        case TokenKind::AmpAmp: return 2;
        case TokenKind::Pipe: return 3;
        case TokenKind::Caret: return 4;
        case TokenKind::Amp: return 5;
        case TokenKind::EqualEqual:
        case TokenKind::NotEqual: return 6;
        case TokenKind::Less:
        case TokenKind::Greater:
        case TokenKind::LessEqual:
        case TokenKind::GreaterEqual: return 7;
        case TokenKind::Shl:
        case TokenKind::Shr: return 8;
        case TokenKind::Plus:
        case TokenKind::Minus: return 9;
        case TokenKind::Star:
        case TokenKind::Slash:
        case TokenKind::Percent: return 10;
        default: return 0;
    }
}

static bool is_assignment_operator(TokenKind kind) {
    switch (kind) {
        case TokenKind::Assign:
        case TokenKind::PlusEqual:
        case TokenKind::MinusEqual:
        case TokenKind::StarEqual:
        case TokenKind::SlashEqual:
        case TokenKind::PercentEqual:
        case TokenKind::AmpEqual:
        case TokenKind::PipeEqual:
        case TokenKind::CaretEqual:
        case TokenKind::ShiftLeftEqual:
        case TokenKind::ShiftRightEqual: return true;
        default: return false;
    }
}

// The keywords that can be part of a declaration specifier.
static bool is_type_specifier_keyword(TokenKind kind) {
    switch (kind) {
        case TokenKind::KwVoid:
        case TokenKind::KwChar:
        case TokenKind::KwChar8_t:
        case TokenKind::KwChar16_t:
        case TokenKind::KwChar32_t:
        case TokenKind::KwWchar_t:
        case TokenKind::KwBool:
        case TokenKind::KwShort:
        case TokenKind::KwInt:
        case TokenKind::KwLong:
        case TokenKind::KwFloat:
        case TokenKind::KwDouble:
        case TokenKind::KwSigned:
        case TokenKind::KwUnsigned: return true;
        default: return false;
    }
}

// The keywords that can be part of a declaration specifier but do not name
// a type.
static bool is_other_specifier_keyword(TokenKind kind) {
    switch (kind) {
        case TokenKind::KwTypedef:
        case TokenKind::KwExtern:
        case TokenKind::KwStatic:
        case TokenKind::KwAuto:
        case TokenKind::KwRegister:
        case TokenKind::KwThread_local:
        case TokenKind::KwConst:
        case TokenKind::KwVolatile:
        case TokenKind::KwConstexpr:
        case TokenKind::KwConsteval:
        case TokenKind::KwConstinit:
        case TokenKind::KwInline:
        case TokenKind::KwAlignas:
        case TokenKind::KwStatic_assert:
        case TokenKind::KwNoexcept: return true;
        default: return false;
    }
}

// The qualifiers that can follow a star in a declarator.
static bool is_pointer_qualifier(TokenKind kind) {
    switch (kind) {
        case TokenKind::KwConst:
        case TokenKind::KwVolatile: return true;
        default: return false;
    }
}

// True when the token can begin a declaration.
static bool is_declaration_start(TokenKind kind) {
    return is_type_specifier_keyword(kind) || is_other_specifier_keyword(kind) ||
           kind == TokenKind::KwStruct || kind == TokenKind::KwUnion ||
           kind == TokenKind::KwEnum;
}

// True when the token can begin a type name, which is what tells a cast
// from a parenthesised expression.
//
// A name introduced by a typedef cannot be told apart from a variable
// without the symbol table, and the symbol table belongs to the semantic
// analysis. The parser therefore only recognises the built in type names.
static bool is_type_name_start(TokenKind kind) {
    return is_type_specifier_keyword(kind) || kind == TokenKind::KwStruct ||
           kind == TokenKind::KwUnion || kind == TokenKind::KwEnum;
}

// Parses the value of an integer literal. The spelling may carry a suffix.
static bool parse_integer_value(const String& text, int64* out) {
    size_type i = 0;
    int base = 10;
    bool negative = false;

    if (i < text.size() && (text[i] == '+' || text[i] == '-')) {
        negative = (text[i] == '-');
        ++i;
    }
    if (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
        base = 16;
        i += 2;
    } else if (i + 1 < text.size() && text[i] == '0' &&
               (text[i + 1] == 'b' || text[i + 1] == 'B')) {
        base = 2;
        i += 2;
    } else if (i < text.size() && text[i] == '0') {
        base = 8;
    }

    uint64 value = 0;
    size_type digits = 0;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '\'') continue;
        int digit = -1;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        if (digit < 0 || digit >= base) break;
        value = value * static_cast<uint64>(base) + static_cast<uint64>(digit);
        ++digits;
    }
    if (digits == 0) return false;
    *out = negative ? -static_cast<int64>(value) : static_cast<int64>(value);
    return true;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Parser::Parser(SourceManager* sources, DiagnosticEngine* diags, AST* ast)
    : sources_(sources), diags_(diags), ast_(ast) {}

// ---------------------------------------------------------------------------
// The token stream
// ---------------------------------------------------------------------------

const Token& Parser::peek(size_type ahead) const {
    static const Token kEnd;
    const size_type index = pos_ + ahead;
    if (index >= tokens_.size()) return kEnd;
    return tokens_[index];
}

const Token& Parser::advance() {
    static const Token kEnd;
    if (pos_ >= tokens_.size()) return kEnd;
    return tokens_[pos_++];
}

bool Parser::check(TokenKind kind) const {
    return pos_ < tokens_.size() && tokens_[pos_].kind == kind;
}

bool Parser::check_at(size_type ahead, TokenKind kind) const {
    const size_type index = pos_ + ahead;
    return index < tokens_.size() && tokens_[index].kind == kind;
}

bool Parser::match(TokenKind kind) {
    if (!check(kind)) return false;
    ++pos_;
    return true;
}

const Token& Parser::expect(TokenKind kind, const char* what) {
    if (check(kind)) return advance();
    static const Token kEnd;
    error_at_current("C0200", what);
    return kEnd;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

void Parser::error(const SourceLoc& loc, const char* code, const char* message) {
    ++errors_;
    if (diags_) diags_->error(loc, code, String(message));
}

void Parser::error_at_current(const char* code, const char* message) {
    SourceLoc loc;
    if (pos_ < tokens_.size()) {
        loc = tokens_[pos_].loc;
    } else if (!tokens_.empty()) {
        // The input ended. The diagnostic still points at the source, at the
        // last token there was.
        loc = tokens_[tokens_.size() - 1].loc;
    }
    error(loc, code, message);
}

SourceSpan Parser::span_from(size_type first_token, size_type last_token) const {
    SourceSpan span;
    if (first_token >= tokens_.size() || last_token >= tokens_.size()) return span;
    const Token& first = tokens_[first_token];
    const Token& last = tokens_[last_token];
    span.file_id = first.loc.file_id;
    span.start = first.loc.offset;
    span.end = last.loc.offset + last.length;
    if (sources_) {
        sources_->locate(span.file_id, span.start, &span.start_line, &span.start_column);
        sources_->locate(span.file_id, span.end, &span.end_line, &span.end_column);
    }
    return span;
}

SourceSpan Parser::span_of_current() const {
    if (pos_ >= tokens_.size()) return SourceSpan();
    return span_from(pos_, pos_);
}

// ---------------------------------------------------------------------------
// Declarations
// ---------------------------------------------------------------------------

bool Parser::parse_declaration_specifiers(Vector<ASTNode*>* out) {
    bool any = false;
    for (;;) {
        const TokenKind kind = peek().kind;
        if (kind == TokenKind::KwStruct || kind == TokenKind::KwUnion) {
            const size_type start = pos_;
            const bool is_union = (kind == TokenKind::KwUnion);
            ASTNode* node = parse_struct_or_union_specifier(is_union);
            if (!node) return any;
            node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
            out->push_back(node);
            any = true;
            continue;
        }
        if (kind == TokenKind::KwEnum) {
            const size_type start = pos_;
            ASTNode* node = parse_enum_specifier();
            if (!node) return any;
            node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
            out->push_back(node);
            any = true;
            continue;
        }
        if (is_type_specifier_keyword(kind) || is_other_specifier_keyword(kind)) {
            const size_type start = pos_;
            const Token token = advance();
            ASTNode* node = ast_->create(ASTNodeKind::TypeSpecifier, span_from(start, start));
            node->op = token.kind;
            node->name = token.text;
            out->push_back(node);
            any = true;
            continue;
        }
        break;
    }
    return any;
}

ASTNode* Parser::parse_struct_or_union_specifier(bool is_union) {
    (void)is_union;
    const size_type start = pos_;
    advance();   // 'struct' or 'union'

    ASTNode* node = ast_->create(ASTNodeKind::StructDecl, span_of_current());
    if (check(TokenKind::Identifier)) node->name = advance().text;

    if (check(TokenKind::LBrace)) {
        advance();   // '{'
        node->children = parse_struct_declarator_list();
        expect(TokenKind::RBrace, "expected '}' at the end of the struct");
    }
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

Vector<ASTNode*> Parser::parse_struct_declarator_list() {
    Vector<ASTNode*> fields;
    while (!check(TokenKind::RBrace) && !at_end()) {
        Vector<ASTNode*> specifiers;
        if (!parse_declaration_specifiers(&specifiers)) {
            error_at_current("C0201", "expected a type in the struct");
            break;
        }
        if (match(TokenKind::Semicolon)) continue;   // an anonymous member

        for (;;) {
            const size_type start = pos_;
            Declarator declarator;
            if (!parse_declarator(&declarator)) {
                error_at_current("C0202", "expected a member name");
                break;
            }
            ASTNode* field = ast_->create(ASTNodeKind::FieldDecl,
                                           span_from(start, pos_ > start ? pos_ - 1 : start));
            field->name = declarator.name;
            field->specifiers = specifiers;
            field->declarator = build_declarator_chain(declarator, field->span);
            if (check(TokenKind::Colon)) {
                advance();
                parse_declarator(&declarator);   // the bit field width
            }
            fields.push_back(field);
            if (!match(TokenKind::Comma)) break;
        }
        if (!match(TokenKind::Semicolon)) {
            error_at_current("C0203", "expected ';' at the end of the member");
            break;
        }
    }
    return fields;
}

ASTNode* Parser::parse_enum_specifier() {
    const size_type start = pos_;
    advance();   // 'enum'

    ASTNode* node = ast_->create(ASTNodeKind::EnumDecl, span_of_current());
    if (check(TokenKind::Identifier)) node->name = advance().text;

    if (check(TokenKind::LBrace)) {
        advance();   // '{'
        while (!check(TokenKind::RBrace) && !at_end()) {
            if (!check(TokenKind::Identifier)) {
                error_at_current("C0204", "expected the name of an enum constant");
                break;
            }
            const size_type constant_start = pos_;
            const Token name = advance();
            ASTNode* constant = ast_->create(ASTNodeKind::EnumConstant,
                                             span_from(constant_start, constant_start));
            constant->name = name.text;
            if (match(TokenKind::Assign)) {
                ASTNode* value = parse_conditional_expression();
                if (value) constant->init = value;
            }
            node->children.push_back(constant);
            if (!match(TokenKind::Comma)) break;
        }
        expect(TokenKind::RBrace, "expected '}' at the end of the enum");
    }
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

// Parses a declarator.
//
// The declarator is kept as a chain of constructors, from the identifier
// outward. The order of the chain is the order in which the type is built:
// the base type first, and each constructor on top of it.
//
// The prefix pointers of a level are applied to the base before the
// suffixes of the same level, and a declarator in brackets is applied last.
// That is what makes "int *D[10]" an array of pointers and "int (*D)[10]" a
// pointer to an array.
bool Parser::parse_declarator(Declarator* out) {
    const size_type start = pos_;

    // The prefix pointers of this level. They apply to the base type, so
    // they come before the suffixes of the same level.
    while (check(TokenKind::Star)) {
        const size_type pointer_start = pos_;
        advance();
        while (is_pointer_qualifier(peek().kind)) advance();
        DeclaratorStep step;
        step.kind = ASTNodeKind::DeclaratorPointer;
        step.span = span_from(pointer_start, pos_ > pointer_start ? pos_ - 1 : pointer_start);
        out->steps.push_back(step);
    }

    Vector<DeclaratorStep> suffixes;
    Vector<DeclaratorStep> nested;

    if (check(TokenKind::LParen)) {
        // A declarator in brackets. Its steps are applied after the
        // suffixes of this level.
        advance();   // '('
        Declarator inner;
        if (!parse_declarator(&inner)) {
            error_at_current("C0205", "expected a declarator");
            return false;
        }
        expect(TokenKind::RParen, "expected ')' after the declarator");
        out->name = inner.name;
        parse_declarator_suffixes(&suffixes);
        nested = inner.steps;
    } else {
        if (!check(TokenKind::Identifier)) {
            error_at_current("C0205", "expected a name");
            return false;
        }
        out->name = advance().text;
        parse_declarator_suffixes(&suffixes);
    }

    // The suffixes of this level are applied after the pointers of this
    // level, and the first suffix is the outermost constructor. A
    // declarator in brackets is applied last.
    for (size_type i = suffixes.size(); i > 0; --i) {
        out->steps.push_back(suffixes[i - 1]);
    }
    for (size_type i = 0; i < nested.size(); ++i) {
        out->steps.push_back(nested[i]);
    }

    out->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return true;
}

void Parser::parse_declarator_suffixes(Vector<DeclaratorStep>* steps) {
    for (;;) {
        if (check(TokenKind::LBracket)) {
            const size_type start = pos_;
            advance();   // '['
            DeclaratorStep step;
            step.kind = ASTNodeKind::DeclaratorArray;
            if (!check(TokenKind::RBracket)) {
                ASTNode* size = parse_conditional_expression();
                step.size = size;
            }
            expect(TokenKind::RBracket, "expected ']' after the array size");
            step.span = span_from(start, pos_ > start ? pos_ - 1 : start);
            steps->push_back(step);
            continue;
        }
        if (check(TokenKind::LParen)) {
            const size_type start = pos_;
            advance();   // '('
            DeclaratorStep step;
            step.kind = ASTNodeKind::DeclaratorFunction;
            if (!check(TokenKind::RParen)) {
                parse_parameter_list(&step.parameters);
            }
            expect(TokenKind::RParen, "expected ')' after the parameter list");
            step.span = span_from(start, pos_ > start ? pos_ - 1 : start);
            steps->push_back(step);
            continue;
        }
        break;
    }
}

ASTNode* Parser::build_declarator_chain(const Declarator& declarator, const SourceSpan& span) {
    ASTNode* chain = ast_->create(ASTNodeKind::DeclaratorIdentifier, span);
    chain->name = declarator.name;
    // The steps are in the order the type is built, so the last one is the
    // outermost constructor.
    for (size_type i = 0; i < declarator.steps.size(); ++i) {
        const DeclaratorStep& step = declarator.steps[i];
        ASTNode* node = ast_->create(step.kind, step.span);
        node->left = chain;
        if (step.kind == ASTNodeKind::DeclaratorArray) {
            node->size = step.size;
        } else if (step.kind == ASTNodeKind::DeclaratorFunction) {
            node->children = step.parameters;
        }
        chain = node;
    }
    return chain;
}

void Parser::parse_parameter_list(Vector<ASTNode*>* out) {
    for (;;) {
        if (check(TokenKind::Ellipsis)) {
            // The variable part of the list. It is recorded as a parameter
            // with no name, so the shape of the list stays visible.
            const size_type start = pos_;
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::ParamDecl, span_from(start, start));
            node->name = "...";
            out->push_back(node);
            break;
        }

        Vector<ASTNode*> specifiers;
        if (!parse_declaration_specifiers(&specifiers)) {
            error_at_current("C0206", "expected the type of a parameter");
            break;
        }
        const size_type start = pos_;
        Declarator declarator;
        // The name of a parameter is optional, as in "int f(void)".
        const bool has_declarator = check(TokenKind::Identifier) ||
                                    check(TokenKind::Star) ||
                                    check(TokenKind::LParen);
        const bool has_name = has_declarator ? parse_declarator(&declarator) : true;
        ASTNode* node = ast_->create(ASTNodeKind::ParamDecl,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->specifiers = specifiers;
        if (has_name) {
            node->name = declarator.name;
            node->declarator = build_declarator_chain(declarator, node->span);
        }
        out->push_back(node);

        if (!match(TokenKind::Comma)) break;
    }
}

// Parses a type name, which is what appears in a cast and in a sizeof.
ASTNode* Parser::parse_type_name() {
    Vector<ASTNode*> specifiers;
    if (!parse_declaration_specifiers(&specifiers)) {
        error_at_current("C0207", "expected a type name");
        return nullptr;
    }
    const size_type start = pos_;
    Declarator declarator;
    if (!check(TokenKind::RParen)) parse_declarator(&declarator);

    ASTNode* node = ast_->create(ASTNodeKind::TypeSpecifier,
                                 span_from(start, pos_ > start ? pos_ - 1 : start));
    node->name = "type-name";
    node->specifiers = specifiers;
    if (!declarator.name.empty()) {
        node->declarator = build_declarator_chain(declarator, node->span);
    }
    return node;
}

ASTNode* Parser::parse_initializer() {
    if (check(TokenKind::LBrace)) {
        const size_type start = pos_;
        advance();   // '{'
        ASTNode* node = ast_->create(ASTNodeKind::InitializerList, span_of_current());
        while (!check(TokenKind::RBrace) && !at_end()) {
            ASTNode* item = parse_initializer();
            if (item) node->children.push_back(item);
            if (!match(TokenKind::Comma)) break;
        }
        expect(TokenKind::RBrace, "expected '}' at the end of the initializer");
        node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
        return node;
    }
    return parse_assignment_expression();
}

// Parses a declaration, which is a list of declarators with their
// initialisers. The node holds the specifiers and one child per declarator.
ASTNode* Parser::parse_declaration() {
    const size_type start = pos_;
    Vector<ASTNode*> specifiers;
    if (!parse_declaration_specifiers(&specifiers)) {
        error_at_current("C0208", "expected a declaration");
        return nullptr;
    }

    ASTNode* node = ast_->create(ASTNodeKind::DeclStmt, span_of_current());
    node->specifiers = specifiers;

    for (;;) {
        const size_type declarator_start = pos_;
        Declarator declarator;
        if (!parse_declarator(&declarator)) break;
        ASTNode* variable = ast_->create(ASTNodeKind::VarDecl,
                                         span_from(declarator_start, pos_ > declarator_start ? pos_ - 1 : declarator_start));
        variable->name = declarator.name;
        variable->specifiers = specifiers;
        variable->declarator = build_declarator_chain(declarator, variable->span);
        if (match(TokenKind::Assign)) {
            variable->init = parse_initializer();
        }
        node->children.push_back(variable);

        if (!match(TokenKind::Comma)) break;
    }

    if (!match(TokenKind::Semicolon)) {
        error_at_current("C0203", "expected ';' at the end of the declaration");
    }
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_function_definition(ASTNode* declaration) {
    // The declaration holds the specifiers and the declarator. The body
    // becomes the second child.
    ASTNode* body = parse_compound_statement();
    if (!body) return declaration;
    declaration->body = body;
    return declaration;
}

ASTNode* Parser::parse_external_declaration() {
    const size_type start = pos_;

    if (check(TokenKind::Semicolon)) {
        advance();
        error_at_current("C0209", "an empty declaration is not allowed");
        return nullptr;
    }

    Vector<ASTNode*> specifiers;
    if (!parse_declaration_specifiers(&specifiers)) {
        error_at_current("C0208", "expected a declaration");
        skip_to_statement_end();
        return nullptr;
    }

    // A declaration that only names a type, like "struct Point { ... };".
    if (check(TokenKind::Semicolon)) {
        ASTNode* node = ast_->create(ASTNodeKind::DeclStmt, span_of_current());
        node->specifiers = specifiers;
        for (size_type i = 0; i < specifiers.size(); ++i) {
            if (specifiers[i]->kind == ASTNodeKind::StructDecl ||
                specifiers[i]->kind == ASTNodeKind::EnumDecl) {
                node->children.push_back(specifiers[i]);
            }
        }
        advance();   // ';'
        node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
        return node;
    }

    const size_type declarator_start = pos_;
    Declarator declarator;
    if (!parse_declarator(&declarator)) {
        skip_to_statement_end();
        return nullptr;
    }

    // A declarator whose outermost constructor is a function is a function.
    const bool is_function = !declarator.steps.empty() &&
                             declarator.steps[declarator.steps.size() - 1].kind ==
                                 ASTNodeKind::DeclaratorFunction;

    if (is_function && check(TokenKind::LBrace)) {
        ASTNode* node = ast_->create(ASTNodeKind::FunctionDecl,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->name = declarator.name;
        node->specifiers = specifiers;
        node->declarator = build_declarator_chain(declarator, node->span);
        // The parameters are the children of the function declarator.
        for (size_type i = 0; i < declarator.steps.size(); ++i) {
            if (declarator.steps[i].kind == ASTNodeKind::DeclaratorFunction) {
                node->specifiers = specifiers;
                for (size_type k = 0; k < declarator.steps[i].parameters.size(); ++k) {
                    node->children.push_back(declarator.steps[i].parameters[k]);
                }
            }
        }
        parse_function_definition(node);
        node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
        return node;
    }

    // Otherwise it is a declaration, which may hold more than one name.
    ASTNode* node = ast_->create(ASTNodeKind::DeclStmt, span_of_current());
    node->specifiers = specifiers;

    ASTNode* variable = ast_->create(ASTNodeKind::VarDecl,
                                     span_from(declarator_start, pos_ > declarator_start ? pos_ - 1 : declarator_start));
    variable->name = declarator.name;
    variable->specifiers = specifiers;
    variable->declarator = build_declarator_chain(declarator, variable->span);
    if (match(TokenKind::Assign)) {
        variable->init = parse_initializer();
    }
    node->children.push_back(variable);

    while (match(TokenKind::Comma)) {
        const size_type next_start = pos_;
        Declarator next;
        if (!parse_declarator(&next)) {
            error_at_current("C0205", "expected a name");
            break;
        }
        ASTNode* more = ast_->create(ASTNodeKind::VarDecl,
                                     span_from(next_start, pos_ > next_start ? pos_ - 1 : next_start));
        more->name = next.name;
        more->specifiers = specifiers;
        more->declarator = build_declarator_chain(next, more->span);
        if (match(TokenKind::Assign)) {
            more->init = parse_initializer();
        }
        node->children.push_back(more);
    }

    if (!match(TokenKind::Semicolon)) {
        error_at_current("C0203", "expected ';' at the end of the declaration");
        skip_to_statement_end();
    }
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

ASTNode* Parser::parse_compound_statement() {
    const size_type start = pos_;
    expect(TokenKind::LBrace, "expected '{'");
    ASTNode* node = ast_->create(ASTNodeKind::CompoundStmt, span_of_current());
    for (;;) {
        if (check(TokenKind::RBrace) || at_end()) break;
        const size_type before = pos_;
        if (is_declaration_start(peek().kind)) {
            ASTNode* declaration = parse_declaration();
            if (declaration) node->children.push_back(declaration);
        } else {
            ASTNode* statement = parse_statement();
            if (statement) node->children.push_back(statement);
        }
        // The parser has to make progress, whatever the input is.
        if (pos_ == before) {
            advance();
        }
    }
    expect(TokenKind::RBrace, "expected '}' at the end of the block");
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_if_statement() {
    const size_type start = pos_;
    advance();   // 'if'
    expect(TokenKind::LParen, "expected '(' after 'if'");
    ASTNode* condition = parse_expression();
    expect(TokenKind::RParen, "expected ')' after the condition");
    ASTNode* node = ast_->create(ASTNodeKind::IfStmt, span_of_current());
    node->condition = condition;
    node->then_branch = parse_statement();
    if (match(TokenKind::KwElse)) {
        node->else_branch = parse_statement();
    }
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_while_statement() {
    const size_type start = pos_;
    advance();   // 'while'
    expect(TokenKind::LParen, "expected '(' after 'while'");
    ASTNode* condition = parse_expression();
    expect(TokenKind::RParen, "expected ')' after the condition");
    ASTNode* node = ast_->create(ASTNodeKind::WhileStmt, span_of_current());
    node->condition = condition;
    node->body = parse_statement();
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_do_statement() {
    const size_type start = pos_;
    advance();   // 'do'
    ASTNode* node = ast_->create(ASTNodeKind::DoStmt, span_of_current());
    node->body = parse_statement();
    expect(TokenKind::KwWhile, "expected 'while' after the body of a do statement");
    expect(TokenKind::LParen, "expected '(' after 'while'");
    node->condition = parse_expression();
    expect(TokenKind::RParen, "expected ')' after the condition");
    expect(TokenKind::Semicolon, "expected ';' at the end of a do statement");
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_for_statement() {
    const size_type start = pos_;
    advance();   // 'for'
    expect(TokenKind::LParen, "expected '(' after 'for'");
    ASTNode* node = ast_->create(ASTNodeKind::ForStmt, span_of_current());

    // The first part is a declaration or an expression.
    if (is_declaration_start(peek().kind)) {
        node->init = parse_declaration();
    } else {
        node->init = parse_expression_statement();
    }
    if (!check(TokenKind::Semicolon)) {
        node->condition = parse_expression();
    }
    expect(TokenKind::Semicolon, "expected ';' after the condition of a for statement");
    if (!check(TokenKind::RParen)) {
        node->value = parse_expression();
    }
    expect(TokenKind::RParen, "expected ')' after the parts of a for statement");
    node->body = parse_statement();
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_switch_statement() {
    const size_type start = pos_;
    advance();   // 'switch'
    expect(TokenKind::LParen, "expected '(' after 'switch'");
    ASTNode* condition = parse_expression();
    expect(TokenKind::RParen, "expected ')' after the condition");
    ASTNode* node = ast_->create(ASTNodeKind::SwitchStmt, span_of_current());
    node->condition = condition;
    node->body = parse_statement();
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_case_statement() {
    const size_type start = pos_;
    if (match(TokenKind::KwCase)) {
        ASTNode* value = parse_conditional_expression();
        expect(TokenKind::Colon, "expected ':' after the value of a case");
        ASTNode* node = ast_->create(ASTNodeKind::CaseStmt, span_of_current());
        node->condition = value;
        node->body = parse_statement();
        node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
        return node;
    }
    advance();   // 'default'
    expect(TokenKind::Colon, "expected ':' after 'default'");
    ASTNode* node = ast_->create(ASTNodeKind::DefaultStmt, span_of_current());
    node->body = parse_statement();
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_return_statement() {
    const size_type start = pos_;
    advance();   // 'return'
    ASTNode* node = ast_->create(ASTNodeKind::ReturnStmt, span_of_current());
    if (!check(TokenKind::Semicolon)) {
        node->value = parse_expression();
    }
    expect(TokenKind::Semicolon, "expected ';' at the end of a return statement");
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_expression_statement() {
    const size_type start = pos_;
    ASTNode* node = ast_->create(ASTNodeKind::ExprStmt, span_of_current());
    if (!check(TokenKind::Semicolon)) {
        node->value = parse_expression();
    }
    expect(TokenKind::Semicolon, "expected ';' at the end of the statement");
    node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
    return node;
}

ASTNode* Parser::parse_statement() {
    const size_type start = pos_;
    switch (peek().kind) {
        case TokenKind::LBrace: return parse_compound_statement();
        case TokenKind::KwIf: return parse_if_statement();
        case TokenKind::KwWhile: return parse_while_statement();
        case TokenKind::KwDo: return parse_do_statement();
        case TokenKind::KwFor: return parse_for_statement();
        case TokenKind::KwSwitch: return parse_switch_statement();
        case TokenKind::KwCase:
        case TokenKind::KwDefault: return parse_case_statement();
        case TokenKind::KwReturn: return parse_return_statement();
        case TokenKind::KwBreak: {
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::BreakStmt, span_from(start, start));
            expect(TokenKind::Semicolon, "expected ';' after 'break'");
            node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
            return node;
        }
        case TokenKind::KwContinue: {
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::ContinueStmt, span_from(start, start));
            expect(TokenKind::Semicolon, "expected ';' after 'continue'");
            node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
            return node;
        }
        case TokenKind::KwGoto: {
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::GotoStmt, span_of_current());
            if (check(TokenKind::Identifier)) node->name = advance().text;
            expect(TokenKind::Semicolon, "expected ';' at the end of a goto statement");
            node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
            return node;
        }
        case TokenKind::Semicolon: {
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::NullStmt, span_from(start, start));
            return node;
        }
        case TokenKind::Identifier:
            // A label is an identifier followed by a colon.
            if (check_at(1, TokenKind::Colon)) {
                ASTNode* node = ast_->create(ASTNodeKind::LabelStmt, span_of_current());
                node->name = advance().text;
                advance();   // ':'
                node->body = parse_statement();
                node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
                return node;
            }
            break;
        default:
            break;
    }
    return parse_expression_statement();
}

void Parser::skip_to_statement_end() {
    int depth = 0;
    while (!at_end()) {
        if (check(TokenKind::LBrace)) ++depth;
        if (check(TokenKind::RBrace)) {
            if (depth == 0) return;
            --depth;
        }
        if (depth == 0 && check(TokenKind::Semicolon)) {
            advance();
            return;
        }
        advance();
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

ASTNode* Parser::parse_expression() {
    const size_type start = pos_;
    ASTNode* left = parse_assignment_expression();
    while (check(TokenKind::Comma)) {
        advance();
        ASTNode* right = parse_assignment_expression();
        ASTNode* node = ast_->create(ASTNodeKind::BinaryExpr,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->op = TokenKind::Comma;
        node->left = left;
        node->right = right;
        left = node;
    }
    return left;
}

ASTNode* Parser::parse_assignment_expression() {
    const size_type start = pos_;
    ASTNode* left = parse_conditional_expression();
    if (is_assignment_operator(peek().kind)) {
        const Token op = advance();
        // The assignment operators are right associative.
        ASTNode* right = parse_assignment_expression();
        ASTNode* node = ast_->create(ASTNodeKind::AssignExpr,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->op = op.kind;
        node->left = left;
        node->right = right;
        return node;
    }
    return left;
}

ASTNode* Parser::parse_conditional_expression() {
    const size_type start = pos_;
    ASTNode* condition = parse_binary_expression(1);
    if (check(TokenKind::Question)) {
        advance();
        ASTNode* then_branch = parse_expression();
        expect(TokenKind::Colon, "expected ':' in the conditional expression");
        // The conditional operator is right associative.
        ASTNode* else_branch = parse_conditional_expression();
        ASTNode* node = ast_->create(ASTNodeKind::ConditionalExpr,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->condition = condition;
        node->then_branch = then_branch;
        node->else_branch = else_branch;
        return node;
    }
    return condition;
}

ASTNode* Parser::parse_binary_expression(uint32 min_precedence) {
    const size_type start = pos_;
    ASTNode* left = parse_cast_expression();
    for (;;) {
        const uint32 precedence = binary_precedence(peek().kind);
        if (precedence == 0 || precedence < min_precedence) break;
        const Token op = advance();
        // Every binary operator is left associative, so the right hand side
        // only takes the operators that bind tighter.
        ASTNode* right = parse_binary_expression(precedence + 1);
        ASTNode* node = ast_->create(ASTNodeKind::BinaryExpr,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->op = op.kind;
        node->left = left;
        node->right = right;
        left = node;
    }
    return left;
}

ASTNode* Parser::parse_cast_expression() {
    const size_type start = pos_;
    if (check(TokenKind::LParen) && is_type_name_start(peek(1).kind)) {
        const size_type saved = pos_;
        advance();   // '('
        ASTNode* type = parse_type_name();
        if (type && check(TokenKind::RParen)) {
            advance();   // ')'
            ASTNode* value = parse_cast_expression();
            ASTNode* node = ast_->create(ASTNodeKind::CastExpr,
                                         span_from(start, pos_ > start ? pos_ - 1 : start));
            node->type = type;
            node->value = value;
            return node;
        }
        // It was not a cast after all.
        pos_ = saved;
    }
    return parse_unary_expression();
}

ASTNode* Parser::parse_unary_expression() {
    const size_type start = pos_;
    const TokenKind kind = peek().kind;

    if (kind == TokenKind::PlusPlus || kind == TokenKind::MinusMinus) {
        const Token op = advance();
        ASTNode* operand = parse_unary_expression();
        ASTNode* node = ast_->create(ASTNodeKind::UnaryExpr,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->op = op.kind;
        node->operand = operand;
        return node;
    }

    if (kind == TokenKind::Exclaim || kind == TokenKind::Tilde ||
        kind == TokenKind::Plus || kind == TokenKind::Minus) {
        const Token op = advance();
        ASTNode* operand = parse_cast_expression();
        ASTNode* node = ast_->create(ASTNodeKind::UnaryExpr,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->op = op.kind;
        node->operand = operand;
        return node;
    }

    if (kind == TokenKind::KwSizeof) {
        const Token op = advance();
        ASTNode* node = ast_->create(ASTNodeKind::UnaryExpr,
                                     span_from(start, pos_ > start ? pos_ - 1 : start));
        node->op = op.kind;
        if (check(TokenKind::LParen) && is_type_name_start(peek(1).kind)) {
            advance();   // '('
            node->type = parse_type_name();
            expect(TokenKind::RParen, "expected ')' after the type name");
        } else {
            node->operand = parse_unary_expression();
        }
        node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
        return node;
    }

    return parse_postfix_expression();
}

ASTNode* Parser::parse_argument_list(Vector<ASTNode*>* out) {
    while (!check(TokenKind::RParen) && !at_end()) {
        ASTNode* argument = parse_assignment_expression();
        if (argument) out->push_back(argument);
        if (!match(TokenKind::Comma)) break;
    }
    return nullptr;
}

ASTNode* Parser::parse_postfix_expression() {
    const size_type start = pos_;
    ASTNode* expression = parse_primary_expression();
    for (;;) {
        if (check(TokenKind::LBracket)) {
            advance();
            ASTNode* index = parse_expression();
            expect(TokenKind::RBracket, "expected ']' after the index");
            ASTNode* node = ast_->create(ASTNodeKind::IndexExpr,
                                         span_from(start, pos_ > start ? pos_ - 1 : start));
            node->object = expression;
            node->index = index;
            expression = node;
            continue;
        }
        if (check(TokenKind::LParen)) {
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::CallExpr,
                                         span_from(start, pos_ > start ? pos_ - 1 : start));
            node->callee = expression;
            parse_argument_list(&node->children);
            expect(TokenKind::RParen, "expected ')' after the arguments");
            node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
            expression = node;
            continue;
        }
        if (check(TokenKind::Period) || check(TokenKind::Arrow)) {
            const Token op = advance();
            ASTNode* node = ast_->create(ASTNodeKind::MemberExpr,
                                         span_from(start, pos_ > start ? pos_ - 1 : start));
            node->op = op.kind;
            node->object = expression;
            if (check(TokenKind::Identifier)) {
                node->name = advance().text;
            } else {
                error_at_current("C0210", "expected the name of a member");
            }
            node->span = span_from(start, pos_ > start ? pos_ - 1 : start);
            expression = node;
            continue;
        }
        if (check(TokenKind::PlusPlus) || check(TokenKind::MinusMinus)) {
            const Token op = advance();
            ASTNode* node = ast_->create(ASTNodeKind::UnaryExpr,
                                         span_from(start, pos_ > start ? pos_ - 1 : start));
            node->op = op.kind;
            node->operand = expression;
            expression = node;
            continue;
        }
        break;
    }
    return expression;
}

ASTNode* Parser::parse_primary_expression() {
    const size_type start = pos_;
    const Token& token = peek();

    switch (token.kind) {
        case TokenKind::Identifier: {
            ASTNode* node = ast_->create(ASTNodeKind::IdentifierExpr, span_of_current());
            node->name = advance().text;
            return node;
        }
        case TokenKind::IntegerLiteral: {
            const Token spelling = advance();
            ASTNode* node = ast_->create(ASTNodeKind::IntegerLiteral, span_from(start, start));
            node->text = spelling.text;
            if (!parse_integer_value(spelling.text, &node->int_value)) {
                node->int_value = 0;
            }
            return node;
        }
        case TokenKind::FloatingLiteral: {
            const Token spelling = advance();
            ASTNode* node = ast_->create(ASTNodeKind::FloatingLiteral, span_from(start, start));
            node->text = spelling.text;
            node->float_value = 0.0;
            for (size_type i = 0; i < spelling.text.size(); ++i) {
                const char c = spelling.text[i];
                if ((c >= '0' && c <= '9') || c == '.') {
                    node->float_value = node->float_value * 10.0 +
                                        (c == '.' ? 0.0 : static_cast<double>(c - '0'));
                } else {
                    break;
                }
            }
            return node;
        }
        case TokenKind::CharacterLiteral: {
            const Token spelling = advance();
            ASTNode* node = ast_->create(ASTNodeKind::CharLiteral, span_from(start, start));
            node->text = spelling.text;
            // The value of a character literal is the value of the last
            // character in it, which is the rule for a single character.
            if (!spelling.text.empty()) {
                const char c = spelling.text[spelling.text.size() - 1];
                node->int_value = static_cast<int64>(c);
            }
            return node;
        }
        case TokenKind::StringLiteral: {
            const Token spelling = advance();
            ASTNode* node = ast_->create(ASTNodeKind::StringLiteral, span_from(start, start));
            node->text = spelling.text;
            return node;
        }
        case TokenKind::KwTrue:
        case TokenKind::KwFalse: {
            const bool value = (token.kind == TokenKind::KwTrue);
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::BoolLiteral, span_from(start, start));
            node->int_value = value ? 1 : 0;
            return node;
        }
        case TokenKind::KwNullptr: {
            advance();
            return ast_->create(ASTNodeKind::NullPtrLiteral, span_from(start, start));
        }
        case TokenKind::KwThis: {
            advance();
            ASTNode* node = ast_->create(ASTNodeKind::IdentifierExpr, span_from(start, start));
            node->name = "this";
            return node;
        }
        case TokenKind::LParen: {
            advance();
            ASTNode* inner = parse_expression();
            expect(TokenKind::RParen, "expected ')' at the end of the expression");
            return inner;
        }
        default:
            break;
    }

    error_at_current("C0211", "expected an expression");
    // An error node keeps the tree well formed, so the stages after the
    // parser still have something to walk.
    ASTNode* node = ast_->create(ASTNodeKind::ErrorExpr, span_of_current());
    if (!at_end() && !check(TokenKind::Semicolon) &&
        !check(TokenKind::RBrace) && !check(TokenKind::RParen)) {
        advance();
    }
    return node;
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

bool Parser::parse_translation_unit(const Vector<Token>& tokens) {
    tokens_ = tokens;
    pos_ = 0;
    errors_ = 0;

    ASTNode* unit = ast_->create(ASTNodeKind::TranslationUnit, span_of_current());
    for (;;) {
        if (at_end()) break;
        const size_type before = pos_;
        ASTNode* declaration = parse_external_declaration();
        if (declaration) unit->children.push_back(declaration);
        if (pos_ == before) {
            // The parser has to make progress, whatever the input is.
            advance();
        }
    }
    unit->span = span_of_current();
    ast_->set_root(unit);
    unit_ = unit;
    return errors_ == 0;
}

} // namespace rawr
