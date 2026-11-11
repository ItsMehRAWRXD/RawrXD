// Sema.cpp â€” the semantic analysis of the C11 tree.
//
// The parser records what was written down. This layer decides what it
// means, and reports every problem it finds with the span of the source it
// is about.

#include "frontend/Sema.h"

#include "frontend/Token.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

#include <cstdio>

namespace rawr {

namespace {

String num(long long value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%lld", value);
    return String(buffer);
}

String quoted(const String& text) {
    String out("\"");
    out.append(text.data(), text.size());
    out.append("\"", 1);
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// The types
// ---------------------------------------------------------------------------
bool CType::is_integer() const {
    switch (kind) {
    case CTypeKind::Bool:
    case CTypeKind::Char:  case CTypeKind::Short: case CTypeKind::Int:
    case CTypeKind::Long:  case CTypeKind::LongLong:
    case CTypeKind::UChar: case CTypeKind::UShort: case CTypeKind::UInt:
    case CTypeKind::ULong: case CTypeKind::ULongLong:
        return true;
    default:
        return false;
    }
}

bool CType::is_arithmetic() const {
    return is_integer() || kind == CTypeKind::Float || kind == CTypeKind::Double;
}

bool CType::is_scalar() const {
    return is_arithmetic() || is_pointer();
}

String CType::describe() const {
    switch (kind) {
    case CTypeKind::Error:   return "<an unknown type>";
    case CTypeKind::Void:    return "void";
    case CTypeKind::Bool:    return "bool";
    case CTypeKind::Char:    return "char";
    case CTypeKind::Short:   return "short";
    case CTypeKind::Int:     return "int";
    case CTypeKind::Long:    return "long";
    case CTypeKind::LongLong: return "long long";
    case CTypeKind::UChar:   return "unsigned char";
    case CTypeKind::UShort:  return "unsigned short";
    case CTypeKind::UInt:    return "unsigned int";
    case CTypeKind::ULong:   return "unsigned long";
    case CTypeKind::ULongLong: return "unsigned long long";
    case CTypeKind::Float:   return "float";
    case CTypeKind::Double:  return "double";
    case CTypeKind::Pointer: {
        String out = base ? base->describe() : String("<a type>");
        out.append("*", 1);
        return out;
    }
    case CTypeKind::Array: {
        String out = base ? base->describe() : String("<a type>");
        out.append("[", 1);
        out.append(num(count).data(), num(count).size());
        out.append("]", 1);
        return out;
    }
    case CTypeKind::Function: {
        String out = base ? base->describe() : String("<a type>");
        out.append("(", 1);
        for (size_type i = 0; i < params.size(); ++i) {
            if (i) out.append(", ", 2);
            const String text = params[i] ? params[i]->describe() : String("<a type>");
            out.append(text.data(), text.size());
        }
        if (variadic) out.append("...", 3);
        out.append(")", 1);
        return out;
    }
    case CTypeKind::Struct:  return "struct " + name;
    case CTypeKind::Enum:    return "enum " + name;
    }
    return "<a type>";
}

bool CType::accepts(const CType& value) const {
    if (is_error() || value.is_error()) return false;
    if (kind == value.kind) return true;
    // An integer converts to any other integer, and to a floating type.
    if (is_arithmetic() && value.is_arithmetic()) return true;
    // A pointer accepts a pointer of any type; the target types are not
    // checked yet.
    if (is_pointer() && value.is_pointer()) return true;
    // A pointer accepts the null pointer constant.
    if (is_pointer() && value.is_integer()) return true;
    if (is_void() || value.is_void()) return false;
    return false;
}

// ---------------------------------------------------------------------------
// The scopes
// ---------------------------------------------------------------------------
const Symbol* Scope::lookup(const String& name) const {
    for (size_type i = 0; i < symbols_.size(); ++i) {
        if (symbols_[i].name == name) return &symbols_[i];
    }
    return parent_ ? parent_->lookup(name) : nullptr;
}

bool Scope::declare(const Symbol& symbol) {
    for (size_type i = 0; i < symbols_.size(); ++i) {
        if (symbols_[i].name == symbol.name) return false;
    }
    symbols_.push_back(symbol);
    return true;
}

// ---------------------------------------------------------------------------
// The analysis
// ---------------------------------------------------------------------------
void Sema::report(const SourceSpan& span, const char* code, const String& message) {
    ++errors_;
    if (!diagnostics_.empty()) diagnostics_.append("\n", 1);
    diagnostics_.append("error: ", 7);
    diagnostics_.append(message.data(), message.size());
    diagnostics_.append(" [", 2);
    diagnostics_.append(code, rawrstd::strlen_raw(code));
    diagnostics_.append("]", 1);
    if (span.start_line != 0) {
        diagnostics_.append(" at line ", 10);
        diagnostics_.append(num(span.start_line).data(), num(span.start_line).size());
        diagnostics_.append(", column ", 8);
        diagnostics_.append(num(span.start_column).data(), num(span.start_column).size());
    }
}

void Sema::report_at(const ASTNode* node, const char* code, const String& message) {
    report(node ? node->span : SourceSpan(), code, message);
}

bool Sema::analyze(ASTNode* unit) {
    file_scope_ = Scope();
    scope_ = &file_scope_;
    errors_ = 0;
    diagnostics_.clear();

    if (!unit) {
        report(SourceSpan(), "C1001", String("the translation unit is empty"));
        return false;
    }

    for (size_type i = 0; i < unit->children.size(); ++i) {
        ASTNode* child = unit->children[i];
        if (!child) continue;
        if (child->kind == ASTNodeKind::FunctionDecl) {
            declare_function(child);
        } else if (child->kind == ASTNodeKind::DeclStmt) {
            for (size_type d = 0; d < child->children.size(); ++d) {
                ASTNode* var = child->children[d];
                if (!var || var->kind != ASTNodeKind::VarDecl) continue;
                const CType base = type_from_specifiers(var->specifiers);
                String name;
                CType type;
                if (!resolve_declarator(var->declarator, base, &name, &type)) {
                    report_at(var, "C1002", String("a declaration has no readable declarator"));
                    continue;
                }
                if (type.is_function()) {
                    // A prototype of a function that is defined elsewhere.
                    Symbol symbol;
                    symbol.name = name;
                    symbol.type = type;
                    symbol.is_function = true;
                    symbol.is_definition = false;
                    symbol.span = var->span;
                    if (!file_scope_.declare(symbol)) {
                        report_at(var, "C1003",
                                  String("the name ") + quoted(name) + " is declared twice");
                    }
                    continue;
                }
                report_at(var, "C1004",
                          String("a file scope variable is not supported yet: ") + name);
            }
        }
    }
    release_types();
    return errors_ == 0;
}

void Sema::declare_function(ASTNode* fn) {
    const CType return_type = type_from_specifiers(fn->specifiers);
    current_return_type_ = return_type;

    // The parameters and their types.
    Vector<CType> param_types;
    for (size_type i = 0; i < fn->children.size(); ++i) {
        ASTNode* param = fn->children[i];
        if (!param || param->kind != ASTNodeKind::ParamDecl) continue;
        const CType base = type_from_specifiers(param->specifiers);
        String name;
        CType type;
        if (!resolve_declarator(param->declarator, base, &name, &type)) {
            // A parameter with no declarator, such as "void".
            if (!base.is_void()) param_types.push_back(base);
            continue;
        }
        param_types.push_back(type);
    }

    CType type;
    type.kind = CTypeKind::Function;
    type.base = intern(return_type);
    for (size_type i = 0; i < param_types.size(); ++i) {
        type.params.push_back(intern(param_types[i]));
    }

    Symbol symbol;
    symbol.name = fn->name;
    symbol.type = type;
    symbol.is_function = true;
    symbol.is_definition = (fn->body != nullptr);
    symbol.span = fn->span;

    // A function may be declared and then defined, but declared twice is a
    // redeclaration.
    const Symbol* existing = file_scope_.lookup(fn->name);
    if (existing && existing->is_definition && symbol.is_definition) {
        report_at(fn, "C1005",
                  String("the function ") + quoted(fn->name) + " is defined twice");
    } else if (existing && existing->is_function && !existing->is_definition &&
               symbol.is_definition) {
        // A prototype and then the definition: fine.
    } else if (!existing) {
        file_scope_.declare(symbol);
    }

    if (!fn->body) return;   // a prototype

    // The function's own scope holds the parameters.
    Scope function_scope(&file_scope_);
    Scope* saved = scope_;
    scope_ = &function_scope;

    for (size_type i = 0; i < fn->children.size(); ++i) {
        ASTNode* param = fn->children[i];
        if (!param || param->kind != ASTNodeKind::ParamDecl) continue;
        if (param->name.empty() || param->name == "...") continue;
        const CType base = type_from_specifiers(param->specifiers);
        String name;
        CType type;
        if (!resolve_declarator(param->declarator, base, &name, &type)) {
            report_at(param, "C1006", String("a parameter has no readable declarator"));
            continue;
        }
        Symbol param_symbol;
        param_symbol.name = name;
        param_symbol.type = type;
        param_symbol.span = param->span;
        if (!function_scope.declare(param_symbol)) {
            report_at(param, "C1007",
                      String("the parameter ") + quoted(name) + " is declared twice");
        }
    }

    analyze_body(fn->body, &function_scope);
    scope_ = saved;
}

void Sema::analyze_body(ASTNode* body, Scope* scope) {
    if (!body) return;
    Scope* saved = scope_;
    scope_ = scope;
    for (size_type i = 0; i < body->children.size(); ++i) {
        analyze_statement(body->children[i], scope_);
    }
    scope_ = saved;
}

void Sema::analyze_statement(ASTNode* stmt, Scope* scope) {
    if (!stmt) return;
    switch (stmt->kind) {
    case ASTNodeKind::CompoundStmt: {
        // A block opens a scope of its own, so a name declared in it may
        // shadow an outer one.
        Scope block_scope(scope);
        Scope* saved = scope_;
        scope_ = &block_scope;
        for (size_type i = 0; i < stmt->children.size(); ++i) {
            analyze_statement(stmt->children[i], &block_scope);
        }
        scope_ = saved;
        return;
    }
    case ASTNodeKind::DeclStmt:
        for (size_type i = 0; i < stmt->children.size(); ++i) {
            analyze_declaration(stmt->children[i], scope);
        }
        return;
    case ASTNodeKind::ExprStmt:
        if (stmt->value) analyze_expression(stmt->value, scope);
        return;
    case ASTNodeKind::IfStmt: {
        if (stmt->condition) {
            const CType type = analyze_expression(stmt->condition, scope);
            if (!type.is_error() && !type.is_scalar()) {
                report_at(stmt->condition, "C1010",
                          String("the condition of an if must be a value, not ") +
                              type.describe());
            }
        }
        if (stmt->then_branch) analyze_statement(stmt->then_branch, scope);
        if (stmt->else_branch) analyze_statement(stmt->else_branch, scope);
        return;
    }
    case ASTNodeKind::WhileStmt:
    case ASTNodeKind::DoStmt: {
        if (stmt->condition) {
            const CType type = analyze_expression(stmt->condition, scope);
            if (!type.is_error() && !type.is_scalar()) {
                report_at(stmt->condition, "C1011",
                          String("the condition of a loop must be a value, not ") +
                              type.describe());
            }
        }
        ++loop_depth_;
        if (stmt->body) analyze_statement(stmt->body, scope);
        --loop_depth_;
        return;
    }
    case ASTNodeKind::ForStmt: {
        Scope for_scope(scope);
        Scope* saved = scope_;
        scope_ = &for_scope;
        if (stmt->init) analyze_statement(stmt->init, &for_scope);
        if (stmt->condition) analyze_expression(stmt->condition, &for_scope);
        ++loop_depth_;
        if (stmt->body) analyze_statement(stmt->body, &for_scope);
        --loop_depth_;
        if (stmt->value) analyze_expression(stmt->value, &for_scope);
        scope_ = saved;
        return;
    }
    case ASTNodeKind::ReturnStmt: {
        if (!stmt->value) {
            if (!current_return_type_.is_void()) {
                report_at(stmt, "C1012",
                          String("a function that returns ") +
                              current_return_type_.describe() +
                              " must return a value");
            }
            return;
        }
        const CType type = analyze_expression(stmt->value, scope);
        if (!type.is_error() && !current_return_type_.is_void() &&
            !current_return_type_.accepts(type)) {
            report_at(stmt->value, "C1013",
                      String("a value of type ") + type.describe() +
                          " cannot be returned from a function that returns " +
                          current_return_type_.describe());
        }
        return;
    }
    case ASTNodeKind::BreakStmt:
        if (loop_depth_ == 0 && switch_depth_ == 0) {
            report_at(stmt, "C1014", String("a break is only allowed inside a loop or a switch"));
        }
        return;
    case ASTNodeKind::ContinueStmt:
        if (loop_depth_ == 0) {
            report_at(stmt, "C1015", String("a continue is only allowed inside a loop"));
        }
        return;
    case ASTNodeKind::CaseStmt:
    case ASTNodeKind::DefaultStmt:
        if (switch_depth_ == 0) {
            report_at(stmt, "C1016",
                      String("a case is only allowed inside a switch"));
        }
        return;
    case ASTNodeKind::SwitchStmt: {
        if (stmt->condition) analyze_expression(stmt->condition, scope);
        ++switch_depth_;
        if (stmt->body) analyze_statement(stmt->body, scope);
        --switch_depth_;
        return;
    }
    case ASTNodeKind::NullStmt:
        return;
    default:
        break;
    }
    report_at(stmt, "C1017",
              String("this statement is not supported yet: ") +
                  String(ast_node_kind_name(stmt->kind)));
}

void Sema::analyze_declaration(ASTNode* decl, Scope* scope) {
    if (!decl || decl->kind != ASTNodeKind::VarDecl) return;
    const CType base = type_from_specifiers(decl->specifiers);
    String name;
    CType type;
    if (!resolve_declarator(decl->declarator, base, &name, &type)) {
        report_at(decl, "C1018", String("a declaration has no readable declarator"));
        return;
    }
    if (type.is_function()) {
        report_at(decl, "C1019",
                  String("a function cannot be declared inside a function"));
        return;
    }
    if (type.is_void()) {
        report_at(decl, "C1020", String("a variable cannot have the type void"));
        return;
    }

    Symbol symbol;
    symbol.name = name;
    symbol.type = type;
    symbol.span = decl->span;
    if (!scope->declare(symbol)) {
        report_at(decl, "C1021",
                  String("the name ") + quoted(name) + " is declared twice in the same scope");
        return;
    }

    if (decl->init) {
        const CType value = analyze_expression(decl->init, scope);
        if (!value.is_error() && !type.accepts(value)) {
            report_at(decl->init, "C1022",
                      String("a value of type ") + value.describe() +
                          " cannot be held in " + type.describe());
        }
    }
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------
bool Sema::is_lvalue(ASTNode* expr) {
    if (!expr) return false;
    switch (expr->kind) {
    case ASTNodeKind::IdentifierExpr:
    case ASTNodeKind::IndexExpr:
    case ASTNodeKind::MemberExpr:
        return true;
    default:
        return false;
    }
}

CType Sema::analyze_expression(ASTNode* expr, Scope* scope) {
    if (!expr) return CType();
    switch (expr->kind) {
    case ASTNodeKind::IntegerLiteral:
    case ASTNodeKind::CharLiteral: {
        CType type;
        type.kind = CTypeKind::Int;
        return type;
    }
    case ASTNodeKind::BoolLiteral: {
        CType type;
        type.kind = CTypeKind::Bool;
        return type;
    }
    case ASTNodeKind::FloatingLiteral: {
        CType type;
        type.kind = CTypeKind::Double;
        return type;
    }
    case ASTNodeKind::IdentifierExpr: {
        const Symbol* symbol = scope->lookup(expr->name);
        if (!symbol) {
            report_at(expr, "C1030",
                      String("the name ") + quoted(expr->name) + " is not declared");
            return CType();
        }
        return symbol->type;
    }
    case ASTNodeKind::BinaryExpr: {
        const CType left = analyze_expression(expr->left, scope);
        const CType right = analyze_expression(expr->right, scope);
        if (left.is_error() || right.is_error()) return CType();
        // The comparison operators produce an int, and so do the arithmetic
        // ones.
        switch (expr->op) {
        case TokenKind::EqualEqual: case TokenKind::NotEqual:
        case TokenKind::Less: case TokenKind::Greater:
        case TokenKind::LessEqual: case TokenKind::GreaterEqual:
        case TokenKind::AmpAmp: case TokenKind::PipePipe: {
            CType type;
            type.kind = CTypeKind::Int;
            return type;
        }
        default:
            break;
        }
        if (!left.is_arithmetic() || !right.is_arithmetic()) {
            report_at(expr, "C1031",
                      String("an arithmetic operator needs arithmetic operands, not ") +
                          left.describe() + " and " + right.describe());
            return CType();
        }
        return left.is_integer() && right.is_integer() ? left : right;
    }
    case ASTNodeKind::AssignExpr: {
        if (!is_lvalue(expr->left)) {
            report_at(expr->left, "C1032",
                      String("the left side of an assignment must be a place that can be stored to"));
            analyze_expression(expr->right, scope);
            return CType();
        }
        const CType left = analyze_expression(expr->left, scope);
        const CType right = analyze_expression(expr->right, scope);
        if (!left.is_error() && !right.is_error() && !left.accepts(right)) {
            report_at(expr, "C1033",
                      String("a value of type ") + right.describe() +
                          " cannot be stored in " + left.describe());
        }
        return left;
    }
    case ASTNodeKind::UnaryExpr: {
        const CType operand = analyze_expression(expr->operand, scope);
        if (expr->op == TokenKind::Exclaim) {
            CType type;
            type.kind = CTypeKind::Int;
            return type;
        }
        if (expr->op == TokenKind::Minus) {
            if (!operand.is_error() && !operand.is_arithmetic()) {
                report_at(expr, "C1034",
                          String("a unary minus needs a number, not ") + operand.describe());
            }
            return operand;
        }
        report_at(expr, "C1035",
                  String("this unary operator is not supported yet"));
        return CType();
    }
    case ASTNodeKind::CallExpr: {
        if (!expr->callee || expr->callee->kind != ASTNodeKind::IdentifierExpr) {
            report_at(expr, "C1036", String("only a named function can be called"));
            return CType();
        }
        const Symbol* symbol = scope->lookup(expr->callee->name);
        if (!symbol) {
            report_at(expr->callee, "C1037",
                      String("the function ") + quoted(expr->callee->name) +
                          " is not declared");
            return CType();
        }
        if (!symbol->is_function) {
            report_at(expr->callee, "C1038",
                      String("the name ") + quoted(expr->callee->name) +
                          " is not a function");
            return CType();
        }
        const size_t given = expr->children.size();
        const size_t wanted = symbol->type.params.size();
        if (given != wanted && !symbol->type.variadic) {
            report_at(expr, "C1039",
                      String("the function ") + quoted(expr->callee->name) +
                          " takes " + num((long long)wanted) + " arguments but " +
                          num((long long)given) + " were given");
        }
        for (size_type i = 0; i < expr->children.size(); ++i) {
            const CType argument = analyze_expression(expr->children[i], scope);
            if (i < wanted && !argument.is_error() &&
                !symbol->type.params[i]->accepts(argument)) {
                report_at(expr->children[i], "C1040",
                          String("an argument of type ") + argument.describe() +
                              " does not fit the parameter of type " +
                              symbol->type.params[i]->describe());
            }
        }
        return symbol->type.base ? *symbol->type.base : CType();
    }
    case ASTNodeKind::CastExpr: {
        analyze_expression(expr->operand, scope);
        return type_from_specifiers(expr->specifiers);
    }
    case ASTNodeKind::ConditionalExpr: {
        const CType left = analyze_expression(expr->left, scope);
        const CType right = analyze_expression(expr->right, scope);
        if (!left.is_error() && !right.is_error()) {
            return left.accepts(right) ? left : right;
        }
        return CType();
    }
    default:
        break;
    }
    report_at(expr, "C1041",
              String("this expression is not supported yet: ") +
                  String(ast_node_kind_name(expr->kind)));
    return CType();
}

// ---------------------------------------------------------------------------
// The arena of types
// ---------------------------------------------------------------------------
const CType* Sema::intern(const CType& type) {
    CType* copy = new CType(type);
    arena_.push_back(copy);
    return copy;
}

void Sema::release_types() {
    for (size_type i = 0; i < arena_.size(); ++i) delete arena_[i];
    arena_.clear();
}

// ---------------------------------------------------------------------------
// The types from the specifiers
// ---------------------------------------------------------------------------
CType Sema::type_from_specifiers(const Vector<ASTNode*>& specifiers) {
    CType type;
    type.kind = CTypeKind::Int;

    bool is_signed = true;
    bool is_unsigned = false;
    int longs = 0;
    int shorts = 0;
    bool saw_char = false;
    bool saw_int = false;
    bool saw_bool = false;
    bool saw_float = false;
    bool saw_double = false;
    bool saw_void = false;

    for (size_type i = 0; i < specifiers.size(); ++i) {
        const ASTNode* spec = specifiers[i];
        if (!spec) continue;
        if (spec->kind == ASTNodeKind::StructDecl) {
            CType s;
            s.kind = CTypeKind::Struct;
            s.name = spec->name;
            return s;
        }
        if (spec->kind == ASTNodeKind::EnumDecl) {
            CType e;
            e.kind = CTypeKind::Enum;
            e.name = spec->name;
            return e;
        }
        switch (spec->op) {
        case TokenKind::KwVoid:     saw_void = true; break;
        case TokenKind::KwChar:     saw_char = true; break;
        case TokenKind::KwShort:    ++shorts; break;
        case TokenKind::KwInt:      saw_int = true; break;
        case TokenKind::KwLong:     ++longs; break;
        case TokenKind::KwSigned:   is_signed = true; break;
        case TokenKind::KwUnsigned: is_unsigned = true; is_signed = false; break;
        case TokenKind::KwBool:     saw_bool = true; break;
        case TokenKind::KwFloat:    saw_float = true; break;
        case TokenKind::KwDouble:   saw_double = true; break;
        default: break;
        }
    }

    if (saw_void) { type.kind = CTypeKind::Void; return type; }
    if (saw_bool) { type.kind = CTypeKind::Bool; return type; }
    if (saw_float) { type.kind = CTypeKind::Float; return type; }
    if (saw_double) { type.kind = CTypeKind::Double; return type; }
    if (saw_char) { type.kind = is_unsigned ? CTypeKind::UChar : CTypeKind::Char; return type; }
    if (shorts) { type.kind = is_unsigned ? CTypeKind::UShort : CTypeKind::Short; return type; }
    if (longs >= 2) { type.kind = is_unsigned ? CTypeKind::ULongLong : CTypeKind::LongLong; return type; }
    if (longs == 1) { type.kind = is_unsigned ? CTypeKind::ULong : CTypeKind::Long; return type; }
    type.kind = is_unsigned ? CTypeKind::UInt : CTypeKind::Int;
    (void)saw_int;
    return type;
}

// ---------------------------------------------------------------------------
// The declarator chain
// ---------------------------------------------------------------------------
bool Sema::resolve_declarator(ASTNode* declarator, const CType& base,
                               String* name_out, CType* type_out) {
    if (!declarator) return false;

    // The chain hangs from the outermost constructor inwards through "left",
    // and the type is built from the identifier outwards. The constructors are
    // therefore applied in the reverse of the order they appear in the chain.
    Vector<ASTNode*> wrappers;
    ASTNode* node = declarator;
    while (node && node->kind != ASTNodeKind::DeclaratorIdentifier) {
        wrappers.push_back(node);
        node = node->left;
    }
    if (!node) return false;
    if (name_out) *name_out = node->name;

    CType type = base;
    for (size_type i = wrappers.size(); i > 0; --i) {
        ASTNode* wrapper = wrappers[i - 1];
        switch (wrapper->kind) {
        case ASTNodeKind::DeclaratorPointer: {
            CType pointer;
            pointer.kind = CTypeKind::Pointer;
            // The element type goes into the arena, so that the pointer
            // keeps pointing at it for as long as the analysis lives.
            pointer.base = intern(type);
            type = pointer;
            break;
        }
        case ASTNodeKind::DeclaratorArray: {
            CType array;
            array.kind = CTypeKind::Array;
            array.base = intern(type);
            if (wrapper->size) {
                const ASTNode* count = wrapper->size;
                if (count->kind == ASTNodeKind::IntegerLiteral) {
                    array.count = (uint32)count->int_value;
                }
            }
            type = array;
            break;
        }
        case ASTNodeKind::DeclaratorFunction: {
            CType function;
            function.kind = CTypeKind::Function;
            function.base = intern(type);
            for (size_type p = 0; p < wrapper->children.size(); ++p) {
                const ASTNode* param = wrapper->children[p];
                if (!param) continue;
                if (param->name == "...") { function.variadic = true; continue; }
                const CType param_type = type_from_specifiers(param->specifiers);
                // "(void)" is an empty parameter list, not a parameter of
                // type void.
                if (param_type.is_void() && param->name.empty()) continue;
                function.params.push_back(intern(param_type));
            }
            type = function;
            break;
        }
        default:
            return false;
        }
    }
    if (type_out) *type_out = type;
    return true;
}


} // namespace rawr



