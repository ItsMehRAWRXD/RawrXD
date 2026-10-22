// Sema.h â€” the semantic analysis of the C11 tree.
//
// The parser records what was written down. This layer decides what it
// means: which name is which, what type it has, whether it can be assigned
// to, and whether a call is well formed.
//
// Every diagnostic carries the span of the source it is about, so the message
// points at the text that has to change.
//
// The analysis runs BEFORE the lowering. When it reports an error, no code is
// generated at all: a program that does not make sense never becomes machine
// code.

#ifndef RAWR_COMPILER_SEMA_H
#define RAWR_COMPILER_SEMA_H

#include "frontend/AST.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

namespace rawr {

// ---------------------------------------------------------------------------
// The types
// ---------------------------------------------------------------------------
enum class CTypeKind : uint8 {
    Error,       // a type that could not be worked out
    Void,
    Bool,
    Char, Short, Int, Long, LongLong,
    UChar, UShort, UInt, ULong, ULongLong,
    Float, Double,
    Pointer,
    Array,
    Function,
    Struct,
    Enum,
};

struct CType {
    CTypeKind kind = CTypeKind::Error;

    // The pointee of a pointer, the element of an array, the return type of
    // a function.
    //
    // A type cannot hold itself, so the base is a pointer into the arena
    // the analysis owns. The arena never moves its elements, so the pointer
    // stays valid for as long as the analysis does.
    const CType* base = nullptr;

    // The number of elements of an array.
    uint32 count = 0;

    // The tag of a struct or an enum.
    String name;

    // The parameters of a function.
    Vector<const CType*> params;
    bool variadic = false;

    bool is_error() const { return kind == CTypeKind::Error; }
    bool is_void() const { return kind == CTypeKind::Void; }
    bool is_integer() const;
    bool is_arithmetic() const;
    bool is_scalar() const;
    bool is_pointer() const { return kind == CTypeKind::Pointer; }
    bool is_array() const { return kind == CTypeKind::Array; }
    bool is_function() const { return kind == CTypeKind::Function; }

    /// @brief A readable form of the type, for a diagnostic.
    String describe() const;

    /// @brief Can a value of this type be assigned to one of that type?
    bool accepts(const CType& value) const;
};

// ---------------------------------------------------------------------------
// The symbols
// ---------------------------------------------------------------------------
struct Symbol {
    String name;
    CType type;
    bool is_definition = false;   // a definition, not only a declaration
    bool is_function = false;
    SourceSpan span;
};

// A scope. The scopes nest: a file scope holds the functions and the file
// scope variables, a function scope holds the parameters, and a block scope
// holds the locals. A name is looked up from the innermost scope outwards, so
// a local may shadow an outer name.
class Scope {
public:
    explicit Scope(Scope* parent = nullptr) : parent_(parent) {}

    // Looks a name up, innermost scope first.
    const Symbol* lookup(const String& name) const;

    // Declares a name in this scope. Returns false when the name is already
    // declared here, which is a redeclaration.
    bool declare(const Symbol& symbol);

    bool is_file_scope() const { return parent_ == nullptr; }
    Scope* parent() const { return parent_; }

private:
    Scope* parent_ = nullptr;
    Vector<Symbol> symbols_;
};

// ---------------------------------------------------------------------------
// The analysis
// ---------------------------------------------------------------------------
class Sema {
public:
    /// @brief Analyses a translation unit.
    ///
    /// Returns false when a diagnostic was reported.
    bool analyze(ASTNode* unit);

    /// @brief The diagnostics, rendered.
    const String& diagnostics() const { return diagnostics_; }

    uint32 error_count() const { return errors_; }

    /// @brief The type of a declaration, for the lowering.
    ///
    /// The lowering asks for the type of a local and of a parameter, so that
    /// a store uses the right width. A type that was not worked out is the
    /// error type, and the lowering reports it.
    const CType* type_of_local(const String& name) const;

private:
    // ---- diagnostics ----
    void report(const SourceSpan& span, const char* code, const String& message);
    void report_at(const ASTNode* node, const char* code, const String& message);

    // ---- the arena of types ----
    //
    // A type may point at another type, and a type cannot hold itself, so
    // the types live in an arena that never moves them.
    const CType* intern(const CType& type);
    void release_types();

    // ---- types ----
    CType type_from_specifiers(const Vector<ASTNode*>& specifiers);
    // Resolves a declarator chain into a name and a type.
    bool resolve_declarator(ASTNode* declarator, const CType& base,
                            String* name_out, CType* type_out);

    // ---- declarations ----
    void declare_function(ASTNode* fn);
    void analyze_body(ASTNode* body, Scope* scope);
    void analyze_statement(ASTNode* stmt, Scope* scope);
    void analyze_declaration(ASTNode* decl, Scope* scope);

    // ---- expressions ----
    CType analyze_expression(ASTNode* expr, Scope* scope);
    static bool is_lvalue(ASTNode* expr);

    // ---- state ----
    Scope* scope_ = nullptr;
    Scope file_scope_;
    CType current_return_type_;
    int loop_depth_ = 0;
    int switch_depth_ = 0;
    uint32 errors_ = 0;
    String diagnostics_;
    Vector<CType*> arena_;
};

} // namespace rawr

#endif // RAWR_COMPILER_SEMA_H

