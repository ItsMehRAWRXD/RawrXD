// The abstract syntax tree of the RawrXD native compiler.
//
// The tree holds the SYNTAX of a translation unit. It deliberately does not
// hold resolved types: the type of an expression is a question for the
// semantic analysis, and the parser only records what was written down.
//
// Every node carries the range of source it came from, so a later stage can
// point at the exact text that has to change when the tree is repaired.
//
// The nodes live in an arena that the tree owns. The arena hands out
// pointers that stay valid for as long as the tree does, and the tree frees
// all of them at once. Nothing is freed while the tree is being built, so a
// node can safely refer to a node that was created earlier.

#ifndef RAWR_COMPILER_AST_H
#define RAWR_COMPILER_AST_H

#include "frontend/Token.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

namespace rawr {

// A range in a source file.
struct SourceSpan {
    uint32 file_id = 0;
    uint32 start = 0;      // the byte offset of the first character
    uint32 end = 0;        // the byte offset past the last character
    uint32 start_line = 0;
    uint32 start_column = 0;
    uint32 end_line = 0;
    uint32 end_column = 0;

    bool valid() const { return end > start || file_id != 0; }
};

// The kinds of node the tree holds.
enum class ASTNodeKind {
    // The root and the declarations.
    TranslationUnit,
    FunctionDecl,
    VarDecl,
    ParamDecl,
    FieldDecl,
    StructDecl,
    EnumDecl,
    EnumConstant,
    TypeSpecifier,

    // The declarator chain. A declarator is built from the inside out, so
    // "int *a[10]" is an array of pointers: the array node holds the
    // pointer node, and the pointer node holds the identifier.
    DeclaratorIdentifier,
    DeclaratorPointer,
    DeclaratorArray,
    DeclaratorFunction,

    // The statements.
    CompoundStmt,
    DeclStmt,
    ExprStmt,
    IfStmt,
    WhileStmt,
    DoStmt,
    ForStmt,
    SwitchStmt,
    CaseStmt,
    DefaultStmt,
    ReturnStmt,
    BreakStmt,
    ContinueStmt,
    GotoStmt,
    NullStmt,
    LabelStmt,

    // The expressions.
    BinaryExpr,
    UnaryExpr,
    AssignExpr,
    ConditionalExpr,
    CallExpr,
    IndexExpr,
    MemberExpr,
    CastExpr,
    IdentifierExpr,
    IntegerLiteral,
    FloatingLiteral,
    StringLiteral,
    CharLiteral,
    BoolLiteral,
    NullPtrLiteral,
    InitializerList,

    // The nodes that stand in for something that could not be parsed.
    ErrorExpr,
    ErrorStmt,
};

// Returns the name of a node kind, as it appears in the rendered tree.
const char* ast_node_kind_name(ASTNodeKind kind);

struct ASTNode {
    ASTNodeKind kind = ASTNodeKind::ErrorExpr;
    SourceSpan span;

    // The identifier, the member name or the tag name.
    String name;
    // The spelling of a literal.
    String text;
    int64 int_value = 0;
    double float_value = 0.0;
    // The operator of an expression, or the keyword of a type specifier.
    TokenKind op = TokenKind::EndOfFile;

    // The named links. Which ones are used depends on the kind.
    ASTNode* left = nullptr;          // the left operand, the inner declarator
    ASTNode* right = nullptr;         // the right operand
    ASTNode* condition = nullptr;     // the condition of a branch or a loop
    ASTNode* then_branch = nullptr;   // the body of an if
    ASTNode* else_branch = nullptr;   // the else of an if
    ASTNode* body = nullptr;          // the body of a loop or a function
    ASTNode* init = nullptr;          // the initialiser of a declaration
    ASTNode* value = nullptr;         // the value of a return or a statement
    ASTNode* operand = nullptr;       // the operand of a unary expression
    ASTNode* callee = nullptr;        // the function of a call
    ASTNode* index = nullptr;         // the index of a subscript
    ASTNode* object = nullptr;        // the object of a member access
    ASTNode* declarator = nullptr;    // the declarator of a declaration
    ASTNode* size = nullptr;          // the size expression of an array
    ASTNode* type = nullptr;          // the type of a cast or a sizeof

    // The list: the statements of a block, the parameters of a function, the
    // fields of a struct, the arguments of a call, the items of an
    // initialiser.
    Vector<ASTNode*> children;

    // The type specifiers of a declaration, for example "unsigned int".
    // They are kept apart from the list, because the list of a function
    // holds its parameters and the type of the function is not the same
    // thing.
    Vector<ASTNode*> specifiers;
};

// The tree of a translation unit.
class AST {
public:
    AST() = default;

    // Creates a node and returns a pointer to it. The pointer stays valid
    // for as long as the tree does.
    ASTNode* create(ASTNodeKind kind, const SourceSpan& span);

    ASTNode* root() const { return root_; }
    void set_root(ASTNode* node) { root_ = node; }

    uint32 node_count() const { return node_count_; }

    // Renders the tree in a fixed form. The same tree always renders to the
    // same text, which is what makes the shape of a tree testable.
    String render() const;

private:
    void render_node(const ASTNode* node, uint32 depth, String* out) const;
    void render_children(const ASTNode* node, uint32 depth, String* out) const;

    // The nodes, in blocks. A block is allocated once and never grows, so
    // the address of a node never changes.
    static const size_type kBlockSize = 128;
    Vector<Vector<ASTNode>> blocks_;
    size_type block_fill_ = 0;
    ASTNode* root_ = nullptr;
    uint32 node_count_ = 0;
};

} // namespace rawr

#endif // RAWR_COMPILER_AST_H
