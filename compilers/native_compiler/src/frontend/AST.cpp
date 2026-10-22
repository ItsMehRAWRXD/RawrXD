#include "frontend/AST.h"

#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;
using rawrstd::Vector;
using rawrstd::size_type;

const char* ast_node_kind_name(ASTNodeKind kind) {
    switch (kind) {
        case ASTNodeKind::TranslationUnit: return "TranslationUnit";
        case ASTNodeKind::FunctionDecl: return "FunctionDecl";
        case ASTNodeKind::VarDecl: return "VarDecl";
        case ASTNodeKind::ParamDecl: return "ParamDecl";
        case ASTNodeKind::FieldDecl: return "FieldDecl";
        case ASTNodeKind::StructDecl: return "StructDecl";
        case ASTNodeKind::EnumDecl: return "EnumDecl";
        case ASTNodeKind::EnumConstant: return "EnumConstant";
        case ASTNodeKind::TypeSpecifier: return "TypeSpecifier";
        case ASTNodeKind::DeclaratorIdentifier: return "DeclaratorIdentifier";
        case ASTNodeKind::DeclaratorPointer: return "DeclaratorPointer";
        case ASTNodeKind::DeclaratorArray: return "DeclaratorArray";
        case ASTNodeKind::DeclaratorFunction: return "DeclaratorFunction";
        case ASTNodeKind::CompoundStmt: return "CompoundStmt";
        case ASTNodeKind::DeclStmt: return "DeclStmt";
        case ASTNodeKind::ExprStmt: return "ExprStmt";
        case ASTNodeKind::IfStmt: return "IfStmt";
        case ASTNodeKind::WhileStmt: return "WhileStmt";
        case ASTNodeKind::DoStmt: return "DoStmt";
        case ASTNodeKind::ForStmt: return "ForStmt";
        case ASTNodeKind::SwitchStmt: return "SwitchStmt";
        case ASTNodeKind::CaseStmt: return "CaseStmt";
        case ASTNodeKind::DefaultStmt: return "DefaultStmt";
        case ASTNodeKind::ReturnStmt: return "ReturnStmt";
        case ASTNodeKind::BreakStmt: return "BreakStmt";
        case ASTNodeKind::ContinueStmt: return "ContinueStmt";
        case ASTNodeKind::GotoStmt: return "GotoStmt";
        case ASTNodeKind::NullStmt: return "NullStmt";
        case ASTNodeKind::LabelStmt: return "LabelStmt";
        case ASTNodeKind::BinaryExpr: return "BinaryExpr";
        case ASTNodeKind::UnaryExpr: return "UnaryExpr";
        case ASTNodeKind::AssignExpr: return "AssignExpr";
        case ASTNodeKind::ConditionalExpr: return "ConditionalExpr";
        case ASTNodeKind::CallExpr: return "CallExpr";
        case ASTNodeKind::IndexExpr: return "IndexExpr";
        case ASTNodeKind::MemberExpr: return "MemberExpr";
        case ASTNodeKind::CastExpr: return "CastExpr";
        case ASTNodeKind::IdentifierExpr: return "Identifier";
        case ASTNodeKind::IntegerLiteral: return "IntegerLiteral";
        case ASTNodeKind::FloatingLiteral: return "FloatingLiteral";
        case ASTNodeKind::StringLiteral: return "StringLiteral";
        case ASTNodeKind::CharLiteral: return "CharLiteral";
        case ASTNodeKind::BoolLiteral: return "BoolLiteral";
        case ASTNodeKind::NullPtrLiteral: return "NullPtrLiteral";
        case ASTNodeKind::InitializerList: return "InitializerList";
        case ASTNodeKind::ErrorExpr: return "ErrorExpr";
        case ASTNodeKind::ErrorStmt: return "ErrorStmt";
    }
    return "Unknown";
}

ASTNode* AST::create(ASTNodeKind kind, const SourceSpan& span) {
    // A new block is allocated at its full size and is never grown, so the
    // address of a node never changes.
    if (blocks_.empty() || block_fill_ == kBlockSize) {
        Vector<ASTNode> block;
        block.resize(kBlockSize);
        blocks_.push_back(block);
        block_fill_ = 0;
    }

    ASTNode& node = blocks_.back()[block_fill_++];
    node = ASTNode();
    node.kind = kind;
    node.span = span;
    ++node_count_;
    return &node;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

static void indent(uint32 depth, String* out) {
    for (uint32 i = 0; i < depth; ++i) *out << "  ";
}

// The spelling of a punctuator, for the operator of an expression.
static const char* punctuator_spelling(TokenKind kind) {
    switch (kind) {
        case TokenKind::Plus: return "+";
        case TokenKind::Minus: return "-";
        case TokenKind::Star: return "*";
        case TokenKind::Slash: return "/";
        case TokenKind::Percent: return "%";
        case TokenKind::Amp: return "&";
        case TokenKind::Pipe: return "|";
        case TokenKind::Caret: return "^";
        case TokenKind::Tilde: return "~";
        case TokenKind::Exclaim: return "!";
        case TokenKind::AmpAmp: return "&&";
        case TokenKind::PipePipe: return "||";
        case TokenKind::Shl: return "<<";
        case TokenKind::Shr: return ">>";
        case TokenKind::Less: return "<";
        case TokenKind::Greater: return ">";
        case TokenKind::LessEqual: return "<=";
        case TokenKind::GreaterEqual: return ">=";
        case TokenKind::EqualEqual: return "==";
        case TokenKind::NotEqual: return "!=";
        case TokenKind::Assign: return "=";
        case TokenKind::PlusEqual: return "+=";
        case TokenKind::MinusEqual: return "-=";
        case TokenKind::StarEqual: return "*=";
        case TokenKind::SlashEqual: return "/=";
        case TokenKind::PercentEqual: return "%=";
        case TokenKind::AmpEqual: return "&=";
        case TokenKind::PipeEqual: return "|=";
        case TokenKind::CaretEqual: return "^=";
        case TokenKind::ShiftLeftEqual: return "<<=";
        case TokenKind::ShiftRightEqual: return ">>=";
        case TokenKind::PlusPlus: return "++";
        case TokenKind::MinusMinus: return "--";
        case TokenKind::Period: return ".";
        case TokenKind::Arrow: return "->";
        case TokenKind::Comma: return ",";
        case TokenKind::Question: return "?";
        case TokenKind::Colon: return ":";
        default: return "";
    }
}

// The type of a declaration, as the specifiers joined with a space.
static String type_text(const ASTNode* node) {
    String out;
    for (size_type i = 0; i < node->specifiers.size(); ++i) {
        const ASTNode* specifier = node->specifiers[i];
        if (i > 0) out << " ";
        if (specifier->kind == ASTNodeKind::StructDecl) {
            out << "struct";
            if (!specifier->name.empty()) out << " " << specifier->name;
        } else if (specifier->kind == ASTNodeKind::EnumDecl) {
            out << "enum";
            if (!specifier->name.empty()) out << " " << specifier->name;
        } else {
            out << specifier->name;
        }
    }
    return out;
}

// The name of the identifier a declarator chain ends in.
static String declarator_name(const ASTNode* declarator) {
    const ASTNode* node = declarator;
    while (node) {
        if (node->kind == ASTNodeKind::DeclaratorIdentifier) return node->name;
        node = node->left;
    }
    return String();
}

void AST::render_node(const ASTNode* node, uint32 depth, String* out) const {
    if (!node) return;
    indent(depth, out);
    *out << ast_node_kind_name(node->kind);

    switch (node->kind) {
        case ASTNodeKind::FunctionDecl:
            *out << " " << node->name << " -> " << type_text(node);
            break;
        case ASTNodeKind::VarDecl:
        case ASTNodeKind::ParamDecl:
        case ASTNodeKind::FieldDecl:
            if (!node->name.empty()) *out << " " << node->name;
            *out << " : " << type_text(node);
            break;
        case ASTNodeKind::StructDecl:
            if (!node->name.empty()) *out << " " << node->name;
            break;
        case ASTNodeKind::EnumDecl:
            if (!node->name.empty()) *out << " " << node->name;
            break;
        case ASTNodeKind::EnumConstant:
            *out << " " << node->name;
            break;
        case ASTNodeKind::TypeSpecifier:
            *out << " " << node->name;
            break;
        case ASTNodeKind::DeclaratorIdentifier:
            *out << " " << node->name;
            break;
        case ASTNodeKind::DeclaratorPointer:
            *out << " *";
            break;
        case ASTNodeKind::DeclaratorArray:
            // The size of the array is a child, so it is printed on its own
            // line and the shape of the declarator stays readable.
            break;
        case ASTNodeKind::DeclaratorFunction:
            *out << " ()";
            break;
        case ASTNodeKind::BinaryExpr:
        case ASTNodeKind::AssignExpr:
            *out << " " << punctuator_spelling(node->op);
            break;
        case ASTNodeKind::UnaryExpr:
            if (node->op == TokenKind::KwSizeof) {
                *out << " sizeof";
            } else {
                *out << " " << punctuator_spelling(node->op);
            }
            break;
        case ASTNodeKind::MemberExpr:
            *out << " " << punctuator_spelling(node->op) << " " << node->name;
            break;
        case ASTNodeKind::IdentifierExpr:
            *out << " " << node->name;
            break;
        case ASTNodeKind::IntegerLiteral:
        case ASTNodeKind::CharLiteral:
        case ASTNodeKind::BoolLiteral:
            *out << " " << node->int_value;
            break;
        case ASTNodeKind::FloatingLiteral:
            *out << " " << node->text;
            break;
        case ASTNodeKind::StringLiteral:
            *out << " \"" << node->text << "\"";
            break;
        case ASTNodeKind::GotoStmt:
        case ASTNodeKind::LabelStmt:
            *out << " " << node->name;
            break;
        default:
            break;
    }
    *out << "\n";
    render_children(node, depth, out);
}

void AST::render_children(const ASTNode* node, uint32 depth, String* out) const {
    if (!node) return;
    const uint32 inner = depth + 1;

    switch (node->kind) {
        case ASTNodeKind::TranslationUnit:
        case ASTNodeKind::CompoundStmt:
        case ASTNodeKind::StructDecl:
        case ASTNodeKind::EnumDecl:
        case ASTNodeKind::InitializerList:
            for (size_type i = 0; i < node->children.size(); ++i) {
                render_node(node->children[i], inner, out);
            }
            return;

        case ASTNodeKind::FunctionDecl:
            // The parameters come first, then the body.
            for (size_type i = 0; i < node->children.size(); ++i) {
                if (node->children[i]->kind == ASTNodeKind::ParamDecl) {
                    render_node(node->children[i], inner, out);
                }
            }
            render_node(node->body, inner, out);
            return;

        case ASTNodeKind::VarDecl:
        case ASTNodeKind::FieldDecl:
            // The declarator shows the shape of the name, then the
            // initialiser. A declarator that is only a name adds nothing,
            // so it is left out.
            if (node->declarator && node->declarator->left) {
                render_node(node->declarator, inner, out);
            }
            render_node(node->init, inner, out);
            return;

        case ASTNodeKind::ParamDecl:
            if (node->declarator && node->declarator->left) {
                render_node(node->declarator, inner, out);
            }
            return;

        case ASTNodeKind::DeclStmt:
            for (size_type i = 0; i < node->children.size(); ++i) {
                render_node(node->children[i], inner, out);
            }
            return;

        case ASTNodeKind::ExprStmt:
        case ASTNodeKind::ReturnStmt:
            render_node(node->value, inner, out);
            return;

        case ASTNodeKind::IfStmt:
            render_node(node->condition, inner, out);
            render_node(node->then_branch, inner, out);
            render_node(node->else_branch, inner, out);
            return;

        case ASTNodeKind::WhileStmt:
            render_node(node->condition, inner, out);
            render_node(node->body, inner, out);
            return;

        case ASTNodeKind::DoStmt:
            // The body of a do statement is written first.
            render_node(node->body, inner, out);
            render_node(node->condition, inner, out);
            return;

        case ASTNodeKind::ForStmt:
            render_node(node->init, inner, out);
            render_node(node->condition, inner, out);
            render_node(node->value, inner, out);
            render_node(node->body, inner, out);
            return;

        case ASTNodeKind::SwitchStmt:
            render_node(node->condition, inner, out);
            render_node(node->body, inner, out);
            return;

        case ASTNodeKind::CaseStmt:
            render_node(node->condition, inner, out);
            render_node(node->body, inner, out);
            return;

        case ASTNodeKind::DefaultStmt:
            render_node(node->body, inner, out);
            return;

        case ASTNodeKind::BinaryExpr:
        case ASTNodeKind::AssignExpr:
            render_node(node->left, inner, out);
            render_node(node->right, inner, out);
            return;

        case ASTNodeKind::UnaryExpr:
            render_node(node->operand, inner, out);
            return;

        case ASTNodeKind::ConditionalExpr:
            render_node(node->condition, inner, out);
            render_node(node->then_branch, inner, out);
            render_node(node->else_branch, inner, out);
            return;

        case ASTNodeKind::CallExpr:
            render_node(node->callee, inner, out);
            for (size_type i = 0; i < node->children.size(); ++i) {
                render_node(node->children[i], inner, out);
            }
            return;

        case ASTNodeKind::IndexExpr:
            render_node(node->object, inner, out);
            render_node(node->index, inner, out);
            return;

        case ASTNodeKind::MemberExpr:
            render_node(node->object, inner, out);
            return;

        case ASTNodeKind::CastExpr:
            render_node(node->type, inner, out);
            render_node(node->value, inner, out);
            return;

        case ASTNodeKind::DeclaratorPointer:
        case ASTNodeKind::DeclaratorArray:
        case ASTNodeKind::DeclaratorFunction:
            render_node(node->left, inner, out);
            if (node->kind == ASTNodeKind::DeclaratorArray) {
                render_node(node->size, inner, out);
            }
            return;

        case ASTNodeKind::ErrorStmt:
        case ASTNodeKind::ErrorExpr:
            for (size_type i = 0; i < node->children.size(); ++i) {
                render_node(node->children[i], inner, out);
            }
            return;

        default:
            for (size_type i = 0; i < node->children.size(); ++i) {
                render_node(node->children[i], inner, out);
            }
            return;
    }
}

String AST::render() const {
    String out;
    render_node(root_, 0, &out);
    return out;
}

} // namespace rawr
