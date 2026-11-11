// A C front end that lowers C source to x64 assembly.
//
// The output is the MASM-style assembly the certified first-party assembler
// already reads, so the pipeline is
//
//     C source  ->  this front end  ->  .asm  ->  rawr_asm  ->  .obj
//               ->  rawrxd_link  ->  .exe  ->  Windows
//
// The lexer is the certified one from src/frontend/Lexer.h. Nothing here
// re-implements lexing.
//
// ---------------------------------------------------------------------------
// The subset
// ---------------------------------------------------------------------------
//
//   int f(int a, int b) { ... }
//   int x = expr;      x = expr;      expr;
//   return expr;
//   if (expr) stmt [else stmt]
//   while (expr) stmt
//   { stmt* }
//
// Expressions: integer literals, identifiers, calls, assignment, the binary
// operators with their C precedence, ! and unary minus.
//
// ---------------------------------------------------------------------------
// The frame
// ---------------------------------------------------------------------------
//
// Win64. A function keeps its arguments and its locals in the frame, and
// temporaries are frame slots too, so the stack pointer never moves inside a
// body. That is what keeps the 16 byte alignment the ABI requires at a call
// intact: the frame size is a multiple of 16, the shadow space is 32 bytes,
// and nothing is pushed and popped around a call.
//
// The slots are addressed from rbp, downwards. Slot k is at [rbp - 8*(k+1)].
// Locals come first, then the temporaries, which are handed out and taken
// back as the expression nesting unwinds.

#include "common/Diagnostics.h"
#include "common/SourceManager.h"
#include "frontend/Lexer.h"
#include "frontend/Token.h"

#include <cstdio>

#include "frontend/c_stage2.h"

#include "rawrstd/string.h"
#include "rawrstd/sys.h"
#include "rawrstd/vector.h"

namespace rawr {
// Append a string to another.
//
// rawrstd::String has operator+= for a character and for a C string, but not
// for another String, so this is the way to join two of them.
static void append_string(rawrstd::String* target, const rawrstd::String& value) {
    target->append(value.data(), value.size());
}
// A decimal rendering of a value.
//
// rawrstd::String has no constructor from an integer, so the number is
// formatted first.
static rawrstd::String num(long long value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%lld", value);
    return rawrstd::String(buffer);
}

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------
enum class CKind : uint8 {
    Program, Function, Block,
    Return, If, While, Decl, Assign, ExprStmt,
    Number, Ident, Call, Binary, Unary,
};

struct CNode {
    CKind kind = CKind::Program;
    rawrstd::String text;        // identifier, operator, or parameter name
    long long value = 0;         // integer literal
    CNode* a = nullptr;
    CNode* b = nullptr;
    CNode* c = nullptr;
    rawrstd::Vector<CNode*> kids;    // parameters, arguments, statements
    int slot = -1;               // frame slot, filled in by the code generator
    bool is_param = false;
};

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------
class CParser {
public:
    CParser(Lexer* lexer, rawrstd::String* error)
        : lexer_(lexer), error_(error) {}

    CNode* parse_program() {
        CNode* program = new_node(CKind::Program);
        while (peek().kind != TokenKind::EndOfFile) {
            CNode* fn = parse_function();
            if (!fn) return nullptr;
            program->kids.push_back(fn);
        }
        return program;
    }

private:
    Lexer* lexer_ = nullptr;
    rawrstd::String* error_ = nullptr;

    CNode* new_node(CKind kind) {
        CNode* n = new CNode();
        n->kind = kind;
        return n;
    }

    const Token& peek() {
        if (!has_peeked_) {
            lexer_->next(&peeked_);
            has_peeked_ = true;
        }
        return peeked_;
    }

    Token advance() {
        peek();
        has_peeked_ = false;
        return peeked_;
    }

    bool check(TokenKind k) { return peek().kind == k; }

    bool check_keyword(const char* spelling) {
        return peek().kind == TokenKind::Keyword && peek().text == spelling;
    }

    bool accept(TokenKind k) {
        if (!check(k)) return false;
        advance();
        return true;
    }

    bool fail(const char* message) {
        if (error_ && error_->empty()) {
            *error_ = rawrstd::String(message);
            *error_ += " (line ";
            append_string(error_, num(static_cast<int>(peek().loc.line)));
            *error_ += ")";
        }
        return false;
    }

    // ---- functions ----
    CNode* parse_function() {
        if (!check(TokenKind::KwInt) && !check(TokenKind::KwVoid)) {
            fail("expected a return type");
            return nullptr;
        }
        advance();
        if (!check(TokenKind::Identifier)) { fail("expected a function name"); return nullptr; }
        CNode* fn = new_node(CKind::Function);
        fn->text = advance().text;
        if (!accept(TokenKind::LParen)) { fail("expected '('"); return nullptr; }
        // "(void)" is an empty parameter list, not a parameter of type void.
        if (check(TokenKind::KwVoid)) {
            advance();
        } else if (!check(TokenKind::RParen)) {
            for (;;) {
                if (!check(TokenKind::KwInt)) { fail("expected a parameter type"); return nullptr; }
                advance();
                if (!check(TokenKind::Identifier)) { fail("expected a parameter name"); return nullptr; }
                CNode* param = new_node(CKind::Ident);
                param->text = advance().text;
                param->is_param = true;
                fn->kids.push_back(param);
                if (accept(TokenKind::Comma)) continue;
                break;
            }
        }
        if (!accept(TokenKind::RParen)) { fail("expected ')'"); return nullptr; }
        // A prototype declares a function that is defined elsewhere. It has
        // no body, so nothing is generated for it, and its parameters are
        // not locals of this function.
        if (check(TokenKind::Semicolon)) {
            advance();
            CNode* declaration = new_node(CKind::Function);
            declaration->text = fn->text;
            fn->kids.clear();
            declaration->a = nullptr;
            return declaration;
        }
        CNode* body = parse_block();
        if (!body) return nullptr;
        fn->a = body;
        return fn;
    }

    CNode* parse_block() {
        if (!accept(TokenKind::LBrace)) { fail("expected '{'"); return nullptr; }
        CNode* block = new_node(CKind::Block);
        while (!check(TokenKind::RBrace) && !check(TokenKind::EndOfFile)) {
            CNode* stmt = parse_statement();
            if (!stmt) return nullptr;
            block->kids.push_back(stmt);
        }
        if (!accept(TokenKind::RBrace)) { fail("expected '}'"); return nullptr; }
        return block;
    }

    // ---- statements ----
    CNode* parse_statement() {
        if (check(TokenKind::KwReturn)) {
            advance();
            CNode* ret = new_node(CKind::Return);
            ret->a = parse_expression();
            if (!ret->a) return nullptr;
            if (!accept(TokenKind::Semicolon)) { fail("expected ';'"); return nullptr; }
            return ret;
        }
        if (check(TokenKind::KwIf)) {
            advance();
            CNode* if_node = new_node(CKind::If);
            if (!accept(TokenKind::LParen)) { fail("expected '('"); return nullptr; }
            if_node->a = parse_expression();
            if (!if_node->a) return nullptr;
            if (!accept(TokenKind::RParen)) { fail("expected ')'"); return nullptr; }
            if_node->b = parse_statement();
            if (!if_node->b) return nullptr;
            if (accept(TokenKind::KwElse)) {
                if_node->c = parse_statement();
                if (!if_node->c) return nullptr;
            }
            return if_node;
        }
        if (check(TokenKind::KwWhile)) {
            advance();
            CNode* loop = new_node(CKind::While);
            if (!accept(TokenKind::LParen)) { fail("expected '('"); return nullptr; }
            loop->a = parse_expression();
            if (!loop->a) return nullptr;
            if (!accept(TokenKind::RParen)) { fail("expected ')'"); return nullptr; }
            loop->b = parse_statement();
            if (!loop->b) return nullptr;
            return loop;
        }
        if (check(TokenKind::LBrace)) {
            return parse_block();
        }
        if (check(TokenKind::KwInt)) {
            // A declaration: int name [= expr] ;
            advance();
            if (!check(TokenKind::Identifier)) { fail("expected a variable name"); return nullptr; }
            CNode* decl = new_node(CKind::Decl);
            decl->text = advance().text;
            if (accept(TokenKind::Assign)) {
                decl->a = parse_expression();
                if (!decl->a) return nullptr;
            }
            if (!accept(TokenKind::Semicolon)) { fail("expected ';'"); return nullptr; }
            return decl;
        }
        // Either an assignment or an expression statement.
        CNode* expr = parse_expression();
        if (!expr) return nullptr;
        if (check(TokenKind::Assign)) {
            advance();
            CNode* assign = new_node(CKind::Assign);
            assign->a = expr;
            assign->b = parse_expression();
            if (!assign->b) return nullptr;
            if (!accept(TokenKind::Semicolon)) { fail("expected ';'"); return nullptr; }
            return assign;
        }
        CNode* stmt = new_node(CKind::ExprStmt);
        stmt->a = expr;
        if (!accept(TokenKind::Semicolon)) { fail("expected ';'"); return nullptr; }
        return stmt;
    }

    // ---- expressions ----
    //
    // Precedence climbing. The table is C's, lowest binding first.
    CNode* parse_expression() { return parse_assignment(); }

    CNode* parse_assignment() {
        CNode* left = parse_binary(0);
        if (!left) return nullptr;
        if (check(TokenKind::Assign)) {
            advance();
            CNode* assign = new_node(CKind::Assign);
            assign->a = left;
            assign->b = parse_assignment();
            return assign->b ? assign : nullptr;
        }
        return left;
    }

    struct OpLevel { TokenKind kind; const char* op; };

    static int precedence_of(TokenKind k, const char** op_out) {
        switch (k) {
        case TokenKind::PipePipe: *op_out = "||"; return 1;
        case TokenKind::AmpAmp:   *op_out = "&&"; return 2;
        case TokenKind::Pipe:     *op_out = "|";  return 3;
        case TokenKind::Caret:    *op_out = "^";  return 4;
        case TokenKind::Amp:      *op_out = "&";  return 5;
        case TokenKind::EqualEqual:  *op_out = "=="; return 6;
        case TokenKind::NotEqual:    *op_out = "!="; return 6;
        case TokenKind::Less:        *op_out = "<";  return 7;
        case TokenKind::Greater:     *op_out = ">";  return 7;
        case TokenKind::LessEqual:   *op_out = "<="; return 7;
        case TokenKind::GreaterEqual:*op_out = ">="; return 7;
        case TokenKind::Plus:     *op_out = "+";  return 8;
        case TokenKind::Minus:    *op_out = "-";  return 8;
        case TokenKind::Star:     *op_out = "*";  return 9;
        case TokenKind::Slash:    *op_out = "/";  return 9;
        case TokenKind::Percent:  *op_out = "%";  return 9;
        default: return 0;
        }
    }

    CNode* parse_binary(int min_prec) {
        CNode* left = parse_unary();
        if (!left) return nullptr;
        for (;;) {
            const char* op = nullptr;
            const int prec = precedence_of(peek().kind, &op);
            if (prec == 0 || prec < min_prec) break;
            advance();
            CNode* right = parse_binary(prec + 1);
            if (!right) return nullptr;
            CNode* node = new_node(CKind::Binary);
            node->text = rawrstd::String(op);
            node->a = left;
            node->b = right;
            left = node;
        }
        return left;
    }

    CNode* parse_unary() {
        if (check(TokenKind::Exclaim) || check(TokenKind::Minus)) {
            const bool negate = check(TokenKind::Minus);
            advance();
            CNode* operand = parse_unary();
            if (!operand) return nullptr;
            CNode* node = new_node(CKind::Unary);
            node->text = rawrstd::String(negate ? "-" : "!");
            node->a = operand;
            return node;
        }
        return parse_primary();
    }

    CNode* parse_primary() {
        if (check(TokenKind::IntegerLiteral)) {
            CNode* node = new_node(CKind::Number);
            const rawrstd::String text = advance().text;
            node->value = parse_integer(text);
            return node;
        }
        if (check(TokenKind::Identifier)) {
            const rawrstd::String name = advance().text;
            if (check(TokenKind::LParen)) {
                advance();
                CNode* call = new_node(CKind::Call);
                call->text = name;
                if (!check(TokenKind::RParen)) {
                    for (;;) {
                        CNode* arg = parse_expression();
                        if (!arg) return nullptr;
                        call->kids.push_back(arg);
                        if (accept(TokenKind::Comma)) continue;
                        break;
                    }
                }
                if (!accept(TokenKind::RParen)) { fail("expected ')'"); return nullptr; }
                return call;
            }
            CNode* node = new_node(CKind::Ident);
            node->text = name;
            return node;
        }
        if (accept(TokenKind::LParen)) {
            CNode* inner = parse_expression();
            if (!inner) return nullptr;
            if (!accept(TokenKind::RParen)) { fail("expected ')'"); return nullptr; }
            return inner;
        }
        fail("expected an expression");
        return nullptr;
    }

    static long long parse_integer(const rawrstd::String& text) {
        if (text.empty()) return 0;
        long long value = 0;
        int base = 10;
        size_type i = 0;
        if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
            base = 16;
            i = 2;
        }
        for (; i < text.size(); ++i) {
            const char c = text[i];
            int digit = -1;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
            else break;
            if (digit >= base) break;
            value = value * base + digit;
        }
        return value;
    }

    Token peeked_;
    bool has_peeked_ = false;
};

// ---------------------------------------------------------------------------
// The code generator
// ---------------------------------------------------------------------------
class CCodeGen {
public:
    explicit CCodeGen(rawrstd::String* out) : out_(out) {}

    void generate(CNode* program) {
        // The functions this program defines.
        defined_.clear();
        externals_.clear();
        for (CNode* fn : program->kids) {
            if (fn->a) defined_.push_back(fn->text);
        }

        // The bodies are generated first. A function that is called but
        // defined in another translation unit has to be declared external, and
        // that is only known once the bodies have been read. The assembler
        // needs to be told: a relocation against a symbol it has never heard
        // of cannot be written.
        rawrstd::String body;
        rawrstd::String* saved = out_;
        out_ = &body;
        for (CNode* fn : program->kids) {
            // A prototype has no body and produces no code.
            if (!fn->a) continue;
            emit_function(fn);
        }
        out_ = saved;

        line("; Generated by the RawrXD C front end");
        line("; x64 assembly for the first-party assembler");
        line("");
        line("bits 64");
        line("default rel");
        line("");
        line("section .text");
        line("extern ExitProcess");
        for (const rawrstd::String& name : externals_) {
            if (!is_defined(name)) {
                line((rawrstd::String("extern ") + name).data());
            }
        }
        line("");
        out_->append(body.data(), body.size());
    }

    bool is_defined(const rawrstd::String& name) const {
        for (const rawrstd::String& candidate : defined_) {
            if (candidate == name) return true;
        }
        return false;
    }

private:
    rawrstd::String* out_ = nullptr;
    int label_counter_ = 0;
    int local_count_ = 0;
    int temp_base_ = 0;
    int temp_top_ = 0;
    int max_temp_ = 0;
    int param_count_ = 0;
    int epilogue_label_ = 0;
    bool is_main_ = false;
    bool uses_exit_ = false;

    // A label on a line of its own.
    //
    // The label and its colon have to be on the same line: the assembler
    // reads a label as an identifier followed by a colon, in one line.
    void line_label(const rawrstd::String& name) {
        out_->append(name.data(), name.size());
        out_->append(":", 1);
        out_->append("\n", 1);
    }
    void line(const char* text) {
        out_->append(text, rawrstd::strlen_raw(text));
        out_->append("\n", 1);
    }

    void emit(const rawrstd::String& text) {
        out_->append("    ", 4);
        out_->append(text.data(), text.size());
        out_->append("\n", 1);
    }

    int new_label() { return ++label_counter_; }

    rawrstd::String label_name(int n) {
        rawrstd::String s(".L");
        append_string(&s, num(n));
        return s;
    }

    // A frame slot is addressed from rbp, downwards.
    rawrstd::String slot_ref(int slot) {
        rawrstd::String s("[rbp - ");
        append_string(&s, num(8 * (slot + 1)));
        append_string(&s, rawrstd::String("]"));
        return s;
    }

    // ---- functions ----
    void emit_function(CNode* fn) {
        is_main_ = (fn->text == "main");

        // The parameters arrive in the argument registers and are given slots.
        // They are locals like any other, so they have to be in the table the
        // name lookup searches, or every use of a parameter reads slot zero.
        local_count_ = 0;
        param_count_ = 0;
        locals_.clear();
        for (CNode* param : fn->kids) {
            param->slot = local_count_++;
            ++param_count_;
            locals_.push_back(param);
        }

        // The body is generated first, because the frame size depends on how
        // many temporaries the body needed.
        collect_locals(fn->a);
        epilogue_label_ = new_label();
        temp_base_ = local_count_;
        temp_top_ = temp_base_;
        max_temp_ = temp_base_;
        rawrstd::String body;
        rawrstd::String* saved = out_;
        out_ = &body;
        for (CNode* stmt : fn->a->kids) {
            emit_statement(stmt);
        }
        out_ = saved;

        const int slots = local_count_ > max_temp_ ? local_count_ : max_temp_;
        // 32 bytes of shadow space, and the frame size is a multiple of 16
        // so that the stack is aligned at every call.
        //
        // The rounding has to be a rounding UP to the next multiple of 16.
        // Adding 16 to a frame that is already 8 past a multiple leaves it 8
        // past a multiple, and a call made with the stack misaligned is a
        // call the callee may not survive.
        int frame = 32 + 8 * slots;
        frame = ((frame + 15) / 16) * 16;

        line((rawrstd::String("global ") + fn->text).data());
        line_label(fn->text);
        emit(rawrstd::String("push rbp"));
        emit(rawrstd::String("mov rbp, rsp"));
        emit(rawrstd::String("sub rsp, ") + num(frame));

        // The parameters are moved into their slots before anything else can
        // overwrite the argument registers.
        static const char* kArgRegs[4] = {"rcx", "rdx", "r8", "r9"};
        for (size_t i = 0; i < fn->kids.size() && i < 4; ++i) {
            emit(rawrstd::String("mov ") + slot_ref(fn->kids[i]->slot) + ", " + kArgRegs[i]);
        }

        out_->append(body.data(), body.size());

        // The epilogue. A return anywhere in the body jumps here.
        line_label(label_name(epilogue_label_));

        if (is_main_) {
            // main is the entry point, so it has to hand the value to
            // ExitProcess rather than return it.
            uses_exit_ = true;
            emit(rawrstd::String("mov ecx, eax"));
            emit(rawrstd::String("sub rsp, 32"));
            emit(rawrstd::String("call ExitProcess"));
            emit(rawrstd::String("add rsp, 32"));
            emit(rawrstd::String("ret"));
        } else {
            emit(rawrstd::String("leave"));
            emit(rawrstd::String("ret"));
        }
        line("");
    }

    // ---- statements ----
    void emit_statement(CNode* stmt) {
        if (!stmt) return;
        switch (stmt->kind) {
        case CKind::Return: {
            emit_expression(stmt->a);
            // A return has to LEAVE the function, not fall through to
            // whatever follows it. The value is in rax and the epilogue does
            // the rest.
            emit(rawrstd::String("jmp ") + label_name(epilogue_label_).data());
            break;
        }
        case CKind::Decl: {
            if (stmt->a) {
                emit_expression(stmt->a);
                emit(rawrstd::String("mov ") + slot_ref(stmt->slot) + ", rax");
            }
            break;
        }
        case CKind::Assign: {
            emit_expression(stmt->b);
            const int slot = find_local(stmt->a);
            if (slot >= 0) {
                emit(rawrstd::String("mov ") + slot_ref(slot) + ", rax");
            }
            break;
        }
        case CKind::ExprStmt:
            emit_expression(stmt->a);
            break;
        case CKind::If: {
            const int else_label = new_label();
            const int end_label = new_label();
            emit_condition(stmt->a, else_label, false);
            emit_statement(stmt->b);
            if (stmt->c) {
                emit(rawrstd::String("jmp ") + label_name(end_label).data());
            }
            line_label(label_name(else_label));
            if (stmt->c) {
                emit_statement(stmt->c);
                line_label(label_name(end_label));
            }
            break;
        }
        case CKind::While: {
            const int top_label = new_label();
            const int end_label = new_label();
            line_label(label_name(top_label));
            emit_condition(stmt->a, end_label, false);
            emit_statement(stmt->b);
            emit(rawrstd::String("jmp ") + label_name(top_label).data());
            line_label(label_name(end_label));
            break;
        }
        case CKind::Block:
            for (CNode* s : stmt->kids) emit_statement(s);
            break;
        default:
            break;
        }
    }

    // A condition becomes a compare and a jump.
    void emit_condition(CNode* expr, int target, bool jump_if_true) {
        emit_expression(expr);
        emit(rawrstd::String("cmp rax, 0"));
        emit(rawrstd::String(jump_if_true ? "jne " : "je ") + label_name(target).data());
    }

    // ---- expressions ----
    // Every expression leaves its value in rax.
    void emit_expression(CNode* expr) {
        if (!expr) return;
        switch (expr->kind) {
        case CKind::Number:
            emit(rawrstd::String("mov rax, ") + num(static_cast<int>(expr->value)));
            break;
        case CKind::Ident: {
            const int slot = find_local(expr);
            if (slot >= 0) {
                emit(rawrstd::String("mov rax, ") + slot_ref(slot));
            } else {
                emit(rawrstd::String("mov rax, 0"));
            }
            break;
        }
        case CKind::Unary: {
            emit_expression(expr->a);
            if (expr->text == "-") {
                emit(rawrstd::String("neg rax"));
            } else {
                // !x is 1 when x is zero.
                const int end_label = new_label();
                emit(rawrstd::String("cmp rax, 0"));
                emit(rawrstd::String("mov rax, 0"));
                emit(rawrstd::String("je ") + label_name(end_label).data());
                emit(rawrstd::String("mov rax, 1"));
                line_label(label_name(end_label));
            }
            break;
        }
        case CKind::Assign: {
            emit_expression(expr->b);
            const int slot = find_local(expr->a);
            if (slot >= 0) {
                emit(rawrstd::String("mov ") + slot_ref(slot) + ", rax");
            }
            break;
        }
        case CKind::Call:
            emit_call(expr);
            break;
        case CKind::Binary:
            emit_binary(expr);
            break;
        default:
            break;
        }
    }

    // A binary operation keeps the left operand in a frame slot, so that the
    // stack pointer never moves.
    void emit_binary(CNode* expr) {
        const rawrstd::String op = expr->text;

        if (op == "&&" || op == "||") {
            const int short_label = new_label();
            const int end_label = new_label();
            emit_expression(expr->a);
            emit(rawrstd::String("cmp rax, 0"));
            if (op == "&&") {
                emit(rawrstd::String("je ") + label_name(short_label).data());
            } else {
                emit(rawrstd::String("jne ") + label_name(short_label).data());
            }
            emit_expression(expr->b);
            emit(rawrstd::String("cmp rax, 0"));
            if (op == "&&") {
                emit(rawrstd::String("je ") + label_name(short_label).data());
                emit(rawrstd::String("mov rax, 1"));
            } else {
                emit(rawrstd::String("jne ") + label_name(short_label).data());
                emit(rawrstd::String("mov rax, 0"));
            }
            emit(rawrstd::String("jmp ") + label_name(end_label).data());
            line_label(label_name(short_label));
            if (op == "&&") {
                emit(rawrstd::String("mov rax, 0"));
            } else {
                emit(rawrstd::String("mov rax, 1"));
            }
            line_label(label_name(end_label));
            return;
        }

        const int saved = temp_top_++;
        if (temp_top_ > max_temp_) max_temp_ = temp_top_;

        emit_expression(expr->a);
        emit(rawrstd::String("mov ") + slot_ref(saved) + ", rax");
        emit_expression(expr->b);
        emit(rawrstd::String("mov rbx, rax"));
        emit(rawrstd::String("mov rax, ") + slot_ref(saved));
        temp_top_ = saved;

        if (op == "+")        emit(rawrstd::String("add rax, rbx"));
        else if (op == "-")   emit(rawrstd::String("sub rax, rbx"));
        else if (op == "*")   emit(rawrstd::String("imul rbx"));
        else if (op == "/")   { emit(rawrstd::String("cqo")); emit(rawrstd::String("idiv rbx")); }
        else if (op == "%")   { emit(rawrstd::String("cqo")); emit(rawrstd::String("idiv rbx")); }
        else if (op == "&")   emit(rawrstd::String("and rax, rbx"));
        else if (op == "|")   emit(rawrstd::String("or rax, rbx"));
        else if (op == "^")   emit(rawrstd::String("xor rax, rbx"));
        else if (op == "==" || op == "!=" || op == "<" || op == ">" ||
                 op == "<=" || op == ">=") {
            emit_comparison_value(op);
        }
    }

    // A comparison used as a value.
    //
    // The assembler has no setcc, so the result is produced with a branch:
    // the comparison sets the flags, and the branch decides the value.
    //
    // The branch has to SKIP the "true" assignment when the comparison is
    // false, so it is the INVERSE of the comparison that is used. Using the
    // comparison itself inverted the result: a true comparison produced zero
    // and a false one produced one.
    void emit_comparison_value(const rawrstd::String& op) {
        const int false_label = new_label();
        emit(rawrstd::String("cmp rax, rbx"));
        emit(rawrstd::String("mov rax, 0"));
        emit(rawrstd::String(invert_condition(op)) + " " + label_name(false_label).data());
        emit(rawrstd::String("mov rax, 1"));
        line_label(label_name(false_label));
    }

    // The inverse of a comparison, for the branch that skips the true path.
    const char* invert_condition(const rawrstd::String& op) {
        if (op == "==") return "jne";
        if (op == "!=") return "je";
        if (op == "<")  return "jge";
        if (op == ">")  return "jle";
        if (op == "<=") return "jg";
        if (op == ">=") return "jl";
        return "je";
    }

    // A call: the arguments are evaluated into frame slots and then moved into
    // the argument registers.
    void emit_call(CNode* call) {
        const size_t count = call->kids.size();
        if (count > 4) {
            // The Win64 integer argument registers are four; more than that
            // belongs on the stack, which this subset does not implement.
            emit(rawrstd::String("mov rax, 0"));
            return;
        }
        rawrstd::Vector<int> slots;
        for (size_t i = 0; i < count; ++i) {
            const int slot = temp_top_++;
            if (temp_top_ > max_temp_) max_temp_ = temp_top_;
            slots.push_back(slot);
            emit_expression(call->kids[i]);
            emit(rawrstd::String("mov ") + slot_ref(slot) + ", rax");
        }
        static const char* kArgRegs[4] = {"rcx", "rdx", "r8", "r9"};
        for (size_t i = 0; i < count; ++i) {
            emit(rawrstd::String("mov ") + kArgRegs[i] + ", " + slot_ref(slots[i]));
        }
        for (size_t i = 0; i < count; ++i) {
            temp_top_ = slots[i];
        }
        externals_.push_back(call->text);
        emit(rawrstd::String("call ") + call->text.data());
    }

    // The declarations in a function, in order, each given a frame slot.
    void collect_locals(CNode* node) {
        if (!node) return;
        if (node->kind == CKind::Decl) {
            node->slot = local_count_++;
            locals_.push_back(node);
        }
        for (CNode* kid : node->kids) collect_locals(kid);
        collect_locals(node->a);
        collect_locals(node->b);
        collect_locals(node->c);
    }

    // Locals are found by name in the function being generated.
    int find_local(CNode* node) {
        if (!node) return -1;
        if (node->kind == CKind::Ident) {
            for (CNode* candidate : locals_) {
                if (candidate->text == node->text) return candidate->slot;
            }
        }
        return -1;
    }

    rawrstd::Vector<CNode*> locals_;
    rawrstd::Vector<rawrstd::String> defined_;
    rawrstd::Vector<rawrstd::String> externals_;
};

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------
bool c_compile_to_asm(const char* source_path, const char* asm_path,
                       rawrstd::String* error) {
    if (!source_path || !asm_path || !error) return false;
    error->clear();

    // Read the source.
    rawrstd::String source;
    {
        rawrstd::File in;
        if (!in.open(source_path, rawrstd::FileMode::Read)) {
            *error = rawrstd::String("cannot open ") + rawrstd::String(source_path);
            return false;
        }
        char buffer[8192];
        for (;;) {
            const int64 got = in.read(buffer, sizeof(buffer));
            if (got <= 0) break;
            source.append(buffer, static_cast<size_type>(got));
        }
        in.close();
    }

    // The certified lexer.
    SourceManager sources;
    DiagnosticEngine diags(&sources);
    const uint32 file_id = sources.add_buffer(source_path, source.data(), source.size());
    Lexer lexer(&sources, &diags, file_id);

    CParser parser(&lexer, error);
    CNode* program = parser.parse_program();
    if (!program) {
        if (error->empty()) *error = rawrstd::String("the source could not be parsed");
        return false;
    }

    rawrstd::String assembly;
    CCodeGen gen(&assembly);
    gen.generate(program);

    rawrstd::File out;
    if (!out.open(asm_path, rawrstd::FileMode::Write)) {
        *error = rawrstd::String("cannot write ") + rawrstd::String(asm_path);
        return false;
    }
    out.write(assembly.data(), assembly.size());
    out.close();
    return true;
}
} // namespace rawr








