#pragma once

// ChatTemplate.hpp - minimal Jinja2-subset renderer for GGUF
// chat templates (RAWRXD_MODELGENIE_NATIVE_CHAT_001).
//
// Supports the constructs used by GGUF tokenizer.chat_template
// metadata (DeepSeek / Llama / Mistral style):
//   {% if <cond> %} ... {% elif <cond> %} ... {% else %} ... {% endif %}
//   {% for <var> in messages %} ... {% endfor %}
//   {% set <var> = <expr> %}
//   {{ <expr> }}
//
// Expressions: string literals ('...' with \n \t \r \' \\ escapes),
// identifiers, message['role'] / message['content'] subscripts,
// '+' concatenation, 'not', '<var> is defined', '==' comparison.
//
// Any construct outside this subset makes rendering fail (returns
// false) so the caller can fall back explicitly instead of
// silently mangling the prompt. Header-only; the template set is
// small and the DLL has no other use for a separate TU.

#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace RawrXD {

struct ChatMessage {
    std::string role;
    std::string content;
};

struct ChatTemplateVars {
    // String forms of the control tokens; the template refers to
    // them as {{ bos_token }} / {{ eos_token }}.
    std::string bosToken;
    std::string eosToken;
    // Append the assistant generation prefix ({{ 'Assistant:' }}).
    bool addGenerationPrompt = true;
    std::vector<ChatMessage> messages;
};

namespace chat_template_detail {

struct Value {
    enum class Kind { String, Bool, Message };
    Kind kind = Kind::String;
    std::string text;
    bool boolean = false;
    const ChatMessage* message = nullptr;

    static Value Str(std::string s) {
        Value v;
        v.kind = Kind::String;
        v.text = std::move(s);
        return v;
    }
    static Value Bool(bool b) {
        Value v;
        v.kind = Kind::Bool;
        v.boolean = b;
        return v;
    }
    static Value Msg(const ChatMessage* m) {
        Value v;
        v.kind = Kind::Message;
        v.message = m;
        return v;
    }
    bool truthy() const {
        switch (kind) {
        case Kind::Bool: return boolean;
        case Kind::String: return !text.empty();
        case Kind::Message: return message != nullptr;
        }
        return false;
    }
};

using Scope = std::map<std::string, Value>;

inline std::string trim(std::string_view s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return std::string(s.substr(first, last - first + 1));
}

inline bool startsWith(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

// Recursive-descent expression evaluator over the Jinja subset.
class ExprEval {
public:
    ExprEval(const std::string& expr, const Scope& scope)
        : src_(expr), scope_(scope) {}

    bool eval(Value& out) {
        if (!parseConcat(out)) return false;
        skipWs();
        return pos_ == src_.size();
    }

private:
    void skipWs() {
        while (pos_ < src_.size() &&
               (src_[pos_] == ' ' || src_[pos_] == '\t'))
            ++pos_;
    }
    char peek() const { return pos_ < src_.size() ? src_[pos_] : '\0'; }
    bool startsWithAt(const char* lit) const {
        const size_t n = std::char_traits<char>::length(lit);
        return src_.compare(pos_, n, lit) == 0;
    }

    // concat := unary ('+' unary)*
    bool parseConcat(Value& out) {
        if (!parseUnary(out)) return false;
        while (true) {
            skipWs();
            if (peek() != '+') break;
            ++pos_;
            Value rhs;
            if (!parseUnary(rhs)) return false;
            if (out.kind != Value::Kind::String ||
                rhs.kind != Value::Kind::String)
                return false;  // concatenation is defined for strings only
            out.text += rhs.text;
        }
        return true;
    }

    // unary := 'not' unary | postfix
    bool parseUnary(Value& out) {
        skipWs();
        if (startsWithAt("not")) {
            // 'not' must be followed by whitespace or end-of-word
            const char after = pos_ + 3 < src_.size() ? src_[pos_ + 3] : '\0';
            if (after == ' ' || after == '\t' || after == '\0') {
                pos_ += 3;
                Value v;
                if (!parseUnary(v)) return false;
                out = Value::Bool(!v.truthy());
                return true;
            }
        }
        return parsePostfix(out);
    }

    // postfix := ['<ident>' 'is' ['not'] 'defined'] |
    //            primary ['==' primary]
    bool parsePostfix(Value& out) {
        // Try '<ident> is (not) defined' first: the defined-test
        // needs the identifier name, not its value.
        const size_t save = pos_;
        skipWs();
        std::string ident;
        if (parseIdentifier(ident)) {
            skipWs();
            if (startsWithAt("is")) {
                const size_t save2 = pos_;
                pos_ += 2;
                skipWs();
                if (startsWithAt("not")) {
                    pos_ += 3;
                    skipWs();
                }
                if (startsWithAt("defined")) {
                    pos_ += 7;
                    out = Value::Bool(scope_.count(ident) != 0);
                    return true;
                }
                pos_ = save2;
            }
        }
        pos_ = save;

        if (!parsePrimary(out)) return false;
        skipWs();
        if (startsWithAt("==")) {
            pos_ += 2;
            Value rhs;
            if (!parsePrimary(rhs)) return false;
            if (out.kind == Value::Kind::String &&
                rhs.kind == Value::Kind::String) {
                out = Value::Bool(out.text == rhs.text);
            } else if (out.kind == Value::Kind::Bool &&
                       rhs.kind == Value::Kind::Bool) {
                out = Value::Bool(out.boolean == rhs.boolean);
            } else {
                return false;
            }
        }
        return true;
    }

    // primary := string | '(' concat ')' | ident | ident '[' string ']'
    bool parsePrimary(Value& out) {
        skipWs();
        if (peek() == '\'') return parseStringLiteral(out);
        if (peek() == '(') {
            ++pos_;
            if (!parseConcat(out)) return false;
            skipWs();
            if (peek() != ')') return false;
            ++pos_;
            return true;
        }
        std::string ident;
        if (!parseIdentifier(ident)) return false;
        skipWs();
        if (peek() == '[') {
            ++pos_;
            skipWs();
            Value key;
            if (!parseStringLiteral(key)) return false;
            skipWs();
            if (peek() != ']') return false;
            ++pos_;
            auto it = scope_.find(ident);
            if (it == scope_.end() || it->second.kind != Value::Kind::Message)
                return false;
            if (key.text == "role")
                out = Value::Str(it->second.message->role);
            else if (key.text == "content")
                out = Value::Str(it->second.message->content);
            else
                return false;
            return true;
        }
        auto it = scope_.find(ident);
        if (it == scope_.end()) return false;
        out = it->second;
        return true;
    }

    bool parseStringLiteral(Value& out) {
        if (peek() != '\'') return false;
        ++pos_;
        std::string s;
        while (pos_ < src_.size() && src_[pos_] != '\'') {
            const char c = src_[pos_++];
            if (c == '\\' && pos_ < src_.size()) {
                const char e = src_[pos_++];
                switch (e) {
                case 'n': s.push_back('\n'); break;
                case 't': s.push_back('\t'); break;
                case 'r': s.push_back('\r'); break;
                case '\'': s.push_back('\''); break;
                case '\\': s.push_back('\\'); break;
                default: s.push_back('\\'); s.push_back(e); break;
                }
            } else {
                s.push_back(c);
            }
        }
        if (pos_ >= src_.size()) return false;  // unterminated literal
        ++pos_;  // closing quote
        out = Value::Str(std::move(s));
        return true;
    }

    bool parseIdentifier(std::string& out) {
        skipWs();
        const size_t start = pos_;
        if (pos_ < src_.size() &&
            (src_[pos_] == '_' ||
             (src_[pos_] >= 'a' && src_[pos_] <= 'z') ||
             (src_[pos_] >= 'A' && src_[pos_] <= 'Z'))) {
            ++pos_;
        } else {
            return false;
        }
        while (pos_ < src_.size() &&
               (src_[pos_] == '_' ||
                (src_[pos_] >= 'a' && src_[pos_] <= 'z') ||
                (src_[pos_] >= 'A' && src_[pos_] <= 'Z') ||
                (src_[pos_] >= '0' && src_[pos_] <= '9'))) {
            ++pos_;
        }
        out = src_.substr(start, pos_ - start);
        return true;
    }

    const std::string& src_;
    size_t pos_ = 0;
    const Scope& scope_;
};

// Template renderer. Owns the root scope (the control-token
// string forms and the generation-prompt flag) and the
// variable bag the for-loop iterates.
class Renderer {
public:
    // AST node for the template.
    struct Node {
        enum class Kind { Text, Emit, If, For, Set };
        Kind kind = Kind::Text;
        // Text / Emit / Set
        std::string text;
        std::string expr;
        // If
        std::string cond;
        std::vector<Node> thenNodes;
        std::vector<std::pair<std::string, std::vector<Node>>> elifs;
        std::vector<Node> elseNodes;
        // For
        std::string varName;
        std::vector<Node> body;
    };

    // Lexeme: raw text, {{ expr }} or {% tag %}.
    enum class TokKind { Text, Expr, Tag };
    struct Tok {
        TokKind kind = TokKind::Text;
        std::string text;
    };

    explicit Renderer(const ChatTemplateVars& vars) : vars_(vars) {
        root_["bos_token"] = Value::Str(vars.bosToken);
        root_["eos_token"] = Value::Str(vars.eosToken);
        root_["add_generation_prompt"] = Value::Bool(vars.addGenerationPrompt);
    }

    bool render(std::string_view tmpl, std::string& out);
    bool lex(std::string_view tmpl, std::vector<Tok>& toks);
    bool parseNodes(const std::vector<Tok>& toks, size_t& pos,
                    const std::vector<std::string>& endMarkers,
                    std::vector<Node>& nodes);
    bool evalNodes(const std::vector<Node>& nodes, Scope& scope,
                   std::string& out);

    Scope root_;
    const ChatTemplateVars& vars_;
};

inline bool Renderer::render(std::string_view tmpl, std::string& out) {
    std::vector<Tok> toks;
    if (!lex(tmpl, toks)) return false;
    size_t pos = 0;
    std::vector<Node> nodes;
    if (!parseNodes(toks, pos, {}, nodes)) return false;
    if (pos != toks.size()) return false;  // stray end marker
    Scope scope = root_;
    return evalNodes(nodes, scope, out);
}

inline bool Renderer::lex(std::string_view tmpl, std::vector<Tok>& toks) {
    size_t i = 0;
    while (i < tmpl.size()) {
        size_t open = std::string_view::npos;
        bool isExpr = false;
        for (size_t j = i; j + 1 < tmpl.size(); ++j) {
            if (tmpl[j] != '{') continue;
            if (tmpl[j + 1] == '{') { open = j; isExpr = true; break; }
            if (tmpl[j + 1] == '%') { open = j; isExpr = false; break; }
        }
        if (open == std::string_view::npos) {
            toks.push_back({TokKind::Text, std::string(tmpl.substr(i))});
            break;
        }
        if (open > i)
            toks.push_back({TokKind::Text, std::string(tmpl.substr(i, open - i))});
        const std::string_view close = isExpr ? "}}" : "%}";
        const size_t end = tmpl.find(close, open + 2);
        if (end == std::string_view::npos) return false;  // unterminated
        toks.push_back({isExpr ? TokKind::Expr : TokKind::Tag,
                        std::string(tmpl.substr(open + 2, end - open - 2))});
        i = end + 2;
    }
    return true;
}

inline bool Renderer::parseNodes(const std::vector<Tok>& toks, size_t& pos,
                                 const std::vector<std::string>& endMarkers,
                                 std::vector<Node>& nodes) {
    while (pos < toks.size()) {
        const Tok& t = toks[pos];
        if (t.kind == TokKind::Text) {
            Node n;
            n.kind = Node::Kind::Text;
            n.text = t.text;
            nodes.push_back(std::move(n));
            ++pos;
            continue;
        }
        if (t.kind == TokKind::Expr) {
            Node n;
            n.kind = Node::Kind::Emit;
            n.expr = trim(t.text);
            nodes.push_back(std::move(n));
            ++pos;
            continue;
        }
        // Tag: end marker or block start.
        const std::string tag = trim(t.text);
        for (const auto& m : endMarkers) {
            if (tag == m || startsWith(tag, m + " ")) return true;
        }
        if (startsWith(tag, "if ")) {
            Node n;
            n.kind = Node::Kind::If;
            n.cond = trim(tag.substr(3));
            ++pos;
            if (!parseNodes(toks, pos, {"elif", "else", "endif"}, n.thenNodes))
                return false;
            while (pos < toks.size()) {
                const std::string marker = trim(toks[pos].text);
                if (marker == "endif") { ++pos; break; }
                if (startsWith(marker, "elif ")) {
                    ++pos;
                    std::vector<Node> body;
                    if (!parseNodes(toks, pos, {"elif", "else", "endif"}, body))
                        return false;
                    n.elifs.emplace_back(trim(marker.substr(5)), std::move(body));
                    continue;
                }
                if (marker == "else") {
                    ++pos;
                    if (!parseNodes(toks, pos, {"endif"}, n.elseNodes))
                        return false;
                    continue;
                }
                return false;  // unexpected marker
            }
            nodes.push_back(std::move(n));
            continue;
        }
        if (startsWith(tag, "for ")) {
            // "for <var> in messages" - messages is the only
            // supported iterable.
            const auto inPos = tag.find(" in ");
            if (inPos == std::string::npos) return false;
            Node n;
            n.kind = Node::Kind::For;
            n.varName = trim(tag.substr(4, inPos - 4));
            const std::string listName = trim(tag.substr(inPos + 4));
            if (listName != "messages") return false;
            ++pos;
            if (!parseNodes(toks, pos, {"endfor"}, n.body)) return false;
            if (pos >= toks.size() || trim(toks[pos].text) != "endfor")
                return false;
            ++pos;
            nodes.push_back(std::move(n));
            continue;
        }
        if (startsWith(tag, "set ")) {
            // "set <var> = <expr>"
            const auto eq = tag.find('=');
            if (eq == std::string::npos) return false;
            Node n;
            n.kind = Node::Kind::Set;
            n.varName = trim(tag.substr(4, eq - 4));
            n.expr = trim(tag.substr(eq + 1));
            ++pos;
            nodes.push_back(std::move(n));
            continue;
        }
        return false;  // unsupported tag
    }
    return true;
}

inline bool Renderer::evalNodes(const std::vector<Node>& nodes, Scope& scope,
                                std::string& out) {
    for (const Node& n : nodes) {
        switch (n.kind) {
        case Node::Kind::Text:
            out += n.text;
            break;
        case Node::Kind::Emit: {
            ExprEval ev(n.expr, scope);
            Value v;
            if (!ev.eval(v)) return false;
            if (v.kind == Value::Kind::String) {
                out += v.text;
            } else if (v.kind == Value::Kind::Bool) {
                out += (v.boolean ? "true" : "false");
            } else {
                return false;
            }
            break;
        }
        case Node::Kind::If: {
            ExprEval ev(n.cond, scope);
            Value cond;
            if (!ev.eval(cond)) return false;
            if (cond.truthy()) {
                if (!evalNodes(n.thenNodes, scope, out)) return false;
                break;
            }
            bool matched = false;
            for (const auto& [elifCond, body] : n.elifs) {
                ExprEval ev2(elifCond, scope);
                Value c2;
                if (!ev2.eval(c2)) return false;
                if (c2.truthy()) {
                    if (!evalNodes(body, scope, out)) return false;
                    matched = true;
                    break;
                }
            }
            if (!matched && !n.elseNodes.empty()) {
                if (!evalNodes(n.elseNodes, scope, out)) return false;
            }
            break;
        }
        case Node::Kind::For: {
            for (const ChatMessage& msg : vars_.messages) {
                Scope child = scope;
                child[n.varName] = Value::Msg(&msg);
                if (!evalNodes(n.body, child, out)) return false;
            }
            break;
        }
        case Node::Kind::Set: {
            ExprEval ev(n.expr, scope);
            Value v;
            if (!ev.eval(v)) return false;
            scope[n.varName] = v;
            break;
        }
        }
    }
    return true;
}

} // namespace chat_template_detail

inline bool RenderChatTemplate(std::string_view tmpl,
                               const ChatTemplateVars& vars,
                               std::string& out) {
    chat_template_detail::Renderer renderer(vars);
    return renderer.render(tmpl, out);
}

} // namespace RawrXD
