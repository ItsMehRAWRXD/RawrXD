// C++20 preprocessor for the RawrXD native compiler.
//
// Turns source text into the token stream the parser consumes: includes are
// resolved, macros are expanded, and conditional regions are selected.
//
// Supported directives:
//   #include "file"      #include <file>      #include MACRO
//   #define              #undef
//   #if  #ifdef  #ifndef  #elif  #else  #endif
//   #error  #warning  #line  #pragma
//
// Supported macro features:
//   object-like and function-like macros, variadic macros, the # operator
//   and the ## operator, and the predefined macros __FILE__, __LINE__,
//   __DATE__, __TIME__, __COUNTER__ and __INCLUDE_LEVEL__.
//
// The macro expansion follows the model in the C++ standard: a macro is
// replaced by its replacement list, the result is rescanned, and a macro is
// not replaced again while its own replacement is being rescanned. That last
// rule is what stops a self referential macro from looping forever.

#ifndef RAWR_COMPILER_PREPROCESSOR_H
#define RAWR_COMPILER_PREPROCESSOR_H

#include "common/Diagnostics.h"
#include "common/SourceManager.h"
#include "frontend/Token.h"
#include "rawrstd/map.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

namespace rawr {

// One macro definition.
struct Macro {
    String name;
    bool function_like = false;
    Vector<String> parameters;
    bool variadic = false;
    Vector<Token> replacement;
    SourceLoc loc;
    bool builtin = false;       // __FILE__ and friends
    bool expanding = false;     // set while the replacement is being rescanned
};

// A token plus the flags the preprocessor needs.
struct PPToken {
    Token token;
    bool at_line_start = false;
    bool space_before = false;
    bool from_expansion = false;   // produced by a macro, not by the file
    bool no_expand = false;        // a macro name that is not an invocation
};

class Preprocessor {
public:
    Preprocessor(SourceManager* sources, DiagnosticEngine* diags);

    // Adds a directory to the <...> include search path.
    void add_include_dir(const char* dir);

    // Defines a macro from the command line, as in -DNAME=value.
    void define(const char* name, const char* value);

    // Removes a macro.
    void undefine(const char* name);

    // Preprocesses a file. Returns false when an error was reported.
    bool run(uint32 file_id, Vector<Token>* out);

    const Vector<Token>& tokens() const { return tokens_; }
    uint32 macro_count() const { return static_cast<uint32>(macros_.size()); }
    uint32 include_count() const { return include_count_; }

private:
    // A stack of token sequences being read. The frames are the macro
    // expansions; the file itself is read from file_tokens_.
    struct Frame {
        Vector<PPToken> tokens;
        size_type pos = 0;
        String expanding_macro;   // cleared when the frame is popped
    };

    // The three ways a conditional region can be opened.
    enum class ConditionalKind {
        Expression,     // #if, with a constant expression
        NameDefined,    // #ifdef
        NameNotDefined, // #ifndef
    };

    // The state of one conditional region.
    struct Conditional {
        bool parent_active = false;
        bool taken = false;        // some branch has already been taken
        bool active = false;       // this branch is active
        bool seen_else = false;
        SourceLoc loc;
    };

    // ---- token stream ----
    bool next_raw(PPToken* out);
    void push_token(const PPToken& token);
    void push_expansion(const Vector<PPToken>& tokens, const String& macro_name);
    void pop_frame();
    bool region_active() const;

    // ---- file handling ----
    bool load_file_tokens(uint32 file_id, Vector<PPToken>* out);
    void process_current_file();
    bool process_include(uint32 file_id);

    // ---- directives ----
    void handle_directive();
    void handle_include(const SourceLoc& loc, Vector<PPToken>& line);
    void handle_define(const SourceLoc& loc, Vector<PPToken>& line);
    void handle_undef(const SourceLoc& loc, Vector<PPToken>& line);
    void handle_if(const SourceLoc& loc, ConditionalKind kind, Vector<PPToken>& line);
    void handle_elif(const SourceLoc& loc, Vector<PPToken>& line);
    void handle_else(const SourceLoc& loc, Vector<PPToken>& line);
    void handle_endif(const SourceLoc& loc, Vector<PPToken>& line);
    void handle_error(const SourceLoc& loc, bool is_error, Vector<PPToken>& line);

    // Reads the rest of the current logical line.
    void read_line(Vector<PPToken>* out);

    // ---- macro expansion ----
    bool expand_macro(const PPToken& token);
    bool collect_arguments(const Macro& macro, Vector<Vector<PPToken>>* out);
    void substitute(const Macro& macro, const Vector<Vector<PPToken>>& arguments,
                    Vector<PPToken>* out);
    void expand_list(const Vector<PPToken>& in, Vector<PPToken>* out);
    int parameter_index(const Macro& macro, const String& name) const;

    // Builds the string literal for the # operator.
    Token stringify(const Vector<PPToken>& tokens);
    // Pastes two tokens together and re-lexes the result.
    bool paste(const PPToken& left, const PPToken& right, PPToken* out);

    // ---- conditional expressions ----
    bool evaluate_expression(Vector<PPToken> tokens, int64* out);
    bool eval_conditional(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_logical_or(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_logical_and(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_inclusive_or(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_exclusive_or(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_and_expr(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_equality(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_relational(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_shift(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_additive(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_multiplicative(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_unary(Vector<PPToken>& t, size_type& pos, int64* out);
    bool eval_primary(Vector<PPToken>& t, size_type& pos, int64* out);

    SourceManager* sources_ = nullptr;
    DiagnosticEngine* diags_ = nullptr;

    rawrstd::StringMap<Macro> macros_;
    Vector<Frame> frames_;
    Vector<PPToken> pushback_;
    Vector<Conditional> conditionals_;
    Vector<Token> tokens_;

    // The file currently being processed and the position in it.
    Vector<PPToken> file_tokens_;
    size_type file_pos_ = 0;

    uint32 include_count_ = 0;
    uint32 include_depth_ = 0;
    uint32 counter_ = 0;
    uint32 paste_counter_ = 0;
    bool failed_ = false;
    bool isolated_ = false;   // true while a token list is expanded on its own
};

} // namespace rawr

#endif // RAWR_COMPILER_PREPROCESSOR_H
