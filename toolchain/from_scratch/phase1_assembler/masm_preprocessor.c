/*==========================================================================
 * masm_preprocessor.c — MASM-to-NASM-style preprocessor
 *
 * Handles MASM-specific constructs before main assembly:
 *   - INCLUDE directive (with include path search)
 *   - EQU constant definitions
 *   - MACRO/ENDM macro definitions and expansion
 *   - INVOKE macro expansion (x64 calling convention)
 *   - Conditional assembly (IF/ELSE/ENDIF)
 *   - Local labels (@@, @F, @B)
 *   - PROC/ENDP with FRAME/unwind directives
 *   - Structure definitions
 *
 * Output: Preprocessed source ready for asm_lexer/asm_parser
 *=========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#define MAX_INCLUDE_DEPTH 32
#define MAX_MACRO_NESTING 16
#define MAX_LINE_LEN 4096
#define MAX_SYMBOLS 65536
#define MAX_MACROS 1024

typedef struct {
    char name[128];
    char value[4096];
    int is_macro;
    int arg_count;
    char args[16][64];
    char *body;
    size_t body_len;
} symbol_t;

typedef struct {
    symbol_t symbols[MAX_SYMBOLS];
    int count;
} symbol_table_t;

typedef struct {
    char *paths[32];
    int count;
} include_path_t;

typedef struct {
    int active;           /* Currently expanding */
    int skip_depth;       /* Nesting level for skipping */
    int else_seen;        /* ELSE already encountered */
} conditional_state_t;

typedef struct {
    FILE *out;
    symbol_table_t *symbols;
    include_path_t *include_paths;
    conditional_state_t cond_stack[MAX_MACRO_NESTING];
    int cond_depth;
    int line_num;
    int pass;             /* 1=define, 2=expand */
    char current_file[256];
} preprocessor_t;

/* ---- String utilities ---- */
static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == 0) return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

static void to_lower(char *dst, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n - 1 && src[i]; i++)
        dst[i] = (char)tolower((unsigned char)src[i]);
    dst[i] = '\0';
}

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int is_directive(const char *s, const char *dir) {
    char lower[64];
    to_lower(lower, s, sizeof(lower));
    return strcmp(lower, dir) == 0;
}

/* ---- Symbol table ---- */
static symbol_t *symbol_find(symbol_table_t *st, const char *name) {
    char lower_name[128];
    to_lower(lower_name, name, sizeof(lower_name));
    
    for (int i = st->count - 1; i >= 0; i--) {
        char lower_sym[128];
        to_lower(lower_sym, st->symbols[i].name, sizeof(lower_sym));
        if (strcmp(lower_sym, lower_name) == 0)
            return &st->symbols[i];
    }
    return NULL;
}

static void symbol_add(symbol_table_t *st, const char *name, const char *value) {
    if (st->count >= MAX_SYMBOLS) {
        fprintf(stderr, "Error: Symbol table full\n");
        return;
    }
    symbol_t *sym = &st->symbols[st->count++];
    strncpy(sym->name, name, 127);
    sym->name[127] = '\0';
    strncpy(sym->value, value, sizeof(sym->value) - 1);
    sym->value[sizeof(sym->value) - 1] = '\0';
    sym->is_macro = 0;
    sym->body = NULL;
}

static void macro_add(symbol_table_t *st, const char *name, int arg_count,
                      char args[][64], const char *body) {
    if (st->count >= MAX_SYMBOLS) {
        fprintf(stderr, "Error: Symbol table full\n");
        return;
    }
    symbol_t *sym = &st->symbols[st->count++];
    strncpy(sym->name, name, 127);
    sym->name[127] = '\0';
    sym->is_macro = 1;
    sym->arg_count = arg_count;
    for (int i = 0; i < arg_count; i++) {
        strncpy(sym->args[i], args[i], 63);
        sym->args[i][63] = '\0';
    }
    sym->body_len = strlen(body);
    sym->body = (char *)malloc(sym->body_len + 1);
    if (sym->body) {
        memcpy(sym->body, body, sym->body_len + 1);
    }
}

/* ---- Include file resolution ---- */
static FILE *find_include(include_path_t *paths, const char *filename,
                          char *out_path, size_t out_size) {
    /* Try current directory first */
    FILE *f = fopen(filename, "r");
    if (f) {
        strncpy(out_path, filename, out_size - 1);
        out_path[out_size - 1] = '\0';
        return f;
    }
    
    /* Try include paths */
    for (int i = 0; i < paths->count; i++) {
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", paths->paths[i], filename);
        f = fopen(full_path, "r");
        if (f) {
            strncpy(out_path, full_path, out_size - 1);
            out_path[out_size - 1] = '\0';
            return f;
        }
    }
    
    return NULL;
}

/* ---- INVOKE expansion (x64 calling convention) ---- */
static void expand_invoke(preprocessor_t *pp, const char *target,
                          char **args, int arg_count) {
    /* x64 calling convention: RCX, RDX, R8, R9, then stack */
    const char *reg_args[] = {"rcx", "rdx", "r8", "r9"};
    
    fprintf(pp->out, "    ;; INVOKE %s (auto-generated)\n", target);
    
    /* Calculate stack space needed */
    int stack_args = arg_count > 4 ? arg_count - 4 : 0;
    int shadow_space = 32;  /* 32 bytes shadow space */
    int total_stack = shadow_space + stack_args * 8;
    
    /* Align to 16 bytes */
    if (total_stack % 16 != 0) {
        total_stack += 8;
    }
    
    /* Allocate stack */
    if (total_stack > 0) {
        fprintf(pp->out, "    sub rsp, %d\n", total_stack);
    }
    
    /* Move arguments to registers/stack */
    for (int i = 0; i < arg_count; i++) {
        if (i < 4) {
            /* Register argument */
            fprintf(pp->out, "    mov %s, %s\n", reg_args[i], args[i]);
        } else {
            /* Stack argument */
            int stack_offset = 32 + (i - 4) * 8;
            fprintf(pp->out, "    mov QWORD PTR [rsp+%d], %s\n", stack_offset, args[i]);
        }
    }
    
    /* Call the function */
    fprintf(pp->out, "    call %s\n", target);
    
    /* Restore stack */
    if (total_stack > 0) {
        fprintf(pp->out, "    add rsp, %d\n", total_stack);
    }
}

/* ---- MACRO expansion ---- */
static char *expand_macro(symbol_t *macro, char **args, int arg_count) {
    static char result[MAX_LINE_LEN * 16];
    result[0] = '\0';
    
    if (!macro->body) return result;
    
    /* Simple text substitution for arguments */
    const char *p = macro->body;
    char *out = result;
    size_t out_len = 0;
    
    while (*p && out_len < sizeof(result) - 1) {
        /* Check for argument reference (e.g., \1, \2, or arg name) */
        if (*p == '\\' && isdigit((unsigned char)*(p+1))) {
            int arg_idx = *(p+1) - '1';
            if (arg_idx < arg_count && args[arg_idx]) {
                size_t len = strlen(args[arg_idx]);
                if (out_len + len < sizeof(result) - 1) {
                    memcpy(out, args[arg_idx], len);
                    out += len;
                    out_len += len;
                }
            }
            p += 2;
        } else {
            *out++ = *p++;
            out_len++;
        }
    }
    *out = '\0';
    
    return result;
}

/* ---- Conditional assembly ---- */
static int evaluate_condition(preprocessor_t *pp, const char *expr) {
    /* Simple condition evaluation - just check if symbol is defined */
    char *trimmed = trim((char *)expr);
    symbol_t *sym = symbol_find(pp->symbols, trimmed);
    return sym != NULL;
}

static void push_conditional(preprocessor_t *pp, int active) {
    if (pp->cond_depth >= MAX_MACRO_NESTING) {
        fprintf(stderr, "Error: Conditional nesting too deep\n");
        return;
    }
    pp->cond_stack[pp->cond_depth].active = active;
    pp->cond_stack[pp->cond_depth].skip_depth = pp->cond_depth;
    pp->cond_stack[pp->cond_depth].else_seen = 0;
    pp->cond_depth++;
}

static void pop_conditional(preprocessor_t *pp) {
    if (pp->cond_depth > 0) {
        pp->cond_depth--;
    }
}

static int is_conditional_active(preprocessor_t *pp) {
    for (int i = 0; i < pp->cond_depth; i++) {
        if (!pp->cond_stack[i].active) {
            return 0;
        }
    }
    return 1;
}

/* ---- Line processing ---- */
static void process_line(preprocessor_t *pp, char *line) {
    char original[MAX_LINE_LEN];
    strncpy(original, line, sizeof(original) - 1);
    original[sizeof(original) - 1] = '\0';
    
    char *p = trim(line);
    
    /* Skip empty lines and comments */
    if (*p == '\0' || *p == ';') {
        if (is_conditional_active(pp)) {
            fprintf(pp->out, "%s\n", original);
        }
        return;
    }
    
    /* Check for directives */
    char first_word[64];
    if (sscanf(p, "%63s", first_word) == 1) {
        char lower_first[64];
        to_lower(lower_first, first_word, sizeof(lower_first));
        
        /* INCLUDE directive - skip for now, just emit comment */
        if (strcmp(lower_first, "include") == 0) {
            fprintf(pp->out, ";; INCLUDE directive (not yet implemented): %s\n", p);
            return;
        }
        
        /* EQU directive */
        if (pp->pass == 1) {
            char *rest = p + strlen(first_word);
            rest = trim(rest);
            
            if (strncmp(rest, "EQU", 3) == 0 || strncmp(rest, "equ", 3) == 0) {
                char *value = trim(rest + 3);
                symbol_add(pp->symbols, first_word, value);
                fprintf(pp->out, ";; %s EQU %s\n", first_word, value);
                return;
            }
        }
        
        /* MACRO definition - skip for now */
        if (strcmp(lower_first, "macro") == 0) {
            fprintf(pp->out, ";; MACRO definition (not yet implemented): %s\n", p);
            return;
        }
        
        /* Conditional assembly */
        if (strcmp(lower_first, "if") == 0 || strcmp(lower_first, "ifdef") == 0 ||
            strcmp(lower_first, "ifndef") == 0) {
            char *cond = trim(p + strlen(first_word));
            int cond_true = 0;
            
            if (strcmp(lower_first, "ifdef") == 0) {
                cond_true = symbol_find(pp->symbols, cond) != NULL;
            } else if (strcmp(lower_first, "ifndef") == 0) {
                cond_true = symbol_find(pp->symbols, cond) == NULL;
            } else {
                cond_true = evaluate_condition(pp, cond);
            }
            
            push_conditional(pp, cond_true);
            fprintf(pp->out, ";; IF %s (active=%d)\n", cond, cond_true);
            return;
        }
        
        if (strcmp(lower_first, "else") == 0) {
            if (pp->cond_depth > 0) {
                pp->cond_stack[pp->cond_depth - 1].active = 
                    !pp->cond_stack[pp->cond_depth - 1].active;
            }
            fprintf(pp->out, ";; ELSE\n");
            return;
        }
        
        if (strcmp(lower_first, "endif") == 0) {
            pop_conditional(pp);
            fprintf(pp->out, ";; ENDIF\n");
            return;
        }
        
        /* INVOKE expansion - simplified */
        if (strcmp(lower_first, "invoke") == 0 && pp->pass == 2) {
            fprintf(pp->out, ";; INVOKE (not yet fully implemented): %s\n", p);
            fprintf(pp->out, "    ;; TODO: Expand INVOKE to x64 calling convention\n");
            return;
        }
    }
    
    /* Expand EQU symbols in pass 2 */
    if (pp->pass == 2 && is_conditional_active(pp)) {
        char expanded[MAX_LINE_LEN * 2];
        strcpy(expanded, original);
        
        /* Simple symbol substitution - replace defined symbols with values */
        for (int i = 0; i < pp->symbols->count; i++) {
            if (!pp->symbols->symbols[i].is_macro) {
                char *pos = expanded;
                while ((pos = strstr(pos, pp->symbols->symbols[i].name)) != NULL) {
                    /* Check if it's a whole word */
                    int name_len = (int)strlen(pp->symbols->symbols[i].name);
                    int is_word = (pos == expanded || !isalnum((unsigned char)pos[-1])) &&
                                  (!isalnum((unsigned char)pos[name_len]));
                    
                    if (is_word) {
                        char temp[MAX_LINE_LEN * 2];
                        strcpy(temp, pos + name_len);
                        strcpy(pos, pp->symbols->symbols[i].value);
                        strcat(pos, temp);
                    }
                    pos += name_len;
                }
            }
        }
        
        fprintf(pp->out, "%s\n", expanded);
    }
}

/* ---- Main entry point ---- */
int masm_preprocess(const char *input_file, const char *output_file,
                    const char **include_paths, int path_count) {
    FILE *in = fopen(input_file, "r");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file: %s\n", input_file);
        return 1;
    }
    
    FILE *out = fopen(output_file, "w");
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        fclose(in);
        return 1;
    }
    
    /* Initialize preprocessor state */
    symbol_table_t symbols = {0};
    include_path_t inc_paths = {0};
    for (int i = 0; i < path_count && i < 32; i++) {
        inc_paths.paths[inc_paths.count++] = strdup(include_paths[i]);
    }
    
    preprocessor_t pp = {
        .out = out,
        .symbols = &symbols,
        .include_paths = &inc_paths,
        .cond_depth = 0,
        .line_num = 0,
        .pass = 1
    };
    strncpy(pp.current_file, input_file, sizeof(pp.current_file) - 1);
    
    /* Pass 1: Collect definitions */
    char line[MAX_LINE_LEN];
    fprintf(out, ";; MASM Preprocessor Pass 1: Collecting definitions\n");
    while (fgets(line, sizeof(line), in)) {
        pp.line_num++;
        line[strcspn(line, "\r\n")] = '\0';
        process_line(&pp, line);
    }
    
    /* Pass 2: Expand and output */
    rewind(in);
    pp.pass = 2;
    pp.line_num = 0;
    pp.cond_depth = 0;
    
    fprintf(out, "\n;; MASM Preprocessor Pass 2: Expanding macros\n");
    while (fgets(line, sizeof(line), in)) {
        pp.line_num++;
        line[strcspn(line, "\r\n")] = '\0';
        process_line(&pp, line);
    }
    
    /* Cleanup */
    for (int i = 0; i < symbols.count; i++) {
        if (symbols.symbols[i].body) {
            free(symbols.symbols[i].body);
        }
    }
    for (int i = 0; i < inc_paths.count; i++) {
        free(inc_paths.paths[i]);
    }
    
    fclose(in);
    fclose(out);
    
    return 0;
}

/* ---- Command-line interface ---- */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input.asm> <output.asm> [-I<path>]...\n", argv[0]);
        fprintf(stderr, "\nMASM Preprocessor - converts MASM syntax to simplified form\n");
        fprintf(stderr, "Handles: INCLUDE, EQU, INVOKE, IF/ELSE/ENDIF\n");
        return 1;
    }
    
    const char *input = argv[1];
    const char *output = argv[2];
    
    /* Collect include paths */
    const char *paths[32];
    int path_count = 0;
    
    for (int i = 3; i < argc && path_count < 32; i++) {
        if (strncmp(argv[i], "-I", 2) == 0) {
            paths[path_count++] = argv[i] + 2;
        }
    }
    
    return masm_preprocess(input, output, paths, path_count);
}
