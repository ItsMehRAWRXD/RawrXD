
/*==========================================================================
 * masm_preprocessor_v2.c — Simplified MASM preprocessor
 *
 * Handles basic MASM constructs:
 *   - EQU constant definitions
 *   - Simple symbol substitution
 *   - Skips INCLUDE (outputs as comment)
 *   - Skips complex macros
 *
 * This is intentionally minimal to avoid stack overflow issues.
 *=========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE_LEN 4096
#define MAX_SYMBOLS 4096
#define MAX_NAME_LEN 128
#define MAX_VALUE_LEN 256

typedef struct {
    char name[MAX_NAME_LEN];
    char value[MAX_VALUE_LEN];
} equ_entry_t;

typedef struct {
    equ_entry_t entries[MAX_SYMBOLS];
    int count;
} equ_table_t;

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

static equ_entry_t *equ_find(equ_table_t *eq, const char *name) {
    char lower_name[MAX_NAME_LEN];
    to_lower(lower_name, name, sizeof(lower_name));
    
    for (int i = eq->count - 1; i >= 0; i--) {
        char lower_sym[MAX_NAME_LEN];
        to_lower(lower_sym, eq->entries[i].name, sizeof(lower_sym));
        if (strcmp(lower_sym, lower_name) == 0)
            return &eq->entries[i];
    }
    return NULL;
}

static void equ_add(equ_table_t *eq, const char *name, const char *value) {
    if (eq->count >= MAX_SYMBOLS) {
        fprintf(stderr, "Warning: EQU table full, ignoring %s\n", name);
        return;
    }
    equ_entry_t *e = &eq->entries[eq->count++];
    strncpy(e->name, name, MAX_NAME_LEN - 1);
    e->name[MAX_NAME_LEN - 1] = '\0';
    strncpy(e->value, value, MAX_VALUE_LEN - 1);
    e->value[MAX_VALUE_LEN - 1] = '\0';
}

static int is_word_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

static void substitute_symbols(char *line, equ_table_t *eq) {
    char result[MAX_LINE_LEN * 2];
    char *out = result;
    size_t out_pos = 0;
    
    char *p = line;
    while (*p && out_pos < MAX_LINE_LEN * 2 - 1) {
        /* Check if this position matches any EQU symbol */
        int matched = 0;
        
        for (int i = 0; i < eq->count; i++) {
            size_t name_len = strlen(eq->entries[i].name);
            
            /* Check for whole word match */
            if (strncmp(p, eq->entries[i].name, name_len) == 0) {
                /* Check word boundaries */
                int word_start = (p == line) || !is_word_char(p[-1]);
                int word_end = !is_word_char(p[name_len]);
                
                if (word_start && word_end) {
                    /* Substitute */
                    size_t val_len = strlen(eq->entries[i].value);
                    if (out_pos + val_len < MAX_LINE_LEN * 2 - 1) {
                        memcpy(out, eq->entries[i].value, val_len);
                        out += val_len;
                        out_pos += val_len;
                    }
                    p += name_len;
                    matched = 1;
                    break;
                }
            }
        }
        
        if (!matched) {
            *out++ = *p++;
            out_pos++;
        }
    }
    *out = '\0';
    
    strcpy(line, result);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input.asm> <output.asm>\n", argv[0]);
        fprintf(stderr, "Simple MASM preprocessor - handles EQU and basic symbols\n");
        return 1;
    }
    
    FILE *in = fopen(argv[1], "r");
    if (!in) {
        fprintf(stderr, "Error: Cannot open input: %s\n", argv[1]);
        return 1;
    }
    
    FILE *out = fopen(argv[2], "w");
    if (!out) {
        fprintf(stderr, "Error: Cannot create output: %s\n", argv[2]);
        fclose(in);
        return 1;
    }
    
    equ_table_t eq = {0};
    char line[MAX_LINE_LEN];
    int line_num = 0;
    
    fprintf(out, ";; Preprocessed by masm_preprocessor_v2\n");
    fprintf(out, ";; Original: %s\n\n", argv[1]);
    
    while (fgets(line, sizeof(line), in)) {
        line_num++;
        
        /* Remove trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) {
            line[--len] = '\0';
        }
        
        char *p = trim(line);
        
        /* Skip empty lines and pure comments */
        if (*p == '\0' || *p == ';') {
            fprintf(out, "%s\n", line);
            continue;
        }
        
        /* Check for EQU directive */
        char first_word[MAX_NAME_LEN];
        if (sscanf(p, "%127s", first_word) == 1) {
            /* Look for EQU after first word */
            char *rest = p + strlen(first_word);
            rest = trim(rest);
            
            if (strncmp(rest, "EQU", 3) == 0 || strncmp(rest, "equ", 3) == 0) {
                char *value = trim(rest + 3);
                equ_add(&eq, first_word, value);
                fprintf(out, ";; %s EQU %s\n", first_word, value);
                continue;
            }
            
            /* Skip INCLUDE for now */
            char lower_first[MAX_NAME_LEN];
            to_lower(lower_first, first_word, sizeof(lower_first));
            if (strcmp(lower_first, "include") == 0) {
                fprintf(out, ";; INCLUDE: %s\n", p);
                continue;
            }
            
            /* Skip MACRO definitions */
            if (strcmp(lower_first, "macro") == 0) {
                fprintf(out, ";; MACRO: %s\n", p);
                continue;
            }
            
            /* Skip ENDM */
            if (strcmp(lower_first, "endm") == 0) {
                fprintf(out, ";; ENDM\n");
                continue;
            }
            
            /* Skip INVOKE for now */
            if (strcmp(lower_first, "invoke") == 0) {
                fprintf(out, ";; INVOKE: %s\n", p);
                fprintf(out, "    ;; TODO: Manual x64 call sequence\n");
                continue;
            }
            
            /* Skip conditional assembly directives */
            if (strcmp(lower_first, "if") == 0 || 
                strcmp(lower_first, "ifdef") == 0 ||
                strcmp(lower_first, "ifndef") == 0 ||
                strcmp(lower_first, "else") == 0 ||
                strcmp(lower_first, "endif") == 0) {
                fprintf(out, ";; CONDITIONAL: %s\n", p);
                continue;
            }
        }
        
        /* Substitute EQU symbols and output */
        substitute_symbols(line, &eq);
        fprintf(out, "%s\n", line);
    }
    
    fclose(in);
    fclose(out);
    
    printf("Preprocessed %d lines, %d EQU symbols defined\n", line_num, eq.count);
    return 0;
}
