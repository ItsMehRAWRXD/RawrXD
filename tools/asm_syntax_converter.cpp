// Assembly Syntax Converter - Production Ready
// Converts MASM syntax to NASM-like syntax for our native assembler

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define CONVERTER_VERSION "1.0.0"
#define MAX_LINE_LENGTH 4096
#define MAX_LABEL_LENGTH 256

// Function prototypes
int ConvertFile(const char* inputFile, const char* outputFile);
void ConvertLine(char* output, const char* input, size_t maxLen);
void RemoveLeadingWhitespace(char* str);
void TrimTrailingWhitespace(char* str);
BOOL IsDirective(const char* line);
BOOL IsInstruction(const char* line);
const char* ConvertInstruction(const char* instr);
void ProcessOperand(char* output, const char* operand);

int main(int argc, char** argv) {
    printf("Assembly Syntax Converter v%s - Production Ready\n", CONVERTER_VERSION);
    printf("================================================\n\n");
    
    if (argc < 3) {
        printf("Usage: asm_converter.exe <input.asm> <output.asm>\n");
        printf("\nConverts MASM syntax to NASM-like syntax:\n");
        printf("  - option casemap:none    -> (removed)\n");
        printf("  - .code / .data          -> section .text / .data\n");
        printf("  - PROC/ENDP              -> label:\n");
        printf("  - INVOKE                 -> call\n");
        printf("  - OFFSET                 -> (removed)\n");
        printf("  - PTR                    -> (removed)\n");
        return 1;
    }
    
    printf("Input:  %s\n", argv[1]);
    printf("Output: %s\n", argv[2]);
    printf("\n");
    
    if (ConvertFile(argv[1], argv[2])) {
        printf("\n✅ Conversion successful!\n");
        return 0;
    } else {
        printf("\n❌ Conversion failed!\n");
        return 1;
    }
}

int ConvertFile(const char* inputFile, const char* outputFile) {
    FILE* in = fopen(inputFile, "r");
    if (!in) {
        printf("❌ Cannot open input file: %s\n", inputFile);
        return 0;
    }
    
    FILE* out = fopen(outputFile, "w");
    if (!out) {
        printf("❌ Cannot create output file: %s\n", outputFile);
        fclose(in);
        return 0;
    }
    
    // Write NASM header
    fprintf(out, "; Converted by asm_converter v%s\n", CONVERTER_VERSION);
    fprintf(out, "; Original: %s\n\n", inputFile);
    fprintf(out, "BITS 64\n");
    fprintf(out, "DEFAULT REL\n\n");
    
    char line[MAX_LINE_LENGTH];
    char converted[MAX_LINE_LENGTH];
    int lineNum = 0;
    int inProc = 0;
    char currentProc[MAX_LABEL_LENGTH] = {0};
    
    while (fgets(line, sizeof(line), in)) {
        lineNum++;
        
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        // Skip empty lines and comments
        char trimmed[MAX_LINE_LENGTH];
        strcpy(trimmed, line);
        RemoveLeadingWhitespace(trimmed);
        
        if (trimmed[0] == '\0' || trimmed[0] == ';') {
            fprintf(out, "%s\n", line);
            continue;
        }
        
        // Convert the line
        ConvertLine(converted, line, sizeof(converted));
        
        // Handle PROC/ENDP
        if (strstr(line, "PROC") != NULL && strstr(line, "ENDP") == NULL) {
            // Extract procedure name
            char* proc = strstr(line, "PROC");
            if (proc) {
                *proc = '\0';
                strcpy(currentProc, trimmed);
                // Remove any parameters
                char* space = strchr(currentProc, ' ');
                if (space) *space = '\0';
                
                fprintf(out, "\nsection .text\n");
                fprintf(out, "global %s\n", currentProc);
                fprintf(out, "%s:\n", currentProc);
                inProc = 1;
                continue;
            }
        }
        
        if (strstr(line, "ENDP") != NULL) {
            inProc = 0;
            currentProc[0] = '\0';
            continue;  // Skip ENDP lines
        }
        
        // Skip certain MASM directives
        if (strstr(line, "option casemap") != NULL) continue;
        if (strstr(line, "includelib") != NULL) continue;
        if (strstr(line, "assume") != NULL) continue;
        if (strstr(line, "PROTO") != NULL) continue;
        if (strstr(line, "EXTERNDEF") != NULL) continue;
        if (strstr(line, "PUBLIC") != NULL) continue;
        
        // Convert .code and .data
        if (strstr(trimmed, ".code") == trimmed) {
            fprintf(out, "\nsection .text\n");
            continue;
        }
        if (strstr(trimmed, ".data") == trimmed) {
            fprintf(out, "\nsection .data\n");
            continue;
        }
        if (strstr(trimmed, ".const") == trimmed) {
            fprintf(out, "\nsection .rdata\n");
            continue;
        }
        
        // Write converted line
        if (converted[0] != '\0') {
            fprintf(out, "%s\n", converted);
        }
    }
    
    fclose(in);
    fclose(out);
    
    printf("✅ Converted %d lines\n", lineNum);
    return 1;
}

void ConvertLine(char* output, const char* input, size_t maxLen) {
    char line[MAX_LINE_LENGTH];
    strncpy(line, input, sizeof(line) - 1);
    line[sizeof(line) - 1] = '\0';
    
    // Remove leading whitespace
    RemoveLeadingWhitespace(line);
    
    // Check for label
    char* colon = strchr(line, ':');
    char* comment = strchr(line, ';');
    
    if (colon && (!comment || colon < comment)) {
        // This is a label
        strncpy(output, line, maxLen - 1);
        output[maxLen - 1] = '\0';
        return;
    }
    
    // Split into instruction and operands
    char instr[MAX_LINE_LENGTH] = {0};
    char operands[MAX_LINE_LENGTH] = {0};
    
    // Find first space (instruction separator)
    char* space = strchr(line, ' ');
    char* tab = strchr(line, '\t');
    char* sep = NULL;
    
    if (space && tab) {
        sep = (space < tab) ? space : tab;
    } else if (space) {
        sep = space;
    } else if (tab) {
        sep = tab;
    }
    
    if (sep) {
        size_t instrLen = sep - line;
        strncpy(instr, line, instrLen);
        instr[instrLen] = '\0';
        
        // Get operands
        strcpy(operands, sep + 1);
        TrimTrailingWhitespace(operands);
    } else {
        strcpy(instr, line);
    }
    
    // Convert instruction
    const char* newInstr = ConvertInstruction(instr);
    
    // Build output
    if (operands[0]) {
        // Process operands (remove OFFSET, PTR, etc.)
        char procOperands[MAX_LINE_LENGTH];
        ProcessOperand(procOperands, operands);
        
        snprintf(output, maxLen, "    %s %s", newInstr, procOperands);
    } else {
        snprintf(output, maxLen, "    %s", newInstr);
    }
}

void RemoveLeadingWhitespace(char* str) {
    char* start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}

void TrimTrailingWhitespace(char* str) {
    size_t len = strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

const char* ConvertInstruction(const char* instr) {
    // MASM to NASM instruction mapping
    static struct {
        const char* masm;
        const char* nasm;
    } conversions[] = {
        {"mov", "mov"},
        {"push", "push"},
        {"pop", "pop"},
        {"call", "call"},
        {"ret", "ret"},
        {"jmp", "jmp"},
        {"je", "je"},
        {"jne", "jne"},
        {"jg", "jg"},
        {"jge", "jge"},
        {"jl", "jl"},
        {"jle", "jle"},
        {"ja", "ja"},
        {"jae", "jae"},
        {"jb", "jb"},
        {"jbe", "jbe"},
        {"add", "add"},
        {"sub", "sub"},
        {"mul", "mul"},
        {"div", "div"},
        {"imul", "imul"},
        {"idiv", "idiv"},
        {"and", "and"},
        {"or", "or"},
        {"xor", "xor"},
        {"not", "not"},
        {"neg", "neg"},
        {"inc", "inc"},
        {"dec", "dec"},
        {"cmp", "cmp"},
        {"test", "test"},
        {"lea", "lea"},
        {"nop", "nop"},
        {"int", "int"},
        {"syscall", "syscall"},
        {"sysret", "sysret"},
        {"leave", "leave"},
        {"enter", "enter"},
        {"INVOKE", "call"},
        {NULL, NULL}
    };
    
    for (int i = 0; conversions[i].masm != NULL; i++) {
        if (_stricmp(instr, conversions[i].masm) == 0) {
            return conversions[i].nasm;
        }
    }
    
    return instr;  // Return original if not found
}

void ProcessOperand(char* output, const char* operand) {
    char temp[MAX_LINE_LENGTH];
    strcpy(temp, operand);
    
    // Remove OFFSET keyword
    char* offset = strstr(temp, "OFFSET ");
    while (offset) {
        memmove(offset, offset + 7, strlen(offset + 7) + 1);
        offset = strstr(temp, "OFFSET ");
    }
    
    offset = strstr(temp, "offset ");
    while (offset) {
        memmove(offset, offset + 7, strlen(offset + 7) + 1);
        offset = strstr(temp, "offset ");
    }
    
    // Remove PTR keyword (e.g., "DWORD PTR" -> "")
    char* ptr = strstr(temp, "PTR ");
    while (ptr) {
        // Find the type before PTR
        char* start = ptr;
        while (start > temp && !isspace((unsigned char)*(start - 1))) {
            start--;
        }
        memmove(start, ptr + 4, strlen(ptr + 4) + 1);
        ptr = strstr(temp, "PTR ");
    }
    
    ptr = strstr(temp, "ptr ");
    while (ptr) {
        char* start = ptr;
        while (start > temp && !isspace((unsigned char)*(start - 1))) {
            start--;
        }
        memmove(start, ptr + 4, strlen(ptr + 4) + 1);
        ptr = strstr(temp, "ptr ");
    }
    
    // Convert MASM memory syntax [base+index*scale+disp] to NASM [base+index*scale+disp]
    // (They're actually the same, but ensure proper formatting)
    
    strcpy(output, temp);
}
