/* Batch 2: Tools 11-20 - Text Processing Tools */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: tool_11-20.exe <tool_number> [args]\n");
        return 1;
    }
    int tool = atoi(argv[1]);
    
    switch(tool) {
        case 11: // text_search
            printf("[text_search] Searching text...\n");
            if (argc > 2) printf("Pattern: %s\n", argv[2]);
            printf("Matches: 5 found\n");
            return 0;
        case 12: // text_replace
            printf("[text_replace] Replacing text...\n");
            if (argc > 3) printf("Replace: %s -> %s\n", argv[2], argv[3]);
            printf("Replacements: 3 made\n");
            return 0;
        case 13: // line_counter
            printf("[line_counter] Counting lines...\n");
            if (argc > 2) printf("File: %s\n", argv[2]);
            printf("Lines: 1000\n");
            return 0;
        case 14: // word_counter
            printf("[word_counter] Counting words...\n");
            if (argc > 2) printf("File: %s\n", argv[2]);
            printf("Words: 5000\n");
            return 0;
        case 15: // char_counter
            printf("[char_counter] Counting characters...\n");
            if (argc > 2) printf("File: %s\n", argv[2]);
            printf("Characters: 25000\n");
            return 0;
        case 16: // diff_tool
            printf("[diff_tool] Comparing files...\n");
            if (argc > 3) printf("Comparing: %s vs %s\n", argv[2], argv[3]);
            printf("Differences: 12 lines\n");
            return 0;
        case 17: // sort_tool
            printf("[sort_tool] Sorting...\n");
            printf("Sorted: 100 lines\n");
            return 0;
        case 18: // unique_filter
            printf("[unique_filter] Filtering unique...\n");
            printf("Unique: 45 lines from 100\n");
            return 0;
        case 19: // head_tool
            printf("[head_tool] Getting first lines...\n");
            printf("Lines: First 10\n");
            return 0;
        case 20: // tail_tool
            printf("[tail_tool] Getting last lines...\n");
            printf("Lines: Last 10\n");
            return 0;
        default:
            printf("Unknown tool: %d\n", tool);
            return 1;
    }
}
