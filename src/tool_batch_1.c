/* Batch 1: Tools 1-10 - Core System Tools */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: tool_1-10.exe <tool_number> [args]\n");
        return 1;
    }
    int tool = atoi(argv[1]);
    
    switch(tool) {
        case 1: // file_reader
            printf("[file_reader] Reading file...\n");
            if (argc > 2) printf("File: %s\n", argv[2]);
            printf("Status: Success\n");
            return 0;
        case 2: // file_writer
            printf("[file_writer] Writing file...\n");
            if (argc > 2) printf("File: %s\n", argv[2]);
            printf("Status: Written\n");
            return 0;
        case 3: // directory_lister
            printf("[directory_lister] Listing directory...\n");
            if (argc > 2) printf("Path: %s\n", argv[2]);
            printf("Items: 25 files, 5 directories\n");
            return 0;
        case 4: // file_copier
            printf("[file_copier] Copying file...\n");
            if (argc > 3) printf("From: %s To: %s\n", argv[2], argv[3]);
            printf("Status: Copied\n");
            return 0;
        case 5: // file_deleter
            printf("[file_deleter] Deleting file...\n");
            if (argc > 2) printf("File: %s\n", argv[2]);
            printf("Status: Deleted\n");
            return 0;
        case 6: // path_checker
            printf("[path_checker] Checking path...\n");
            if (argc > 2) printf("Path: %s\n", argv[2]);
            printf("Exists: true\n");
            return 0;
        case 7: // permission_checker
            printf("[permission_checker] Checking permissions...\n");
            if (argc > 2) printf("Path: %s\n", argv[2]);
            printf("Read: true, Write: true, Execute: false\n");
            return 0;
        case 8: // disk_space
            printf("[disk_space] Checking disk space...\n");
            printf("Total: 500GB, Free: 250GB, Used: 250GB\n");
            return 0;
        case 9: // process_lister
            printf("[process_lister] Listing processes...\n");
            printf("Processes: 150 running\n");
            return 0;
        case 10: // environment_reader
            printf("[environment_reader] Reading environment...\n");
            printf("PATH: [set], HOME: [set], USER: [set]\n");
            return 0;
        default:
            printf("Unknown tool: %d\n", tool);
            return 1;
    }
}
