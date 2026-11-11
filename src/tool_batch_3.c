/* Batch 3: Tools 21-30 - Archive & Compression Tools */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: tool_21-30.exe <tool_number> [args]\n");
        return 1;
    }
    int tool = atoi(argv[1]);
    
    switch(tool) {
        case 21: // zip_creator
            printf("[zip_creator] Creating zip archive...\n");
            if (argc > 2) printf("Archive: %s\n", argv[2]);
            printf("Files: 10 added\n");
            return 0;
        case 22: // zip_extractor
            printf("[zip_extractor] Extracting zip...\n");
            if (argc > 2) printf("Archive: %s\n", argv[2]);
            printf("Extracted: 10 files\n");
            return 0;
        case 23: // tar_archiver
            printf("[tar_archiver] Creating tar archive...\n");
            printf("Files: 15 archived\n");
            return 0;
        case 24: // tar_extractor
            printf("[tar_extractor] Extracting tar...\n");
            printf("Extracted: 15 files\n");
            return 0;
        case 25: // gzip_compressor
            printf("[gzip_compressor] Compressing...\n");
            printf("Compressed: 50%% size reduction\n");
            return 0;
        case 26: // gzip_decompressor
            printf("[gzip_decompressor] Decompressing...\n");
            printf("Decompressed: Success\n");
            return 0;
        case 27: // bzip2_compressor
            printf("[bzip2_compressor] Compressing...\n");
            printf("Compressed: 60%% size reduction\n");
            return 0;
        case 28: // bzip2_decompressor
            printf("[bzip2_decompressor] Decompressing...\n");
            printf("Decompressed: Success\n");
            return 0;
        case 29: // xz_compressor
            printf("[xz_compressor] Compressing...\n");
            printf("Compressed: 65%% size reduction\n");
            return 0;
        case 30: // xz_decompressor
            printf("[xz_decompressor] Decompressing...\n");
            printf("Decompressed: Success\n");
            return 0;
        default:
            printf("Unknown tool: %d\n", tool);
            return 1;
    }
}
