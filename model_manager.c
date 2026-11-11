// ============================================================================
// model_manager.c
// Interactive model manager for Ollama
// Compile: gcc -O2 model_manager.c -o model_manager.exe -lwinhttp
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

#define MAX_MODELS 100
#define MAX_NAME_LEN 256

typedef struct {
    char name[MAX_NAME_LEN];
    char model[MAX_NAME_LEN];
    char family[MAX_NAME_LEN];
    double size_gb;
    int context_length;
    int embedding_length;
    char quantization[32];
} ModelInfo;

typedef struct {
    ModelInfo models[MAX_MODELS];
    int count;
} ModelList;

// Simple JSON parser for model list
int parse_models(const char* json, ModelList* list) {
    list->count = 0;
    
    const char* p = json;
    while ((p = strstr(p, "\"name\":\"")) != NULL && list->count < MAX_MODELS) {
        p += 8;
        
        // Extract name
        const char* end = strchr(p, '"');
        if (!end) break;
        size_t len = end - p;
        if (len >= MAX_NAME_LEN) len = MAX_NAME_LEN - 1;
        memcpy(list->models[list->count].name, p, len);
        list->models[list->count].name[len] = '\0';
        
        // Extract model field
        p = strstr(end, "\"model\":\"");
        if (p) {
            p += 9;
            end = strchr(p, '"');
            if (end) {
                len = end - p;
                if (len >= MAX_NAME_LEN) len = MAX_NAME_LEN - 1;
                memcpy(list->models[list->count].model, p, len);
                list->models[list->count].model[len] = '\0';
            }
        }
        
        // Extract family
        p = strstr(end, "\"family\":\"");
        if (p) {
            p += 10;
            end = strchr(p, '"');
            if (end) {
                len = end - p;
                if (len >= MAX_NAME_LEN) len = MAX_NAME_LEN - 1;
                memcpy(list->models[list->count].family, p, len);
                list->models[list->count].family[len] = '\0';
            }
        }
        
        // Extract size
        p = strstr(end, "\"size\":");
        if (p) {
            p += 7;
            long long size = atoll(p);
            list->models[list->count].size_gb = size / (1024.0 * 1024.0 * 1024.0);
        }
        
        // Extract context_length
        p = strstr(end, "\"context_length\":");
        if (p) {
            p += 18;
            list->models[list->count].context_length = atoi(p);
        }
        
        // Extract embedding_length
        p = strstr(end, "\"embedding_length\":");
        if (p) {
            p += 19;
            list->models[list->count].embedding_length = atoi(p);
        }
        
        // Extract quantization
        p = strstr(end, "\"quantization_level\":\"");
        if (p) {
            p += 24;
            end = strchr(p, '"');
            if (end) {
                len = end - p;
                if (len >= 32) len = 31;
                memcpy(list->models[list->count].quantization, p, len);
                list->models[list->count].quantization[len] = '\0';
            }
        }
        
        list->count++;
    }
    
    return list->count;
}

int fetch_models(ModelList* list) {
    HINTERNET hSession = WinHttpOpen(L"RawrXD-ModelManager/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) return 0;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 11434, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return 0;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/tags",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }
    
    int result = 0;
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            char buffer[65536];
            DWORD bytesRead;
            if (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
                buffer[bytesRead] = '\0';
                result = parse_models(buffer, list);
            }
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result;
}

void print_model_info(ModelInfo* model) {
    printf("  Name:        %s\n", model->name);
    printf("  Model:       %s\n", model->model);
    printf("  Family:      %s\n", model->family);
    printf("  Size:        %.2f GB\n", model->size_gb);
    printf("  Context:     %d tokens\n", model->context_length);
    printf("  Embedding:   %d dims\n", model->embedding_length);
    printf("  Quant:       %s\n", model->quantization);
}

void list_models(ModelList* list) {
    printf("\n========================================\n");
    printf("Available Models (%d)\n", list->count);
    printf("========================================\n\n");
    
    for (int i = 0; i < list->count; i++) {
        printf("[%d] %s\n", i + 1, list->models[i].name);
        printf("    Family: %s | Size: %.1f GB | Context: %d\n",
               list->models[i].family,
               list->models[i].size_gb,
               list->models[i].context_length);
    }
}

void show_model_details(ModelList* list, int index) {
    if (index < 1 || index > list->count) {
        printf("Invalid model index\n");
        return;
    }
    
    printf("\n========================================\n");
    printf("Model Details\n");
    printf("========================================\n");
    print_model_info(&list->models[index - 1]);
    printf("========================================\n");
}

void test_model(ModelList* list, int index) {
    if (index < 1 || index > list->count) {
        printf("Invalid model index\n");
        return;
    }
    
    const char* model_name = list->models[index - 1].name;
    printf("\nTesting model: %s\n", model_name);
    printf("Sending test prompt...\n\n");
    
    HINTERNET hSession = WinHttpOpen(L"RawrXD-ModelManager/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        printf("Failed to create session\n");
        return;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 11434, 0);
    if (!hConnect) {
        printf("Failed to connect\n");
        WinHttpCloseHandle(hSession);
        return;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    
    if (!hRequest) {
        printf("Failed to create request\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }
    
    char json[512];
    snprintf(json, sizeof(json),
        "{\"model\":\"%s\",\"prompt\":\"Hi, what's your name?\",\"stream\":false,\"options\":{\"num_predict\":20}}",
        model_name);
    
    if (WinHttpSendRequest(hRequest,
            L"Content-Type: application/json\r\n",
            -1L,
            (LPVOID)json, strlen(json), strlen(json), 0)) {
        
        if (WinHttpReceiveResponse(hRequest, NULL)) {
            char buffer[4096];
            DWORD bytesRead;
            if (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
                buffer[bytesRead] = '\0';
                printf("Response:\n%.500s...\n\n", buffer);
                printf("Test completed successfully!\n");
            }
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

void show_menu(void) {
    printf("\n========================================\n");
    printf("RawrXD Model Manager\n");
    printf("========================================\n");
    printf("1. List all models\n");
    printf("2. Show model details\n");
    printf("3. Test model\n");
    printf("4. Refresh model list\n");
    printf("5. Exit\n");
    printf("========================================\n");
    printf("Choice: ");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("RawrXD Model Manager\n");
    printf("========================================\n");
    printf("Connecting to Ollama...\n");
    
    ModelList list;
    if (!fetch_models(&list)) {
        printf("Failed to fetch models from Ollama\n");
        printf("Make sure Ollama is running on localhost:11434\n");
        return 1;
    }
    
    printf("Found %d models\n", list.count);
    
    int choice;
    int running = 1;
    
    while (running) {
        show_menu();
        if (scanf("%d", &choice) != 1) {
            // Clear input buffer
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }
        
        switch (choice) {
            case 1:
                list_models(&list);
                break;
                
            case 2: {
                printf("Enter model number: ");
                int idx;
                if (scanf("%d", &idx) == 1) {
                    show_model_details(&list, idx);
                }
                break;
            }
            
            case 3: {
                printf("Enter model number to test: ");
                int idx;
                if (scanf("%d", &idx) == 1) {
                    test_model(&list, idx);
                }
                break;
            }
            
            case 4:
                printf("Refreshing...\n");
                if (fetch_models(&list)) {
                    printf("Found %d models\n", list.count);
                } else {
                    printf("Failed to refresh\n");
                }
                break;
                
            case 5:
                running = 0;
                break;
                
            default:
                printf("Invalid choice\n");
        }
    }
    
    printf("\nGoodbye!\n");
    return 0;
}
