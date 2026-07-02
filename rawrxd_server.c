// rawrxd_server.c — OpenAI-compatible HTTP bridge for RawrXD inference engine
// Build: cl /O2 rawrxd_server.c /link ws2_32.lib user32.lib kernel32.lib
// Usage: rawrxd_server.exe [--port 8080] [--host 127.0.0.1]

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

// ─── Shared Memory Protocol Constants ────────────────────────────────
#define SHMEM_NAME        "SOVEREIGN_BEACON_V1"
#define CMD_EVENT_NAME    "SOVEREIGN_CMD_EVENT"
#define RESP_EVENT_NAME   "SOVEREIGN_RESP_EVENT"

#define OFF_STATE         0x00    // 4 bytes
#define OFF_CMD_ID        0x04    // 4 bytes
#define OFF_CMD_TYPE      0x08    // 4 bytes
#define OFF_PAYLOAD_LEN   0x0C    // 4 bytes
#define OFF_RESP_STATUS   0x10    // 4 bytes
#define OFF_RESP_LEN      0x14    // 4 bytes
#define OFF_CMD_PAYLOAD   0x18    // 4096 bytes
#define OFF_RESP_PAYLOAD  0x1018  // 61432 bytes
#define OFF_MODEL_STATE   0x2030  // 4 bytes
#define OFF_MAGIC         0xFFF0  // 8 bytes
#define SHMEM_SIZE        0x10000 // 64 KB

#define CMD_INFER         0x3003
#define CMD_LOAD_MODEL    0x2000
#define CMD_GET_STATUS    0x1002

#define STATE_READY       1
#define STATE_PROCESSING  2
#define STATE_COMPLETE    4

#define MODEL_UNLOADED    0
#define MODEL_LOADING     1
#define MODEL_READY       2

// ─── Global Handles ──────────────────────────────────────────────────
static HANDLE g_hShMem    = NULL;
static HANDLE g_hCmdEvent = NULL;
static HANDLE g_hRespEvent= NULL;
static LPVOID g_pShMem    = NULL;
static int    g_cmd_id    = 1;
static char   g_models[256] = "codestral-22b";

// ─── Utility: JSON String Extraction (minimal parser) ───────────────
static int json_extract_string(const char *json, const char *key, char *out, int out_max) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    if (*p != '"') return -1;
    p++;
    int len = 0;
    while (*p && *p != '"' && len < out_max - 1) {
        if (*p == '\\' && *(p+1)) {
            p++;
            switch (*p) {
                case 'n':  out[len++] = '\n'; break;
                case 't':  out[len++] = '\t'; break;
                case 'r':  out[len++] = '\r'; break;
                case '"':  out[len++] = '"';  break;
                case '\\': out[len++] = '\\'; break;
                default:   out[len++] = *p;   break;
            }
        } else {
            out[len++] = *p;
        }
        p++;
    }
    out[len] = '\0';
    return len;
}

static int json_extract_int(const char *json, const char *key, int default_val) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return default_val;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    return atoi(p);
}

static int json_extract_bool(const char *json, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':')) p++;
    return (strncmp(p, "true", 4) == 0) ? 1 : 0;
}

// ─── Shared Memory Connection ──────────────────────────────────────
static int shmem_connect(void) {
    g_hShMem = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, SHMEM_NAME);
    if (!g_hShMem) {
        fprintf(stderr, "[Server] Cannot open shared memory '%s' (err=%lu)\n",
                SHMEM_NAME, GetLastError());
        return 0;
    }
    g_pShMem = MapViewOfFile(g_hShMem, FILE_MAP_ALL_ACCESS, 0, 0, SHMEM_SIZE);
    if (!g_pShMem) {
        fprintf(stderr, "[Server] Cannot map view of file\n");
        CloseHandle(g_hShMem);
        return 0;
    }
    g_hCmdEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, CMD_EVENT_NAME);
    g_hRespEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, RESP_EVENT_NAME);
    if (!g_hCmdEvent || !g_hRespEvent) {
        fprintf(stderr, "[Server] Cannot open events\n");
        return 0;
    }
    ULONGLONG magic = *(ULONGLONG *)((BYTE *)g_pShMem + OFF_MAGIC);
    if (magic != 0xDEADBEEFCAFEBABEULL) {
        fprintf(stderr, "[Server] Magic cookie mismatch! Engine not ready.\n");
        return 0;
    }
    fprintf(stderr, "[Server] Connected to RawrXD engine via shared memory ✓\n");
    return 1;
}

static int is_model_ready(void) {
    if (!g_pShMem) return 0;
    DWORD model_state = *(DWORD *)((BYTE *)g_pShMem + OFF_MODEL_STATE);
    return (model_state == MODEL_READY);
}

static int shmem_infer(const char *prompt, int max_tokens,
                       char *resp_buf, int resp_max) {
    if (!g_pShMem || !g_hCmdEvent || !g_hRespEvent) return -1;

    BYTE *base = (BYTE *)g_pShMem;

    *(DWORD *)(base + OFF_RESP_STATUS) = 0;
    *(DWORD *)(base + OFF_RESP_LEN) = 0;
    *(DWORD *)(base + OFF_STATE) = STATE_READY;

    int payload_len = (int)strlen(prompt);
    if (payload_len > 4090) payload_len = 4090;
    memcpy(base + OFF_CMD_PAYLOAD, prompt, payload_len);
    ((char *)(base + OFF_CMD_PAYLOAD))[payload_len] = '\0';

    g_cmd_id++;
    *(DWORD *)(base + OFF_CMD_ID) = g_cmd_id;
    *(DWORD *)(base + OFF_CMD_TYPE) = CMD_INFER;
    *(DWORD *)(base + OFF_PAYLOAD_LEN) = payload_len;
    *(DWORD *)(base + OFF_STATE) = STATE_PROCESSING;

    SetEvent(g_hCmdEvent);

    DWORD waited = 0;
    int got_response = 0;
    while (waited < 30000) {
        DWORD result = WaitForSingleObject(g_hRespEvent, 10);
        if (result == WAIT_OBJECT_0) {
            got_response = 1;
            break;
        }
        DWORD resp_status = *(DWORD *)(base + OFF_RESP_STATUS);
        if (resp_status != 0) {
            got_response = 1;
            break;
        }
        waited += 10;
    }

    if (!got_response) {
        fprintf(stderr, "[Server] Inference timeout (30s)\n");
        return -1;
    }

    DWORD resp_len = *(DWORD *)(base + OFF_RESP_LEN);
    if (resp_len > (DWORD)(resp_max - 1)) resp_len = resp_max - 1;
    if (resp_len == 0) {
        const char *p = (const char *)(base + OFF_RESP_PAYLOAD);
        resp_len = 0;
        while (resp_len < 61432 && p[resp_len] && resp_len < (DWORD)(resp_max - 1)) {
            resp_buf[resp_len] = p[resp_len];
            resp_len++;
        }
    } else {
        memcpy(resp_buf, base + OFF_RESP_PAYLOAD, resp_len);
    }
    resp_buf[resp_len] = '\0';

    *(DWORD *)(base + OFF_STATE) = STATE_READY;
    ResetEvent(g_hRespEvent);

    return (int)resp_len;
}

// ─── HTTP Response Helpers ─────────────────────────────────────────
static void send_http_response(SOCKET sock, int status_code,
                               const char *content_type,
                               const char *body, int body_len) {
    char header[512];
    const char *status_text = "OK";
    if (status_code == 404) status_text = "Not Found";
    if (status_code == 500) status_text = "Internal Server Error";

    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);

    send(sock, header, hlen, 0);
    if (body_len > 0) {
        send(sock, body, body_len, 0);
    }
}

static void send_sse_chunk(SOCKET sock, const char *data, int data_len) {
    char chunk[4096];
    int len = snprintf(chunk, sizeof(chunk),
        "data: %.*s\r\n\r\n", data_len, data);
    send(sock, chunk, len, 0);
}

static void send_sse_done(SOCKET sock) {
    const char *done = "data: [DONE]\r\n\r\n";
    send(sock, done, (int)strlen(done), 0);
}

static void json_escape(const char *src, char *dst, int dst_max) {
    int j = 0;
    for (int i = 0; src[i] && j < dst_max - 2; i++) {
        switch (src[i]) {
            case '"':  dst[j++]='\\'; dst[j++]='"';  break;
            case '\\': dst[j++]='\\'; dst[j++]='\\'; break;
            case '\n': dst[j++]='\\'; dst[j++]='n';  break;
            case '\r': dst[j++]='\\'; dst[j++]='r';  break;
            case '\t': dst[j++]='\\'; dst[j++]='t';  break;
            default:
                if ((unsigned char)src[i] < 0x20) {
                    j += snprintf(dst + j, dst_max - j, "\\u%04x", src[i]);
                } else {
                    dst[j++] = src[i];
                }
        }
    }
    dst[j] = '\0';
}

// ─── Endpoint: GET /v1/models ──────────────────────────────────────
static void handle_list_models(SOCKET sock) {
    char body[1024];
    int len = snprintf(body, sizeof(body),
        "{\n"
        "  \"object\": \"list\",\n"
        "  \"data\": [\n"
        "    {\n"
        "      \"id\": \"%s\",\n"
        "      \"object\": \"model\",\n"
        "      \"created\": %ld,\n"
        "      \"owned_by\": \"rawrxd\"\n"
        "    }\n"
        "  ]\n"
        "}\n",
        g_models, time(NULL));
    send_http_response(sock, 200, "application/json", body, len);
}

// ─── Endpoint: POST /v1/completions ────────
static void handle_completions(SOCKET sock, const char *body) {
    char prompt[4096];
    char resp_text[62000];
    char escaped[125000];

    int max_tokens = json_extract_int(body, "max_tokens", 64);
    int do_stream  = json_extract_bool(body, "stream");

    int prompt_len = json_extract_string(body, "prompt", prompt, sizeof(prompt));
    if (prompt_len < 0) {
        send_http_response(sock, 400, "application/json",
            "{\"error\":{\"message\":\"Missing 'prompt' field\"}}", 52);
        return;
    }

    if (!is_model_ready()) {
        send_http_response(sock, 503, "application/json",
            "{\"error\":{\"message\":\"Model not loaded\"}}", 38);
        return;
    }

    int resp_len = shmem_infer(prompt, max_tokens, resp_text, sizeof(resp_text));
    if (resp_len < 0) {
        send_http_response(sock, 500, "application/json",
            "{\"error\":{\"message\":\"Inference timeout\"}}", 37);
        return;
    }

    if (do_stream) {
        char header[512];
        int hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n");
        send(sock, header, hlen, 0);

        char *word = strtok(resp_text, " \n");
        while (word) {
            char chunk[60000];
            json_escape(word, escaped, sizeof(escaped));
            int clen = snprintf(chunk, sizeof(chunk),
                "{\"id\":\"cmpl-%d\",\"object\":\"text_completion\","
                "\"choices\":[{\"text\":\"%s \",\"index\":0,"
                "\"finish_reason\":null}]}", g_cmd_id, escaped);
            send_sse_chunk(sock, chunk, clen);
            word = strtok(NULL, " \n");
            Sleep(10);
        }
        char final_chunk[256];
        int flen = snprintf(final_chunk, sizeof(final_chunk),
            "{\"id\":\"cmpl-%d\",\"object\":\"text_completion\","
            "\"choices\":[{\"text\":\"\",\"index\":0,"
            "\"finish_reason\":\"stop\"}]}", g_cmd_id);
        send_sse_chunk(sock, final_chunk, flen);
        send_sse_done(sock);
    } else {
        json_escape(resp_text, escaped, sizeof(escaped));
        char response[128000];
        int rlen = snprintf(response, sizeof(response),
            "{\n"
            "  \"id\": \"cmpl-%d\",\n"
            "  \"object\": \"text_completion\",\n"
            "  \"created\": %ld,\n"
            "  \"model\": \"%s\",\n"
            "  \"choices\": [\n"
            "    {\n"
            "      \"text\": \"%s\",\n"
            "      \"index\": 0,\n"
            "      \"finish_reason\": \"stop\"\n"
            "    }\n"
            "  ],\n"
            "  \"usage\": {\n"
            "    \"prompt_tokens\": %d,\n"
            "    \"completion_tokens\": %d,\n"
            "    \"total_tokens\": %d\n"
            "  }\n"
            "}\n",
            g_cmd_id, time(NULL), g_models, escaped,
            prompt_len / 4, resp_len / 4, (prompt_len + resp_len) / 4);
        send_http_response(sock, 200, "application/json", response, rlen);
    }
}

// ─── Endpoint: POST /v1/chat/completions ──────────────────────────
static void handle_chat_completions(SOCKET sock, const char *body) {
    char prompt[4096];
    char resp_text[62000];
    char escaped[125000];

    int max_tokens = json_extract_int(body, "max_tokens", 256);
    int do_stream  = json_extract_bool(body, "stream");

    const char *p = body;
    const char *last_content = NULL;
    int last_content_len = 0;
    char search[] = "\"content\":\"";
    while ((p = strstr(p, search)) != NULL) {
        p += strlen(search);
        last_content = p;
        const char *q = p;
        while (*q && *q != '"') { if (*q == '\\') q++; q++; }
        last_content_len = (int)(q - p);
        p = q;
    }

    if (!last_content || last_content_len <= 0) {
        send_http_response(sock, 400, "application/json",
            "{\"error\":{\"message\":\"No content found in messages\"}}", 47);
        return;
    }

    int j = 0;
    for (int i = 0; i < last_content_len && j < 4090; i++) {
        if (last_content[i] == '\\' && i + 1 < last_content_len) {
            i++;
            switch (last_content[i]) {
                case 'n':  prompt[j++] = '\n'; break;
                case 't':  prompt[j++] = '\t'; break;
                case 'r':  prompt[j++] = '\r'; break;
                case '"':  prompt[j++] = '"';  break;
                case '\\': prompt[j++] = '\\'; break;
                default:   prompt[j++] = last_content[i]; break;
            }
        } else {
            prompt[j++] = last_content[i];
        }
    }
    prompt[j] = '\0';

    if (!is_model_ready()) {
        send_http_response(sock, 503, "application/json",
            "{\"error\":{\"message\":\"Model not loaded\"}}", 38);
        return;
    }

    int resp_len = shmem_infer(prompt, max_tokens, resp_text, sizeof(resp_text));
    if (resp_len < 0) {
        send_http_response(sock, 500, "application/json",
            "{\"error\":{\"message\":\"Inference timeout\"}}", 37);
        return;
    }

    if (do_stream) {
        char header[512];
        int hlen = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n");
        send(sock, header, hlen, 0);

        char *word = strtok(resp_text, " \n");
        while (word) {
            char chunk[60000];
            json_escape(word, escaped, sizeof(escaped));
            int clen = snprintf(chunk, sizeof(chunk),
                "{\"id\":\"chatcmpl-%d\",\"object\":\"chat.completion.chunk\","
                "\"choices\":[{\"delta\":{\"content\":\"%s \"},"
                "\"index\":0,\"finish_reason\":null}]}",
                g_cmd_id, escaped);
            send_sse_chunk(sock, chunk, clen);
            word = strtok(NULL, " \n");
            Sleep(10);
        }
        char final[256];
        int flen = snprintf(final, sizeof(final),
            "{\"id\":\"chatcmpl-%d\",\"object\":\"chat.completion.chunk\","
            "\"choices\":[{\"delta\":{},\"index\":0,"
            "\"finish_reason\":\"stop\"}]}", g_cmd_id);
        send_sse_chunk(sock, final, flen);
        send_sse_done(sock);
    } else {
        json_escape(resp_text, escaped, sizeof(escaped));
        char response[128000];
        int rlen = snprintf(response, sizeof(response),
            "{\n"
            "  \"id\": \"chatcmpl-%d\",\n"
            "  \"object\": \"chat.completion\",\n"
            "  \"created\": %ld,\n"
            "  \"model\": \"%s\",\n"
            "  \"choices\": [\n"
            "    {\n"
            "      \"index\": 0,\n"
            "      \"message\": {\n"
            "        \"role\": \"assistant\",\n"
            "        \"content\": \"%s\"\n"
            "      },\n"
            "      \"finish_reason\": \"stop\"\n"
            "    }\n"
            "  ],\n"
            "  \"usage\": {\n"
            "    \"prompt_tokens\": %d,\n"
            "    \"completion_tokens\": %d,\n"
            "    \"total_tokens\": %d\n"
            "  }\n"
            "}\n",
            g_cmd_id, time(NULL), g_models, escaped,
            j / 4, resp_len / 4, (j + resp_len) / 4);
        send_http_response(sock, 200, "application/json", response, rlen);
    }
}

// ─── HTTP Request Handler ──────────────────────────────────────────
static void handle_request(SOCKET sock, const char *method,
                           const char *path, const char *body) {
    if (strcmp(method, "OPTIONS") == 0) {
        send_http_response(sock, 204, "application/json", "", 0);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/v1/models") == 0) {
        handle_list_models(sock);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/v1/completions") == 0) {
        handle_completions(sock, body);
        return;
    }

    if (strcmp(method, "POST") == 0 && strcmp(path, "/v1/chat/completions") == 0) {
        handle_chat_completions(sock, body);
        return;
    }

    if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
        int model_ok = is_model_ready();
        char body[256];
        int len = snprintf(body, sizeof(body),
            "{\"status\":\"ok\",\"model_loaded\":%s,\"model\":\"%s\"}",
            model_ok ? "true" : "false", g_models);
        send_http_response(sock, 200, "application/json", body, len);
        return;
    }

    send_http_response(sock, 404, "application/json",
        "{\"error\":{\"message\":\"Not found\"}}", 30);
}

// ─── Connection Handler Thread ────────────────────────────────────
static DWORD WINAPI handle_connection(LPVOID param) {
    SOCKET sock = (SOCKET)(intptr_t)param;
    char buffer[65536];
    char method[16], path[256];
    int total = 0;
    int content_length = 0;
    int header_end = -1;

    while (total < (int)sizeof(buffer) - 1) {
        int n = recv(sock, buffer + total, (int)sizeof(buffer) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        buffer[total] = '\0';

        char *hdr_end = strstr(buffer, "\r\n\r\n");
        if (hdr_end && header_end < 0) {
            header_end = (int)(hdr_end - buffer) + 4;
            char *cl = strstr(buffer, "Content-Length:");
            if (cl) content_length = atoi(cl + 15);
        }

        if (header_end >= 0 && content_length > 0) {
            if (total >= header_end + content_length) break;
        } else if (header_end >= 0 && content_length == 0) {
            break;
        }
    }

    if (total <= 0) {
        closesocket(sock);
        return 0;
    }

    buffer[total] = '\0';
    sscanf(buffer, "%15s %255s", method, path);

    const char *body = "";
    if (header_end >= 0 && header_end < total) {
        body = buffer + header_end;
    }

    fprintf(stderr, "[Server] %s %s (body=%d bytes)\n", method, path,
            content_length);

    handle_request(sock, method, path, body);

    shutdown(sock, SD_SEND);
    closesocket(sock);
    return 0;
}

// ─── Main: Start HTTP Server ───────────────────────────────────────
int main(int argc, char *argv[]) {
    int port = 8080;
    const char *host = "127.0.0.1";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host = argv[++i];
        else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc)
            strncpy(g_models, argv[++i], sizeof(g_models) - 1);
    }

    fprintf(stderr, "╔══════════════════════════════════════════╗\n");
    fprintf(stderr, "║  RawrXD OpenAI-Compatible Server          ║\n");
    fprintf(stderr, "║  http://%s:%-29d   ║\n", host, port);
    fprintf(stderr, "╚══════════════════════════════════════════╝\n");

    if (!shmem_connect()) {
        fprintf(stderr, "[Server] FATAL: Cannot connect to RawrXD engine.\n");
        fprintf(stderr, "[Server] Make sure SovereignOrchestrator is running.\n");
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[Server] WSAStartup failed\n");
        return 1;
    }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "[Server] socket() failed\n");
        return 1;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "[Server] bind() failed: %d\n", WSAGetLastError());
        closesocket(listen_sock);
        return 1;
    }

    if (listen(listen_sock, 16) == SOCKET_ERROR) {
        fprintf(stderr, "[Server] listen() failed\n");
        closesocket(listen_sock);
        return 1;
    }

    fprintf(stderr, "[Server] Listening on http://%s:%d\n", host, port);
    fprintf(stderr, "[Server] Endpoints:\n");
    fprintf(stderr, "  GET  /v1/models           — List models\n");
    fprintf(stderr, "  POST /v1/completions       — Text/FIM completion\n");
    fprintf(stderr, "  POST /v1/chat/completions  — Chat completion\n");
    fprintf(stderr, "  GET  /health               — Health check\n");
    fprintf(stderr, "[Server] Ready! Connect your editor to this endpoint.\n\n");

    while (1) {
        SOCKET client = accept(listen_sock, NULL, NULL);
        if (client == INVALID_SOCKET) continue;

        HANDLE hThread = CreateThread(NULL, 0, handle_connection,
            (LPVOID)(intptr_t)client, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        } else {
            closesocket(client);
        }
    }

    closesocket(listen_sock);
    WSACleanup();
    return 0;
}
