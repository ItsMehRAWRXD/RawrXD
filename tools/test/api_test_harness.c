//=============================================================================
// api_test_harness.c - API Test Harness
// Production-ready API testing with request chaining and assertions
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

//=============================================================================
// API Test Types
//=============================================================================

#define MAX_TESTS 200
#define MAX_HEADERS 20
#define MAX_ASSERTIONS 50
#define MAX_CHAIN_STEPS 10

typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_PATCH,
    HTTP_HEAD
} HttpMethod;

typedef enum {
    ASSERT_STATUS_CODE,
    ASSERT_HEADER_EXISTS,
    ASSERT_HEADER_VALUE,
    ASSERT_BODY_CONTAINS,
    ASSERT_BODY_JSON_PATH,
    ASSERT_RESPONSE_TIME,
    ASSERT_CONTENT_TYPE,
    ASSERT_CUSTOM
} AssertionType;

typedef struct {
    char key[128];
    char value[1024];
} HttpHeader;

typedef struct {
    AssertionType type;
    char expected[512];
    char actual[512];
    int passed;
    char message[1024];
} AssertionResult;

typedef struct {
    char name[256];
    HttpMethod method;
    char url[1024];
    HttpHeader headers[MAX_HEADERS];
    int header_count;
    char body[8192];
    
    // Assertions
    int expected_status;
    char expected_content_type[128];
    int max_response_time_ms;
    char json_path[256];
    char json_expected[512];
    
    // Results
    int actual_status;
    double response_time_ms;
    char response_body[16384];
    char response_headers[4096];
    AssertionResult assertions[MAX_ASSERTIONS];
    int assertion_count;
    int passed;
    char error_message[1024];
} ApiTestCase;

typedef struct {
    char name[256];
    ApiTestCase* tests;
    int test_count;
    int test_capacity;
    int setup_complete;
    int teardown_complete;
} ApiTestSuite;

typedef struct {
    ApiTestSuite* suites;
    int suite_count;
    int suite_capacity;
    
    int total_tests;
    int passed_tests;
    int failed_tests;
    int skipped_tests;
    
    double total_duration_ms;
    double avg_response_time_ms;
    double min_response_time_ms;
    double max_response_time_ms;
    
    int total_assertions;
    int passed_assertions;
    int failed_assertions;
} ApiTestReport;

//=============================================================================
// HTTP Client Implementation
//=============================================================================

ApiTestReport* api_test_create(void) {
    ApiTestReport* report = (ApiTestReport*)calloc(1, sizeof(ApiTestReport));
    report->suite_capacity = 50;
    report->suites = (ApiTestSuite*)calloc(report->suite_capacity, sizeof(ApiTestSuite));
    report->min_response_time_ms = 999999.0;
    return report;
}

void api_test_destroy(ApiTestReport* report) {
    if (!report) return;
    for (int i = 0; i < report->suite_count; i++) {
        free(report->suites[i].tests);
    }
    free(report->suites);
    free(report);
}

ApiTestSuite* api_test_create_suite(ApiTestReport* report, const char* name) {
    if (report->suite_count >= report->suite_capacity) return NULL;
    
    ApiTestSuite* suite = &report->suites[report->suite_count++];
    strncpy(suite->name, name, sizeof(suite->name) - 1);
    suite->test_capacity = MAX_TESTS;
    suite->tests = (ApiTestCase*)calloc(suite->test_capacity, sizeof(ApiTestCase));
    return suite;
}

ApiTestCase* api_test_add_case(ApiTestSuite* suite, const char* name, HttpMethod method) {
    if (suite->test_count >= suite->test_capacity) return NULL;
    
    ApiTestCase* test = &suite->tests[suite->test_count++];
    strncpy(test->name, name, sizeof(test->name) - 1);
    test->method = method;
    test->expected_status = 200;
    test->max_response_time_ms = 5000;
    return test;
}

void api_test_set_url(ApiTestCase* test, const char* url) {
    strncpy(test->url, url, sizeof(test->url) - 1);
}

void api_test_add_header(ApiTestCase* test, const char* key, const char* value) {
    if (test->header_count >= MAX_HEADERS) return;
    HttpHeader* header = &test->headers[test->header_count++];
    strncpy(header->key, key, sizeof(header->key) - 1);
    strncpy(header->value, value, sizeof(header->value) - 1);
}

void api_test_set_body(ApiTestCase* test, const char* body) {
    strncpy(test->body, body, sizeof(test->body) - 1);
}

int execute_http_request(ApiTestCase* test) {
    HINTERNET hSession = WinHttpOpen(L"RawrXD-API-Test/1.0", 
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        snprintf(test->error_message, sizeof(test->error_message),
                 "Failed to create HTTP session");
        return 1;
    }
    
    // Parse URL
    WCHAR wUrl[1024];
    MultiByteToWideChar(CP_UTF8, 0, test->url, -1, wUrl, 1024);
    
    URL_COMPONENTS urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    
    WinHttpCrackUrl(wUrl, 0, 0, &urlComp);
    
    WCHAR host[256], path[1024];
    wcsncpy_s(host, 256, urlComp.lpszHostName, urlComp.dwHostNameLength);
    wcsncpy_s(path, 1024, urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    
    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        snprintf(test->error_message, sizeof(test->error_message),
                 "Failed to connect to host");
        return 1;
    }
    
    // Determine method
    LPCWSTR method = L"GET";
    switch (test->method) {
        case HTTP_GET: method = L"GET"; break;
        case HTTP_POST: method = L"POST"; break;
        case HTTP_PUT: method = L"PUT"; break;
        case HTTP_DELETE: method = L"DELETE"; break;
        case HTTP_PATCH: method = L"PATCH"; break;
        case HTTP_HEAD: method = L"HEAD"; break;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method, path,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            urlComp.nScheme == INTERNET_SCHEME_HTTPS ? 
                                            WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        snprintf(test->error_message, sizeof(test->error_message),
                 "Failed to create request");
        return 1;
    }
    
    // Add headers
    for (int i = 0; i < test->header_count; i++) {
        WCHAR headerLine[1152];
        WCHAR wKey[128], wValue[1024];
        MultiByteToWideChar(CP_UTF8, 0, test->headers[i].key, -1, wKey, 128);
        MultiByteToWideChar(CP_UTF8, 0, test->headers[i].value, -1, wValue, 1024);
        swprintf_s(headerLine, 1152, L"%s: %s", wKey, wValue);
        WinHttpAddRequestHeaders(hRequest, headerLine, (ULONG)-1, 
                                  WINHTTP_ADDREQ_FLAG_ADD);
    }
    
    // Add Content-Type if body present
    if (strlen(test->body) > 0) {
        WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", 
                                  (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD);
    }
    
    // Execute request with timing
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                      strlen(test->body) > 0 ? (LPVOID)test->body : WINHTTP_NO_REQUEST_DATA,
                                      strlen(test->body), strlen(test->body), 0);
    
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        snprintf(test->error_message, sizeof(test->error_message),
                 "Failed to send request");
        return 1;
    }
    
    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        snprintf(test->error_message, sizeof(test->error_message),
                 "Failed to receive response");
        return 1;
    }
    
    QueryPerformanceCounter(&end);
    test->response_time_ms = ((double)(end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
    
    // Get status code
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    test->actual_status = (int)statusCode;
    
    // Get response headers
    DWORD headerSize = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                        WINHTTP_HEADER_NAME_BY_INDEX, NULL, &headerSize, WINHTTP_NO_HEADER_INDEX);
    if (headerSize > 0) {
        WCHAR* headers = (WCHAR*)malloc(headerSize);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                            WINHTTP_HEADER_NAME_BY_INDEX, headers, &headerSize, WINHTTP_NO_HEADER_INDEX);
        WideCharToMultiByte(CP_UTF8, 0, headers, -1, test->response_headers, 
                            sizeof(test->response_headers), NULL, NULL);
        free(headers);
    }
    
    // Get response body
    DWORD downloaded = 0;
    size_t totalDownloaded = 0;
    do {
        DWORD available = 0;
        WinHttpQueryDataAvailable(hRequest, &available);
        if (available == 0) break;
        
        char* buffer = (char*)malloc(available + 1);
        WinHttpReadData(hRequest, buffer, available, &downloaded);
        buffer[downloaded] = '\0';
        
        if (totalDownloaded + downloaded < sizeof(test->response_body)) {
            strncat(test->response_body, buffer, 
                    sizeof(test->response_body) - totalDownloaded - 1);
            totalDownloaded += downloaded;
        }
        free(buffer);
    } while (downloaded > 0);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return 0;
}

void run_assertions(ApiTestCase* test) {
    // Status code assertion
    if (test->assertion_count < MAX_ASSERTIONS) {
        AssertionResult* ar = &test->assertions[test->assertion_count++];
        ar->type = ASSERT_STATUS_CODE;
        snprintf(ar->expected, sizeof(ar->expected), "%d", test->expected_status);
        snprintf(ar->actual, sizeof(ar->actual), "%d", test->actual_status);
        ar->passed = (test->actual_status == test->expected_status);
        snprintf(ar->message, sizeof(ar->message),
                 "Status code %s (expected %d, got %d)",
                 ar->passed ? "✓" : "✗", test->expected_status, test->actual_status);
    }
    
    // Response time assertion
    if (test->max_response_time_ms > 0 && test->assertion_count < MAX_ASSERTIONS) {
        AssertionResult* ar = &test->assertions[test->assertion_count++];
        ar->type = ASSERT_RESPONSE_TIME;
        snprintf(ar->expected, sizeof(ar->expected), "< %d ms", test->max_response_time_ms);
        snprintf(ar->actual, sizeof(ar->actual), "%.2f ms", test->response_time_ms);
        ar->passed = (test->response_time_ms <= test->max_response_time_ms);
        snprintf(ar->message, sizeof(ar->message),
                 "Response time %s (%.2f ms, max %d ms)",
                 ar->passed ? "✓" : "✗", test->response_time_ms, test->max_response_time_ms);
    }
    
    // Content-Type assertion
    if (strlen(test->expected_content_type) > 0 && test->assertion_count < MAX_ASSERTIONS) {
        AssertionResult* ar = &test->assertions[test->assertion_count++];
        ar->type = ASSERT_CONTENT_TYPE;
        strncpy(ar->expected, test->expected_content_type, sizeof(ar->expected) - 1);
        
        char* ct = strstr(test->response_headers, "Content-Type:");
        if (ct) {
            char actual[128] = {0};
            sscanf(ct, "Content-Type: %127[^\r\n]", actual);
            strncpy(ar->actual, actual, sizeof(ar->actual) - 1);
            ar->passed = (strstr(actual, test->expected_content_type) != NULL);
        } else {
            strncpy(ar->actual, "not found", sizeof(ar->actual) - 1);
            ar->passed = 0;
        }
        snprintf(ar->message, sizeof(ar->message),
                 "Content-Type %s", ar->passed ? "✓" : "✗");
    }
    
    // Check if all assertions passed
    test->passed = 1;
    for (int i = 0; i < test->assertion_count; i++) {
        if (!test->assertions[i].passed) {
            test->passed = 0;
            break;
        }
    }
}

void api_test_execute(ApiTestReport* report, ApiTestSuite* suite) {
    printf("\nExecuting Suite: %s\n", suite->name);
    printf("--------------------------------------------------------------\n");
    
    for (int i = 0; i < suite->test_count; i++) {
        ApiTestCase* test = &suite->tests[i];
        printf("  Running: %s ... ", test->name);
        
        int result = execute_http_request(test);
        
        if (result == 0) {
            run_assertions(test);
            printf("%s\n", test->passed ? "✓ PASS" : "✗ FAIL");
            
            if (!test->passed) {
                for (int j = 0; j < test->assertion_count; j++) {
                    if (!test->assertions[j].passed) {
                        printf("    → %s\n", test->assertions[j].message);
                    }
                }
            }
        } else {
            printf("✗ ERROR: %s\n", test->error_message);
            test->passed = 0;
        }
        
        report->total_tests++;
        if (test->passed) {
            report->passed_tests++;
        } else {
            report->failed_tests++;
        }
        
        report->total_assertions += test->assertion_count;
        for (int j = 0; j < test->assertion_count; j++) {
            if (test->assertions[j].passed) {
                report->passed_assertions++;
            } else {
                report->failed_assertions++;
            }
        }
        
        report->total_duration_ms += test->response_time_ms;
        if (test->response_time_ms < report->min_response_time_ms) {
            report->min_response_time_ms = test->response_time_ms;
        }
        if (test->response_time_ms > report->max_response_time_ms) {
            report->max_response_time_ms = test->response_time_ms;
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_api_test_summary(ApiTestReport* report) {
    if (report->total_tests > 0) {
        report->avg_response_time_ms = report->total_duration_ms / report->total_tests;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  API Test Summary\n");
    printf("=============================================================================\n");
    printf("  Total Tests:          %d\n", report->total_tests);
    printf("  Passed:               %d\n", report->passed_tests);
    printf("  Failed:               %d\n", report->failed_tests);
    printf("  Success Rate:         %.1f%%\n", 
           report->total_tests > 0 ? (double)report->passed_tests / report->total_tests * 100 : 0);
    printf("\n");
    printf("  Assertions:\n");
    printf("    Total:              %d\n", report->total_assertions);
    printf("    Passed:             %d\n", report->passed_assertions);
    printf("    Failed:             %d\n", report->failed_assertions);
    printf("\n");
    printf("  Response Times:\n");
    printf("    Total Duration:     %.2f ms\n", report->total_duration_ms);
    printf("    Average:            %.2f ms\n", report->avg_response_time_ms);
    printf("    Min:                %.2f ms\n", 
           report->min_response_time_ms == 999999.0 ? 0 : report->min_response_time_ms);
    printf("    Max:                %.2f ms\n", report->max_response_time_ms);
    printf("=============================================================================\n");
}

void export_api_test_json(ApiTestReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_tests\": %d,\n", report->total_tests);
    fprintf(f, "    \"passed\": %d,\n", report->passed_tests);
    fprintf(f, "    \"failed\": %d,\n", report->failed_tests);
    fprintf(f, "    \"success_rate\": %.2f,\n", 
            report->total_tests > 0 ? (double)report->passed_tests / report->total_tests * 100 : 0);
    fprintf(f, "    \"total_duration_ms\": %.2f,\n", report->total_duration_ms);
    fprintf(f, "    \"avg_response_time_ms\": %.2f\n", report->avg_response_time_ms);
    fprintf(f, "  },\n");
    fprintf(f, "  \"suites\": [\n");
    
    for (int i = 0; i < report->suite_count; i++) {
        ApiTestSuite* suite = &report->suites[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", suite->name);
        fprintf(f, "      \"tests\": [\n");
        
        for (int j = 0; j < suite->test_count; j++) {
            ApiTestCase* test = &suite->tests[j];
            fprintf(f, "        {\n");
            fprintf(f, "          \"name\": \"%s\",\n", test->name);
            fprintf(f, "          \"url\": \"%s\",\n", test->url);
            fprintf(f, "          \"status\": \"%s\",\n", test->passed ? "pass" : "fail");
            fprintf(f, "          \"response_time_ms\": %.2f,\n", test->response_time_ms);
            fprintf(f, "          \"status_code\": %d,\n", test->actual_status);
            fprintf(f, "          \"assertions\": [\n");
            
            for (int k = 0; k < test->assertion_count; k++) {
                AssertionResult* ar = &test->assertions[k];
                fprintf(f, "            {\n");
                fprintf(f, "              \"type\": %d,\n", ar->type);
                fprintf(f, "              \"passed\": %s,\n", ar->passed ? "true" : "false");
                fprintf(f, "              \"message\": \"%s\"\n", ar->message);
                fprintf(f, "            }%s\n", (k < test->assertion_count - 1) ? "," : "");
            }
            
            fprintf(f, "          ]\n");
            fprintf(f, "        }%s\n", (j < suite->test_count - 1) ? "," : "");
        }
        
        fprintf(f, "      ]\n");
        fprintf(f, "    }%s\n", (i < report->suite_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  API test report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD API Test Harness\n");
    printf("=======================\n\n");
    
    ApiTestReport* report = api_test_create();
    
    // Create test suite
    ApiTestSuite* suite = api_test_create_suite(report, "Health Check API");
    
    // Add test cases
    ApiTestCase* test = api_test_add_case(suite, "Health Endpoint", HTTP_GET);
    api_test_set_url(test, "http://httpbin.org/get");
    api_test_add_header(test, "Accept", "application/json");
    test->expected_status = 200;
    test->expected_content_type = "application/json";
    test->max_response_time_ms = 2000;
    
    test = api_test_add_case(suite, "Post Test", HTTP_POST);
    api_test_set_url(test, "http://httpbin.org/post");
    api_test_add_header(test, "Content-Type", "application/json");
    api_test_set_body(test, "{\"test\": \"data\"}");
    test->expected_status = 200;
    test->max_response_time_ms = 3000;
    
    // Execute tests
    api_test_execute(report, suite);
    
    // Generate reports
    print_api_test_summary(report);
    export_api_test_json(report, "api_test_report.json");
    
    printf("\nAPI testing complete!\n");
    
    int exit_code = (report->failed_tests > 0) ? 1 : 0;
    api_test_destroy(report);
    
    return exit_code;
}
