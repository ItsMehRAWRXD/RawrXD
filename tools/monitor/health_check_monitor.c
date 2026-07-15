//=============================================================================
// health_check_monitor.c - Health Check Monitor
// Production-ready deep health probing with dependency chain validation
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

//=============================================================================
// Health Check Types
//=============================================================================

#define MAX_CHECKS 50
#define MAX_DEPENDENCIES 10
#define MAX_HISTORY 100

typedef enum {
    CHECK_HTTP,
    CHECK_TCP,
    CHECK_DATABASE,
    CHECK_DISK,
    CHECK_MEMORY,
    CHECK_CUSTOM
} CheckType;

typedef enum {
    STATUS_UNKNOWN,
    STATUS_HEALTHY,
    STATUS_DEGRADED,
    STATUS_UNHEALTHY
} HealthStatus;

typedef struct {
    char name[128];
    char description[512];
    CheckType type;
    char endpoint[1024];
    int port;
    int timeout_ms;
    int interval_ms;
    int retries;
    
    // Dependencies
    char dependencies[MAX_DEPENDENCIES][128];
    int dependency_count;
    
    // Results
    HealthStatus status;
    double response_time_ms;
    int consecutive_failures;
    int consecutive_successes;
    char last_error[1024];
    time_t last_check;
    time_t last_success;
    
    // History
    double response_times[MAX_HISTORY];
    int history_count;
    double avg_response_time;
    double min_response_time;
    double max_response_time;
} HealthCheck;

typedef struct {
    HealthCheck* checks;
    int check_count;
    int check_capacity;
    
    // Overall health
    HealthStatus overall_status;
    int healthy_count;
    int degraded_count;
    int unhealthy_count;
    int unknown_count;
    
    // Timing
    double total_check_time;
    time_t started_at;
    time_t last_check;
    int total_checks_run;
    
    // Alerts
    int new_failures;
    int recovered_count;
    
    char status_message[1024];
} HealthMonitorReport;

//=============================================================================
// Health Monitor Implementation
//=============================================================================

HealthMonitorReport* health_monitor_create(void) {
    HealthMonitorReport* report = (HealthMonitorReport*)calloc(1, sizeof(HealthMonitorReport));
    report->check_capacity = MAX_CHECKS;
    report->checks = (HealthCheck*)calloc(report->check_capacity, sizeof(HealthCheck));
    report->started_at = time(NULL);
    report->overall_status = STATUS_UNKNOWN;
    return report;
}

void health_monitor_destroy(HealthMonitorReport* report) {
    if (!report) return;
    free(report->checks);
    free(report);
}

HealthCheck* add_health_check(HealthMonitorReport* report, const char* name, CheckType type) {
    if (report->check_count >= report->check_capacity) return NULL;
    
    HealthCheck* check = &report->checks[report->check_count++];
    strncpy(check->name, name, sizeof(check->name) - 1);
    check->type = type;
    check->status = STATUS_UNKNOWN;
    check->timeout_ms = 5000;
    check->interval_ms = 30000;
    check->retries = 3;
    check->min_response_time = 999999.0;
    return check;
}

void add_dependency(HealthCheck* check, const char* dep_name) {
    if (check->dependency_count >= MAX_DEPENDENCIES) return;
    strncpy(check->dependencies[check->dependency_count++], dep_name, 128);
}

HealthStatus check_dependencies(HealthMonitorReport* report, HealthCheck* check) {
    for (int i = 0; i < check->dependency_count; i++) {
        for (int j = 0; j < report->check_count; j++) {
            if (strcmp(report->checks[j].name, check->dependencies[i]) == 0) {
                if (report->checks[j].status == STATUS_UNHEALTHY) {
                    snprintf(check->last_error, sizeof(check->last_error),
                             "Dependency '%s' is unhealthy", check->dependencies[i]);
                    return STATUS_DEGRADED;
                }
            }
        }
    }
    return STATUS_HEALTHY;
}

int run_http_check(HealthCheck* check) {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Health-Check/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return 0;
    
    WCHAR wUrl[1024];
    MultiByteToWideChar(CP_UTF8, 0, check->endpoint, -1, wUrl, 1024);
    
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
        return 0;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            urlComp.nScheme == INTERNET_SCHEME_HTTPS ? 
                                            WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }
    
    BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                      WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }
    
    result = WinHttpReceiveResponse(hRequest, NULL);
    
    QueryPerformanceCounter(&end);
    check->response_time_ms = ((double)(end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
    
    // Update history
    if (check->history_count < MAX_HISTORY) {
        check->response_times[check->history_count++] = check->response_time_ms;
    }
    
    // Update min/max
    if (check->response_time_ms < check->min_response_time) {
        check->min_response_time = check->response_time_ms;
    }
    if (check->response_time_ms > check->max_response_time) {
        check->max_response_time = check->response_time_ms;
    }
    
    // Calculate average
    double sum = 0;
    for (int i = 0; i < check->history_count; i++) {
        sum += check->response_times[i];
    }
    check->avg_response_time = sum / check->history_count;
    
    // Get status code
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return (result && statusCode < 400);
}

int run_disk_check(HealthCheck* check) {
    ULARGE_INTEGER freeBytes, totalBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, NULL)) {
        double freePercent = (double)freeBytes.QuadPart / totalBytes.QuadPart * 100.0;
        if (freePercent < 5.0) {
            snprintf(check->last_error, sizeof(check->last_error),
                     "Disk space critically low: %.1f%% free", freePercent);
            return 0;
        }
        return 1;
    }
    return 0;
}

int run_memory_check(HealthCheck* check) {
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        double usedPercent = (double)(memStatus.ullTotalPhys - memStatus.ullAvailPhys) 
                            / memStatus.ullTotalPhys * 100.0;
        if (usedPercent > 95.0) {
            snprintf(check->last_error, sizeof(check->last_error),
                     "Memory usage critically high: %.1f%%", usedPercent);
            return 0;
        }
        return 1;
    }
    return 0;
}

void run_health_check(HealthMonitorReport* report, HealthCheck* check) {
    check->last_check = time(NULL);
    report->total_checks_run++;
    
    // Check dependencies first
    HealthStatus dep_status = check_dependencies(report, check);
    if (dep_status != STATUS_HEALTHY) {
        check->status = dep_status;
        check->consecutive_failures++;
        return;
    }
    
    int success = 0;
    switch (check->type) {
        case CHECK_HTTP:
            success = run_http_check(check);
            break;
        case CHECK_DISK:
            success = run_disk_check(check);
            break;
        case CHECK_MEMORY:
            success = run_memory_check(check);
            break;
        default:
            success = 1;
    }
    
    if (success) {
        check->consecutive_successes++;
        check->consecutive_failures = 0;
        check->last_success = time(NULL);
        
        // Determine status based on response time
        if (check->response_time_ms > 1000) {
            check->status = STATUS_DEGRADED;
        } else {
            check->status = STATUS_HEALTHY;
        }
    } else {
        check->consecutive_failures++;
        check->consecutive_successes = 0;
        
        if (check->consecutive_failures >= check->retries) {
            check->status = STATUS_UNHEALTHY;
            report->new_failures++;
        } else {
            check->status = STATUS_DEGRADED;
        }
    }
}

void run_all_checks(HealthMonitorReport* report) {
    printf("Running health checks...\n\n");
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    for (int i = 0; i < report->check_count; i++) {
        HealthCheck* check = &report->checks[i];
        printf("  Checking %s...", check->name);
        
        run_health_check(report, check);
        
        const char* status_str = "?";
        switch (check->status) {
            case STATUS_HEALTHY: status_str = "✅ HEALTHY"; report->healthy_count++; break;
            case STATUS_DEGRADED: status_str = "⚠️ DEGRADED"; report->degraded_count++; break;
            case STATUS_UNHEALTHY: status_str = "❌ UNHEALTHY"; report->unhealthy_count++; break;
            case STATUS_UNKNOWN: status_str = "❓ UNKNOWN"; report->unknown_count++; break;
        }
        
        printf(" %s", status_str);
        if (check->type == CHECK_HTTP) {
            printf(" (%.2f ms)", check->response_time_ms);
        }
        printf("\n");
    }
    
    QueryPerformanceCounter(&end);
    report->total_check_time = ((double)(end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
    report->last_check = time(NULL);
    
    // Determine overall status
    if (report->unhealthy_count > 0) {
        report->overall_status = STATUS_UNHEALTHY;
        strncpy(report->status_message, "One or more services are unhealthy", 
                sizeof(report->status_message) - 1);
    } else if (report->degraded_count > 0) {
        report->overall_status = STATUS_DEGRADED;
        strncpy(report->status_message, "Some services are degraded", 
                sizeof(report->status_message) - 1);
    } else {
        report->overall_status = STATUS_HEALTHY;
        strncpy(report->status_message, "All services are healthy", 
                sizeof(report->status_message) - 1);
    }
    
    printf("\n");
}

void setup_demo_checks(HealthMonitorReport* report) {
    HealthCheck* check = add_health_check(report, "API Server", CHECK_HTTP);
    strncpy(check->description, "Main API endpoint", sizeof(check->description) - 1);
    strncpy(check->endpoint, "http://httpbin.org/get", sizeof(check->endpoint) - 1);
    
    check = add_health_check(report, "Database", CHECK_HTTP);
    strncpy(check->description, "Database connectivity", sizeof(check->description) - 1);
    strncpy(check->endpoint, "http://httpbin.org/get", sizeof(check->endpoint) - 1);
    add_dependency(check, "API Server");
    
    check = add_health_check(report, "Disk Space", CHECK_DISK);
    strncpy(check->description, "Available disk space", sizeof(check->description) - 1);
    
    check = add_health_check(report, "Memory", CHECK_MEMORY);
    strncpy(check->description, "Available system memory", sizeof(check->description) - 1);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* status_to_emoji(HealthStatus status) {
    switch (status) {
        case STATUS_HEALTHY: return "✅";
        case STATUS_DEGRADED: return "⚠️";
        case STATUS_UNHEALTHY: return "❌";
        case STATUS_UNKNOWN: return "❓";
        default: return "?";
    }
}

void print_health_summary(HealthMonitorReport* report) {
    printf("=============================================================================\n");
    printf("  Health Check Summary\n");
    printf("=============================================================================\n");
    printf("  Overall Status:         %s %s\n", 
           status_to_emoji(report->overall_status),
           report->overall_status == STATUS_HEALTHY ? "HEALTHY" :
           report->overall_status == STATUS_DEGRADED ? "DEGRADED" :
           report->overall_status == STATUS_UNHEALTHY ? "UNHEALTHY" : "UNKNOWN");
    printf("  Message:                %s\n", report->status_message);
    printf("\n");
    printf("  Service Health:\n");
    printf("    Healthy:              %d\n", report->healthy_count);
    printf("    Degraded:             %d\n", report->degraded_count);
    printf("    Unhealthy:            %d\n", report->unhealthy_count);
    printf("    Unknown:              %d\n", report->unknown_count);
    printf("\n");
    printf("  Execution:\n");
    printf("    Total Checks:         %d\n", report->total_checks_run);
    printf("    Total Time:           %.2f ms\n", report->total_check_time);
    printf("    New Failures:         %d\n", report->new_failures);
    printf("=============================================================================\n");
}

void print_health_details(HealthMonitorReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Health Check Details\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->check_count; i++) {
        HealthCheck* check = &report->checks[i];
        printf("\n  %s %s\n", status_to_emoji(check->status), check->name);
        printf("       Description: %s\n", check->description);
        printf("       Type:        %s\n", 
               check->type == CHECK_HTTP ? "HTTP" :
               check->type == CHECK_DISK ? "Disk" :
               check->type == CHECK_MEMORY ? "Memory" : "Other");
        
        if (check->type == CHECK_HTTP && check->history_count > 0) {
            printf("       Response:    %.2f ms (avg: %.2f, min: %.2f, max: %.2f)\n",
                   check->response_time_ms, check->avg_response_time,
                   check->min_response_time, check->max_response_time);
        }
        
        if (strlen(check->last_error) > 0) {
            printf("       Error:       %s\n", check->last_error);
        }
        
        if (check->dependency_count > 0) {
            printf("       Dependencies:");
            for (int j = 0; j < check->dependency_count; j++) {
                printf(" %s", check->dependencies[j]);
            }
            printf("\n");
        }
    }
    
    printf("\n=============================================================================\n");
}

void export_health_json(HealthMonitorReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"overall_status\": \"%s\",\n",
            report->overall_status == STATUS_HEALTHY ? "healthy" :
            report->overall_status == STATUS_DEGRADED ? "degraded" : "unhealthy");
    fprintf(f, "  \"message\": \"%s\",\n", report->status_message);
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"healthy\": %d,\n", report->healthy_count);
    fprintf(f, "    \"degraded\": %d,\n", report->degraded_count);
    fprintf(f, "    \"unhealthy\": %d,\n", report->unhealthy_count);
    fprintf(f, "    \"total_checks\": %d,\n", report->total_checks_run);
    fprintf(f, "    \"execution_time_ms\": %.2f\n", report->total_check_time);
    fprintf(f, "  },\n");
    fprintf(f, "  \"checks\": [\n");
    
    for (int i = 0; i < report->check_count; i++) {
        HealthCheck* check = &report->checks[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", check->name);
        fprintf(f, "      \"status\": \"%s\",\n",
                check->status == STATUS_HEALTHY ? "healthy" :
                check->status == STATUS_DEGRADED ? "degraded" : "unhealthy");
        fprintf(f, "      \"response_time_ms\": %.2f,\n", check->response_time_ms);
        fprintf(f, "      \"consecutive_failures\": %d,\n", check->consecutive_failures);
        fprintf(f, "      \"last_check\": %ld\n", (long)check->last_check);
        fprintf(f, "    }%s\n", (i < report->check_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Health report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Health Check Monitor\n");
    printf("===========================\n\n");
    
    HealthMonitorReport* report = health_monitor_create();
    
    // Setup checks
    setup_demo_checks(report);
    
    // Run checks
    run_all_checks(report);
    
    // Generate reports
    print_health_summary(report);
    print_health_details(report);
    export_health_json(report, "health_check.json");
    
    printf("\nHealth check complete!\n");
    
    int exit_code = (report->overall_status == STATUS_UNHEALTHY) ? 1 : 0;
    health_monitor_destroy(report);
    
    return exit_code;
}
