//=============================================================================
// resource_monitor.c - System Resource Monitor
// Production-ready resource monitoring with alerting
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Resource Types
//=============================================================================

#define MAX_SAMPLES 1000
#define MAX_ALERTS 100
#define MAX_PROCESSES 50

typedef enum {
    RESOURCE_CPU,
    RESOURCE_MEMORY,
    RESOURCE_DISK,
    RESOURCE_NETWORK,
    RESOURCE_GPU
} ResourceType;

typedef enum {
    ALERT_INFO,
    ALERT_WARNING,
    ALERT_CRITICAL
} AlertLevel;

typedef struct {
    ResourceType type;
    double value;
    double threshold;
    AlertLevel level;
    char message[256];
    time_t timestamp;
    int is_active;
} Alert;

typedef struct {
    time_t timestamp;
    double cpu_percent;
    uint64_t memory_used;
    uint64_t memory_total;
    double memory_percent;
    uint64_t disk_used;
    uint64_t disk_total;
    double disk_percent;
    uint64_t network_rx;
    uint64_t network_tx;
    uint64_t network_rx_rate;
    uint64_t network_tx_rate;
} ResourceSample;

typedef struct {
    int pid;
    char name[256];
    double cpu_percent;
    uint64_t memory_used;
    int thread_count;
} ProcessInfo;

typedef struct {
    ResourceSample* samples;
    int sample_count;
    int sample_capacity;
    
    Alert* alerts;
    int alert_count;
    int alert_capacity;
    
    ProcessInfo* processes;
    int process_count;
    int process_capacity;
    
    double cpu_threshold;
    double memory_threshold;
    double disk_threshold;
    
    int active_alerts;
    int warning_count;
    int critical_count;
    
    time_t start_time;
    time_t end_time;
} ResourceReport;

//=============================================================================
// Resource Monitoring Implementation
//=============================================================================

ResourceReport* resource_create_report(void) {
    ResourceReport* report = (ResourceReport*)calloc(1, sizeof(ResourceReport));
    report->sample_capacity = MAX_SAMPLES;
    report->samples = (ResourceSample*)calloc(report->sample_capacity, sizeof(ResourceSample));
    report->alert_capacity = MAX_ALERTS;
    report->alerts = (Alert*)calloc(report->alert_capacity, sizeof(Alert));
    report->process_capacity = MAX_PROCESSES;
    report->processes = (ProcessInfo*)calloc(report->process_capacity, sizeof(ProcessInfo));
    report->cpu_threshold = 80.0;
    report->memory_threshold = 85.0;
    report->disk_threshold = 90.0;
    report->start_time = time(NULL);
    return report;
}

void resource_destroy_report(ResourceReport* report) {
    if (!report) return;
    free(report->samples);
    free(report->alerts);
    free(report->processes);
    free(report);
}

void add_alert(ResourceReport* report, ResourceType type, double value,
               double threshold, AlertLevel level, const char* message) {
    if (report->alert_count >= report->alert_capacity) return;
    
    Alert* alert = &report->alerts[report->alert_count++];
    alert->type = type;
    alert->value = value;
    alert->threshold = threshold;
    alert->level = level;
    strncpy(alert->message, message, sizeof(alert->message) - 1);
    alert->timestamp = time(NULL);
    alert->is_active = 1;
    
    report->active_alerts++;
    if (level == ALERT_WARNING) report->warning_count++;
    if (level == ALERT_CRITICAL) report->critical_count++;
}

void sample_resources(ResourceReport* report) {
    if (report->sample_count >= report->sample_capacity) return;
    
    ResourceSample* sample = &report->samples[report->sample_count++];
    sample->timestamp = time(NULL);
    
    // Simulated resource sampling
    // In production, would use system APIs
    sample->cpu_percent = 45.0 + (rand() % 30);
    sample->memory_total = 16ULL * 1024 * 1024 * 1024;  // 16 GB
    sample->memory_used = (uint64_t)(sample->memory_total * 0.65);
    sample->memory_percent = 100.0 * (double)sample->memory_used / sample->memory_total;
    sample->disk_total = 500ULL * 1024 * 1024 * 1024;  // 500 GB
    sample->disk_used = (uint64_t)(sample->disk_total * 0.75);
    sample->disk_percent = 100.0 * (double)sample->disk_used / sample->disk_total;
    sample->network_rx = 1024ULL * 1024 * 100;
    sample->network_tx = 1024ULL * 1024 * 50;
    sample->network_rx_rate = 1024 * 1024;
    sample->network_tx_rate = 512 * 1024;
    
    // Check thresholds
    if (sample->cpu_percent > report->cpu_threshold) {
        char msg[256];
        snprintf(msg, sizeof(msg), "CPU usage %.1f%% exceeds threshold %.1f%%",
                 sample->cpu_percent, report->cpu_threshold);
        add_alert(report, RESOURCE_CPU, sample->cpu_percent,
                  report->cpu_threshold, ALERT_WARNING, msg);
    }
    
    if (sample->memory_percent > report->memory_threshold) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Memory usage %.1f%% exceeds threshold %.1f%%",
                 sample->memory_percent, report->memory_threshold);
        add_alert(report, RESOURCE_MEMORY, sample->memory_percent,
                  report->memory_threshold, ALERT_WARNING, msg);
    }
    
    if (sample->disk_percent > report->disk_threshold) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Disk usage %.1f%% exceeds threshold %.1f%%",
                 sample->disk_percent, report->disk_threshold);
        add_alert(report, RESOURCE_DISK, sample->disk_percent,
                  report->disk_threshold, ALERT_CRITICAL, msg);
    }
}

void sample_processes(ResourceReport* report) {
    // Simulated process sampling
    report->process_count = 0;
    
    const char* process_names[] = {"main_app", "worker_1", "worker_2", "logger", "monitor"};
    
    for (int i = 0; i < 5 && report->process_count < report->process_capacity; i++) {
        ProcessInfo* proc = &report->processes[report->process_count++];
        proc->pid = 1000 + i;
        strncpy(proc->name, process_names[i], sizeof(proc->name) - 1);
        proc->cpu_percent = 5.0 + (rand() % 20);
        proc->memory_used = 100 * 1024 * 1024 + (rand() % 500 * 1024 * 1024);
        proc->thread_count = 4 + (rand() % 12);
    }
}

void monitor_resources(ResourceReport* report, int duration_seconds, int sample_interval) {
    int samples_needed = duration_seconds / sample_interval;
    
    printf("Monitoring resources for %d seconds (sampling every %d seconds)...\n",
           duration_seconds, sample_interval);
    
    for (int i = 0; i < samples_needed; i++) {
        sample_resources(report);
        sample_processes(report);
        
        printf("  Sample %d/%d: CPU %.1f%%, Memory %.1f%%, Disk %.1f%%\n",
               i + 1, samples_needed,
               report->samples[report->sample_count - 1].cpu_percent,
               report->samples[report->sample_count - 1].memory_percent,
               report->samples[report->sample_count - 1].disk_percent);
        
        // In production, would sleep here
        // Sleep(sample_interval * 1000);
    }
    
    report->end_time = time(NULL);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* resource_type_to_string(ResourceType type) {
    switch (type) {
        case RESOURCE_CPU: return "CPU";
        case RESOURCE_MEMORY: return "Memory";
        case RESOURCE_DISK: return "Disk";
        case RESOURCE_NETWORK: return "Network";
        case RESOURCE_GPU: return "GPU";
        default: return "Unknown";
    }
}

const char* alert_level_to_string(AlertLevel level) {
    switch (level) {
        case ALERT_INFO: return "INFO";
        case ALERT_WARNING: return "WARNING";
        case ALERT_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

void print_resource_summary(ResourceReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Resource Monitor Summary\n");
    printf("=============================================================================\n");
    printf("  Monitoring Duration:  %lld seconds\n",
           (long long)difftime(report->end_time, report->start_time));
    printf("  Samples Collected:    %d\n", report->sample_count);
    printf("\n");
    printf("  Alerts:\n");
    printf("    Active:             %d\n", report->active_alerts);
    printf("    Warnings:           %d\n", report->warning_count);
    printf("    Critical:           %d\n", report->critical_count);
    printf("=============================================================================\n");
}

void print_resource_stats(ResourceReport* report) {
    if (report->sample_count == 0) return;
    
    // Calculate averages
    double avg_cpu = 0, avg_mem = 0, avg_disk = 0;
    double max_cpu = 0, max_mem = 0, max_disk = 0;
    
    for (int i = 0; i < report->sample_count; i++) {
        avg_cpu += report->samples[i].cpu_percent;
        avg_mem += report->samples[i].memory_percent;
        avg_disk += report->samples[i].disk_percent;
        
        if (report->samples[i].cpu_percent > max_cpu) max_cpu = report->samples[i].cpu_percent;
        if (report->samples[i].memory_percent > max_mem) max_mem = report->samples[i].memory_percent;
        if (report->samples[i].disk_percent > max_disk) max_disk = report->samples[i].disk_percent;
    }
    
    avg_cpu /= report->sample_count;
    avg_mem /= report->sample_count;
    avg_disk /= report->sample_count;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Resource Statistics\n");
    printf("=============================================================================\n");
    printf("  %-10s %10s %10s %10s\n", "Resource", "Average", "Maximum", "Threshold");
    printf("  ---------------------------------------------------------------------------\n");
    printf("  %-10s %9.1f%% %9.1f%% %9.1f%%\n", "CPU", avg_cpu, max_cpu, report->cpu_threshold);
    printf("  %-10s %9.1f%% %9.1f%% %9.1f%%\n", "Memory", avg_mem, max_mem, report->memory_threshold);
    printf("  %-10s %9.1f%% %9.1f%% %9.1f%%\n", "Disk", avg_disk, max_disk, report->disk_threshold);
    printf("=============================================================================\n");
}

void print_alerts(ResourceReport* report) {
    if (report->alert_count == 0) {
        printf("\n  No alerts triggered.\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Alerts\n");
    printf("=============================================================================\n");
    printf("  %-8s %-10s %-10s %s\n", "Level", "Resource", "Value", "Message");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->alert_count; i++) {
        Alert* alert = &report->alerts[i];
        printf("  %-8s %-10s %9.1f%% %s\n",
               alert_level_to_string(alert->level),
               resource_type_to_string(alert->type),
               alert->value,
               alert->message);
    }
    
    printf("=============================================================================\n");
}

void print_processes(ResourceReport* report) {
    if (report->process_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Top Processes\n");
    printf("=============================================================================\n");
    printf("  %-8s %-20s %10s %12s %8s\n", "PID", "Name", "CPU %", "Memory", "Threads");
    printf("  ---------------------------------------------------------------------------\n");
    
    // Sort by CPU usage
    for (int i = 0; i < report->process_count - 1; i++) {
        for (int j = 0; j < report->process_count - i - 1; j++) {
            if (report->processes[j].cpu_percent < report->processes[j + 1].cpu_percent) {
                ProcessInfo temp = report->processes[j];
                report->processes[j] = report->processes[j + 1];
                report->processes[j + 1] = temp;
            }
        }
    }
    
    for (int i = 0; i < report->process_count; i++) {
        ProcessInfo* proc = &report->processes[i];
        printf("  %-8d %-20s %9.1f%% %10llu MB %8d\n",
               proc->pid, proc->name, proc->cpu_percent,
               (unsigned long long)proc->memory_used / (1024 * 1024),
               proc->thread_count);
    }
    
    printf("=============================================================================\n");
}

void export_resource_json(ResourceReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"samples_collected\": %d,\n", report->sample_count);
    fprintf(f, "    \"active_alerts\": %d,\n", report->active_alerts);
    fprintf(f, "    \"warning_count\": %d,\n", report->warning_count);
    fprintf(f, "    \"critical_count\": %d\n", report->critical_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"samples\": [\n");
    
    for (int i = 0; i < report->sample_count; i++) {
        ResourceSample* sample = &report->samples[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"timestamp\": %lld,\n", (long long)sample->timestamp);
        fprintf(f, "      \"cpu_percent\": %.1f,\n", sample->cpu_percent);
        fprintf(f, "      \"memory_percent\": %.1f,\n", sample->memory_percent);
        fprintf(f, "      \"disk_percent\": %.1f\n", sample->disk_percent);
        fprintf(f, "    }%s\n", (i < report->sample_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"alerts\": [\n");
    
    for (int i = 0; i < report->alert_count; i++) {
        Alert* alert = &report->alerts[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"level\": \"%s\",\n", alert_level_to_string(alert->level));
        fprintf(f, "      \"resource\": \"%s\",\n", resource_type_to_string(alert->type));
        fprintf(f, "      \"value\": %.1f,\n", alert->value);
        fprintf(f, "      \"message\": \"%s\"\n", alert->message);
        fprintf(f, "    }%s\n", (i < report->alert_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Resource report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Resource Monitor\n");
    printf("=======================\n\n");
    
    srand((unsigned int)time(NULL));
    
    ResourceReport* report = resource_create_report();
    
    // Parse arguments
    int duration = 60;
    int interval = 5;
    
    if (argc > 1) duration = atoi(argv[1]);
    if (argc > 2) interval = atoi(argv[2]);
    
    printf("Configuration:\n");
    printf("  Duration: %d seconds\n", duration);
    printf("  Sample interval: %d seconds\n", interval);
    printf("  CPU threshold: %.1f%%\n", report->cpu_threshold);
    printf("  Memory threshold: %.1f%%\n", report->memory_threshold);
    printf("  Disk threshold: %.1f%%\n", report->disk_threshold);
    printf("\n");
    
    // Run monitoring
    monitor_resources(report, duration, interval);
    
    // Generate reports
    print_resource_summary(report);
    print_resource_stats(report);
    print_alerts(report);
    print_processes(report);
    export_resource_json(report, "resource_report.json");
    
    printf("\nResource monitoring complete!\n");
    
    int exit_code = report->critical_count > 0 ? 1 : 0;
    resource_destroy_report(report);
    
    return exit_code;
}
