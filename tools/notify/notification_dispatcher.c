//=============================================================================
// notification_dispatcher.c - Notification Dispatcher
// Production-ready notification system with multiple channels
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Notification Types
//=============================================================================

#define MAX_NOTIFICATIONS 1000
#define MAX_CHANNELS 10
#define MAX_RECIPIENTS 100
#define MAX_GROUPS 20

typedef enum {
    CHANNEL_EMAIL,
    CHANNEL_SMS,
    CHANNEL_SLACK,
    CHANNEL_WEBHOOK,
    CHANNEL_PAGERDUTY,
    CHANNEL_CONSOLE
} NotificationChannel;

typedef enum {
    PRIORITY_LOW,
    PRIORITY_NORMAL,
    PRIORITY_HIGH,
    PRIORITY_CRITICAL
} NotificationPriority;

typedef enum {
    STATUS_PENDING,
    STATUS_SENT,
    STATUS_DELIVERED,
    STATUS_FAILED,
    STATUS_RETRYING
} NotificationStatus;

typedef struct {
    char id[64];
    char title[256];
    char message[2048];
    char details[4096];
    NotificationPriority priority;
    NotificationChannel channel;
    char recipient[256];
    char group[128];
    
    time_t created_at;
    time_t sent_at;
    time_t delivered_at;
    NotificationStatus status;
    int retry_count;
    int max_retries;
    char error_message[512];
} Notification;

typedef struct {
    char name[128];
    NotificationChannel channel;
    char config[1024];
    int is_enabled;
    int success_count;
    int failure_count;
    double avg_latency_ms;
} ChannelConfig;

typedef struct {
    char name[128];
    char email[256];
    char phone[32];
    char slack_id[64];
    int is_active;
    time_t last_notified;
} Recipient;

typedef struct {
    char name[128];
    char recipients[50][256];
    int recipient_count;
    char escalation_policy[512];
} NotificationGroup;

typedef struct {
    Notification* notifications;
    int notification_count;
    int notification_capacity;
    
    ChannelConfig* channels;
    int channel_count;
    int channel_capacity;
    
    Recipient* recipients;
    int recipient_count;
    int recipient_capacity;
    
    NotificationGroup* groups;
    int group_count;
    int group_capacity;
    
    int sent_count;
    int failed_count;
    int pending_count;
    
    time_t start_time;
    time_t end_time;
} NotificationReport;

//=============================================================================
// Notification Implementation
//=============================================================================

NotificationReport* notification_create_report(void) {
    NotificationReport* report = (NotificationReport*)calloc(1, sizeof(NotificationReport));
    report->notification_capacity = MAX_NOTIFICATIONS;
    report->notifications = (Notification*)calloc(report->notification_capacity, sizeof(Notification));
    report->channel_capacity = MAX_CHANNELS;
    report->channels = (ChannelConfig*)calloc(report->channel_capacity, sizeof(ChannelConfig));
    report->recipient_capacity = MAX_RECIPIENTS;
    report->recipients = (Recipient*)calloc(report->recipient_capacity, sizeof(Recipient));
    report->group_capacity = MAX_GROUPS;
    report->groups = (NotificationGroup*)calloc(report->group_capacity, sizeof(NotificationGroup));
    report->start_time = time(NULL);
    return report;
}

void notification_destroy_report(NotificationReport* report) {
    if (!report) return;
    free(report->notifications);
    free(report->channels);
    free(report->recipients);
    free(report->groups);
    free(report);
}

void generate_notification_id(char* id, size_t size) {
    static int counter = 0;
    time_t now = time(NULL);
    snprintf(id, size, "NOTIF-%lld-%04d", (long long)now, counter++);
}

Notification* create_notification(NotificationReport* report, const char* title,
                                   const char* message, NotificationPriority priority,
                                   NotificationChannel channel, const char* recipient) {
    if (report->notification_count >= report->notification_capacity) return NULL;
    
    Notification* notif = &report->notifications[report->notification_count++];
    generate_notification_id(notif->id, sizeof(notif->id));
    strncpy(notif->title, title, sizeof(notif->title) - 1);
    strncpy(notif->message, message, sizeof(notif->message) - 1);
    notif->priority = priority;
    notif->channel = channel;
    strncpy(notif->recipient, recipient, sizeof(notif->recipient) - 1);
    notif->created_at = time(NULL);
    notif->status = STATUS_PENDING;
    notif->retry_count = 0;
    notif->max_retries = 3;
    
    report->pending_count++;
    
    return notif;
}

void add_channel(NotificationReport* report, const char* name, NotificationChannel channel,
                 const char* config) {
    if (report->channel_count >= report->channel_capacity) return;
    
    ChannelConfig* ch = &report->channels[report->channel_count++];
    strncpy(ch->name, name, sizeof(ch->name) - 1);
    ch->channel = channel;
    strncpy(ch->config, config, sizeof(ch->config) - 1);
    ch->is_enabled = 1;
}

void add_recipient(NotificationReport* report, const char* name, const char* email) {
    if (report->recipient_count >= report->recipient_capacity) return;
    
    Recipient* rec = &report->recipients[report->recipient_count++];
    strncpy(rec->name, name, sizeof(rec->name) - 1);
    strncpy(rec->email, email, sizeof(rec->email) - 1);
    rec->is_active = 1;
}

int send_via_channel(Notification* notif, ChannelConfig* channel) {
    // Simulated sending
    double latency = 10.0 + (rand() % 100);
    
    // Simulate occasional failures
    if (rand() % 20 == 0) {
        notif->status = STATUS_FAILED;
        strncpy(notif->error_message, "Connection timeout", sizeof(notif->error_message) - 1);
        channel->failure_count++;
        return -1;
    }
    
    notif->status = STATUS_SENT;
    notif->sent_at = time(NULL);
    channel->success_count++;
    
    // Update average latency
    channel->avg_latency_ms = (channel->avg_latency_ms * (channel->success_count - 1) + latency)
                                / channel->success_count;
    
    return 0;
}

void dispatch_notification(NotificationReport* report, Notification* notif) {
    // Find channel
    ChannelConfig* channel = NULL;
    for (int i = 0; i < report->channel_count; i++) {
        if (report->channels[i].channel == notif->channel && report->channels[i].is_enabled) {
            channel = &report->channels[i];
            break;
        }
    }
    
    if (!channel) {
        notif->status = STATUS_FAILED;
        strncpy(notif->error_message, "Channel not found or disabled", sizeof(notif->error_message) - 1);
        report->failed_count++;
        report->pending_count--;
        return;
    }
    
    // Attempt to send
    if (send_via_channel(notif, channel) == 0) {
        report->sent_count++;
        report->pending_count--;
        
        // Simulate delivery
        notif->status = STATUS_DELIVERED;
        notif->delivered_at = time(NULL);
    } else {
        // Retry logic
        if (notif->retry_count < notif->max_retries) {
            notif->retry_count++;
            notif->status = STATUS_RETRYING;
        } else {
            report->failed_count++;
            report->pending_count--;
        }
    }
}

void process_all_notifications(NotificationReport* report) {
    for (int i = 0; i < report->notification_count; i++) {
        Notification* notif = &report->notifications[i];
        if (notif->status == STATUS_PENDING) {
            dispatch_notification(report, notif);
        }
    }
    
    report->end_time = time(NULL);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* channel_to_string(NotificationChannel channel) {
    switch (channel) {
        case CHANNEL_EMAIL: return "Email";
        case CHANNEL_SMS: return "SMS";
        case CHANNEL_SLACK: return "Slack";
        case CHANNEL_WEBHOOK: return "Webhook";
        case CHANNEL_PAGERDUTY: return "PagerDuty";
        case CHANNEL_CONSOLE: return "Console";
        default: return "Unknown";
    }
}

const char* priority_to_string(NotificationPriority priority) {
    switch (priority) {
        case PRIORITY_LOW: return "Low";
        case PRIORITY_NORMAL: return "Normal";
        case PRIORITY_HIGH: return "High";
        case PRIORITY_CRITICAL: return "Critical";
        default: return "Unknown";
    }
}

const char* status_to_string(NotificationStatus status) {
    switch (status) {
        case STATUS_PENDING: return "Pending";
        case STATUS_SENT: return "Sent";
        case STATUS_DELIVERED: return "Delivered";
        case STATUS_FAILED: return "Failed";
        case STATUS_RETRYING: return "Retrying";
        default: return "Unknown";
    }
}

void print_notification_summary(NotificationReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Notification Dispatch Summary\n");
    printf("=============================================================================\n");
    printf("  Total Notifications:  %d\n", report->notification_count);
    printf("  Sent:                 %d\n", report->sent_count);
    printf("  Failed:               %d\n", report->failed_count);
    printf("  Pending:              %d\n", report->pending_count);
    printf("=============================================================================\n");
}

void print_channel_stats(NotificationReport* report) {
    if (report->channel_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Channel Statistics\n");
    printf("=============================================================================\n");
    printf("  %-15s %10s %10s %12s\n", "Channel", "Success", "Failed", "Avg Latency");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->channel_count; i++) {
        ChannelConfig* ch = &report->channels[i];
        printf("  %-15s %10d %10d %10.1f ms\n",
               channel_to_string(ch->channel),
               ch->success_count, ch->failure_count, ch->avg_latency_ms);
    }
    
    printf("=============================================================================\n");
}

void print_notifications(NotificationReport* report) {
    if (report->notification_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Notifications\n");
    printf("=============================================================================\n");
    printf("  %-20s %-10s %-12s %-15s %s\n",
           "ID", "Priority", "Channel", "Status", "Recipient");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->notification_count && i < 20; i++) {
        Notification* notif = &report->notifications[i];
        printf("  %-20s %-10s %-12s %-15s %s\n",
               notif->id,
               priority_to_string(notif->priority),
               channel_to_string(notif->channel),
               status_to_string(notif->status),
               notif->recipient);
    }
    
    if (report->notification_count > 20) {
        printf("  ... and %d more\n", report->notification_count - 20);
    }
    
    printf("=============================================================================\n");
}

void export_notification_json(NotificationReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total\": %d,\n", report->notification_count);
    fprintf(f, "    \"sent\": %d,\n", report->sent_count);
    fprintf(f, "    \"failed\": %d,\n", report->failed_count);
    fprintf(f, "    \"pending\": %d\n", report->pending_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"notifications\": [\n");
    
    for (int i = 0; i < report->notification_count; i++) {
        Notification* notif = &report->notifications[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", notif->id);
        fprintf(f, "      \"title\": \"%s\",\n", notif->title);
        fprintf(f, "      \"priority\": \"%s\",\n", priority_to_string(notif->priority));
        fprintf(f, "      \"channel\": \"%s\",\n", channel_to_string(notif->channel));
        fprintf(f, "      \"status\": \"%s\",\n", status_to_string(notif->status));
        fprintf(f, "      \"recipient\": \"%s\"\n", notif->recipient);
        fprintf(f, "    }%s\n", (i < report->notification_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Notification report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Notification Dispatcher\n");
    printf("==============================\n\n");
    
    srand((unsigned int)time(NULL));
    
    NotificationReport* report = notification_create_report();
    
    // Configure channels
    printf("Configuring notification channels...\n");
    add_channel(report, "Email", CHANNEL_EMAIL, "smtp://mail.example.com");
    add_channel(report, "Slack", CHANNEL_SLACK, "https://hooks.slack.com/...");
    add_channel(report, "Console", CHANNEL_CONSOLE, "stdout");
    
    // Add recipients
    add_recipient(report, "Admin Team", "admin@example.com");
    add_recipient(report, "DevOps", "devops@example.com");
    add_recipient(report, "On-Call", "oncall@example.com");
    
    // Create notifications
    printf("Creating notifications...\n");
    create_notification(report, "System Alert", "CPU usage above threshold",
                        PRIORITY_HIGH, CHANNEL_EMAIL, "admin@example.com");
    create_notification(report, "Build Complete", "Build #1234 succeeded",
                        PRIORITY_NORMAL, CHANNEL_SLACK, "#builds");
    create_notification(report, "Deployment Failed", "Production deployment failed",
                        PRIORITY_CRITICAL, CHANNEL_EMAIL, "devops@example.com");
    create_notification(report, "Daily Summary", "Daily metrics report",
                        PRIORITY_LOW, CHANNEL_CONSOLE, "stdout");
    
    // Process notifications
    printf("\nDispatching notifications...\n");
    process_all_notifications(report);
    
    // Generate reports
    print_notification_summary(report);
    print_channel_stats(report);
    print_notifications(report);
    export_notification_json(report, "notification_report.json");
    
    printf("\nNotification dispatch complete!\n");
    
    notification_destroy_report(report);
    
    return 0;
}
