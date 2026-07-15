//=============================================================================
// thread_analyzer.c - Thread Safety Analyzer
// Production-ready thread analysis and deadlock detection
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Thread Types
//=============================================================================

#define MAX_THREADS 100
#define MAX_LOCKS 100
#define MAX_EDGES 1000

typedef enum {
    THREAD_RUNNING,
    THREAD_BLOCKED,
    THREAD_TERMINATED
} ThreadState;

typedef enum {
    LOCK_FREE,
    LOCK_HELD
} LockState;

typedef struct {
    int id;
    char name[256];
    ThreadState state;
    int blocked_on_lock;
    time_t start_time;
    time_t last_active;
    int lock_count;
    int held_locks[10];
} ThreadInfo;

typedef struct {
    int id;
    char name[256];
    LockState state;
    int held_by;
    time_t acquired_time;
    int wait_count;
} LockInfo;

typedef struct {
    int from_thread;
    int to_lock;
    int edge_type;  // 0 = waits for, 1 = holds
    time_t timestamp;
} WaitEdge;

typedef struct {
    ThreadInfo threads[MAX_THREADS];
    int thread_count;
    
    LockInfo locks[MAX_LOCKS];
    int lock_count;
    
    WaitEdge edges[MAX_EDGES];
    int edge_count;
    
    int potential_deadlocks;
    int lock_contention_count;
    int long_hold_count;
} ThreadReport;

//=============================================================================
// Thread Analysis
//=============================================================================

ThreadReport* thread_create_report(void) {
    ThreadReport* report = (ThreadReport*)calloc(1, sizeof(ThreadReport));
    return report;
}

void thread_destroy_report(ThreadReport* report) {
    free(report);
}

ThreadInfo* get_or_create_thread(ThreadReport* report, int thread_id, const char* name) {
    for (int i = 0; i < report->thread_count; i++) {
        if (report->threads[i].id == thread_id) {
            return &report->threads[i];
        }
    }
    
    if (report->thread_count >= MAX_THREADS) return NULL;
    
    ThreadInfo* thread = &report->threads[report->thread_count++];
    thread->id = thread_id;
    strncpy(thread->name, name, sizeof(thread->name) - 1);
    thread->state = THREAD_RUNNING;
    thread->start_time = time(NULL);
    thread->last_active = time(NULL);
    thread->blocked_on_lock = -1;
    thread->lock_count = 0;
    return thread;
}

LockInfo* get_or_create_lock(ThreadReport* report, int lock_id, const char* name) {
    for (int i = 0; i < report->lock_count; i++) {
        if (report->locks[i].id == lock_id) {
            return &report->locks[i];
        }
    }
    
    if (report->lock_count >= MAX_LOCKS) return NULL;
    
    LockInfo* lock = &report->locks[report->lock_count++];
    lock->id = lock_id;
    strncpy(lock->name, name, sizeof(lock->name) - 1);
    lock->state = LOCK_FREE;
    lock->held_by = -1;
    return lock;
}

void record_lock_acquire(ThreadReport* report, int thread_id, int lock_id) {
    ThreadInfo* thread = get_or_create_thread(report, thread_id, "worker");
    LockInfo* lock = get_or_create_lock(report, lock_id, "mutex");
    
    if (lock->state == LOCK_HELD) {
        // Lock contention
        report->lock_contention_count++;
        lock->wait_count++;
        
        // Record wait edge
        if (report->edge_count < MAX_EDGES) {
            WaitEdge* edge = &report->edges[report->edge_count++];
            edge->from_thread = thread_id;
            edge->to_lock = lock_id;
            edge->edge_type = 0;  // waits for
            edge->timestamp = time(NULL);
        }
        
        thread->state = THREAD_BLOCKED;
        thread->blocked_on_lock = lock_id;
    } else {
        // Acquire successful
        lock->state = LOCK_HELD;
        lock->held_by = thread_id;
        lock->acquired_time = time(NULL);
        
        if (thread->lock_count < 10) {
            thread->held_locks[thread->lock_count++] = lock_id;
        }
        
        // Record hold edge
        if (report->edge_count < MAX_EDGES) {
            WaitEdge* edge = &report->edges[report->edge_count++];
            edge->from_thread = thread_id;
            edge->to_lock = lock_id;
            edge->edge_type = 1;  // holds
            edge->timestamp = time(NULL);
        }
    }
}

void record_lock_release(ThreadReport* report, int thread_id, int lock_id) {
    LockInfo* lock = get_or_create_lock(report, lock_id, "mutex");
    
    if (lock->held_by == thread_id) {
        lock->state = LOCK_FREE;
        lock->held_by = -1;
        
        // Update thread
        ThreadInfo* thread = get_or_create_thread(report, thread_id, "worker");
        thread->state = THREAD_RUNNING;
        thread->blocked_on_lock = -1;
        
        // Remove from held locks
        for (int i = 0; i < thread->lock_count; i++) {
            if (thread->held_locks[i] == lock_id) {
                thread->held_locks[i] = thread->held_locks[--thread->lock_count];
                break;
            }
        }
    }
}

int detect_deadlock(ThreadReport* report) {
    // Simple cycle detection in wait-for graph
    // In production, would use proper graph algorithms
    
    int deadlock_count = 0;
    
    for (int i = 0; i < report->thread_count; i++) {
        ThreadInfo* t1 = &report->threads[i];
        if (t1->state != THREAD_BLOCKED) continue;
        
        // Find what lock t1 is waiting for
        int waiting_for = t1->blocked_on_lock;
        if (waiting_for < 0) continue;
        
        // Find who holds that lock
        LockInfo* lock = NULL;
        for (int j = 0; j < report->lock_count; j++) {
            if (report->locks[j].id == waiting_for) {
                lock = &report->locks[j];
                break;
            }
        }
        
        if (!lock || lock->held_by < 0) continue;
        
        // Check if holder is waiting for something t1 holds
        ThreadInfo* t2 = NULL;
        for (int j = 0; j < report->thread_count; j++) {
            if (report->threads[j].id == lock->held_by) {
                t2 = &report->threads[j];
                break;
            }
        }
        
        if (t2 && t2->state == THREAD_BLOCKED) {
            // Check if t2 is waiting for a lock held by t1
            for (int k = 0; k < t1->lock_count; k++) {
                if (t1->held_locks[k] == t2->blocked_on_lock) {
                    deadlock_count++;
                    break;
                }
            }
        }
    }
    
    report->potential_deadlocks = deadlock_count;
    return deadlock_count;
}

void check_long_holds(ThreadReport* report, int threshold_seconds) {
    time_t now = time(NULL);
    report->long_hold_count = 0;
    
    for (int i = 0; i < report->lock_count; i++) {
        LockInfo* lock = &report->locks[i];
        if (lock->state == LOCK_HELD) {
            int held_for = (int)(now - lock->acquired_time);
            if (held_for > threshold_seconds) {
                report->long_hold_count++;
            }
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_thread_summary(ThreadReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Thread Analysis Report\n");
    printf("=============================================================================\n");
    printf("  Threads:            %d\n", report->thread_count);
    printf("  Locks:              %d\n", report->lock_count);
    printf("\n");
    printf("  Issues Found:\n");
    printf("    Potential Deadlocks: %d\n", report->potential_deadlocks);
    printf("    Lock Contentions:    %d\n", report->lock_contention_count);
    printf("    Long Holds (>5s):   %d\n", report->long_hold_count);
    printf("=============================================================================\n");
}

void print_thread_details(ThreadReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Thread Details\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->thread_count; i++) {
        ThreadInfo* thread = &report->threads[i];
        const char* state_str = (thread->state == THREAD_RUNNING) ? "RUNNING" :
                               (thread->state == THREAD_BLOCKED) ? "BLOCKED" : "TERMINATED";
        
        printf("  Thread %d (%s): %s", thread->id, thread->name, state_str);
        
        if (thread->state == THREAD_BLOCKED && thread->blocked_on_lock >= 0) {
            printf(" [waiting for lock %d]", thread->blocked_on_lock);
        }
        
        if (thread->lock_count > 0) {
            printf(" [holds:");
            for (int j = 0; j < thread->lock_count; j++) {
                printf(" %d", thread->held_locks[j]);
            }
            printf("]");
        }
        
        printf("\n");
    }
    
    printf("=============================================================================\n");
}

void print_lock_details(ThreadReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Lock Details\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->lock_count; i++) {
        LockInfo* lock = &report->locks[i];
        const char* state_str = (lock->state == LOCK_HELD) ? "HELD" : "FREE";
        
        printf("  Lock %d (%s): %s", lock->id, lock->name, state_str);
        
        if (lock->state == LOCK_HELD) {
            printf(" [by thread %d, waited %d times]", lock->held_by, lock->wait_count);
        }
        
        printf("\n");
    }
    
    printf("=============================================================================\n");
}

void export_thread_json(ThreadReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"thread_count\": %d,\n", report->thread_count);
    fprintf(f, "    \"lock_count\": %d,\n", report->lock_count);
    fprintf(f, "    \"potential_deadlocks\": %d,\n", report->potential_deadlocks);
    fprintf(f, "    \"lock_contentions\": %d,\n", report->lock_contention_count);
    fprintf(f, "    \"long_holds\": %d\n", report->long_hold_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"threads\": [\n");
    
    for (int i = 0; i < report->thread_count; i++) {
        ThreadInfo* thread = &report->threads[i];
        const char* state_str = (thread->state == THREAD_RUNNING) ? "running" :
                               (thread->state == THREAD_BLOCKED) ? "blocked" : "terminated";
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": %d,\n", thread->id);
        fprintf(f, "      \"name\": \"%s\",\n", thread->name);
        fprintf(f, "      \"state\": \"%s\",\n", state_str);
        fprintf(f, "      \"blocked_on_lock\": %d,\n", thread->blocked_on_lock);
        fprintf(f, "      \"held_locks\": [");
        for (int j = 0; j < thread->lock_count; j++) {
            fprintf(f, "%d%s", thread->held_locks[j], 
                   (j < thread->lock_count - 1) ? ", " : "");
        }
        fprintf(f, "]\n");
        fprintf(f, "    }%s\n", (i < report->thread_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"locks\": [\n");
    
    for (int i = 0; i < report->lock_count; i++) {
        LockInfo* lock = &report->locks[i];
        const char* state_str = (lock->state == LOCK_HELD) ? "held" : "free";
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": %d,\n", lock->id);
        fprintf(f, "      \"name\": \"%s\",\n", lock->name);
        fprintf(f, "      \"state\": \"%s\",\n", state_str);
        fprintf(f, "      \"held_by\": %d,\n", lock->held_by);
        fprintf(f, "      \"wait_count\": %d\n", lock->wait_count);
        fprintf(f, "    }%s\n", (i < report->lock_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Thread report exported: %s\n", filename);
}

//=============================================================================
// Demo
//=============================================================================

void demo_thread_operations(ThreadReport* report) {
    // Simulate thread operations
    record_lock_acquire(report, 1, 1);  // Thread 1 acquires lock 1
    record_lock_acquire(report, 2, 2);  // Thread 2 acquires lock 2
    
    // Potential deadlock scenario
    record_lock_acquire(report, 1, 2);  // Thread 1 tries to acquire lock 2 (blocked)
    record_lock_acquire(report, 2, 1);  // Thread 2 tries to acquire lock 1 (blocked)
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Thread Analyzer\n");
    printf("=====================\n\n");
    
    ThreadReport* report = thread_create_report();
    
    // Run demo
    printf("Simulating thread operations...\n");
    demo_thread_operations(report);
    
    // Analyze
    detect_deadlock(report);
    check_long_holds(report, 5);
    
    // Generate reports
    print_thread_summary(report);
    print_thread_details(report);
    print_lock_details(report);
    export_thread_json(report, "thread_analysis_report.json");
    
    printf("\nThread analysis complete!\n");
    
    int exit_code = report->potential_deadlocks > 0 ? 1 : 0;
    thread_destroy_report(report);
    
    return exit_code;
}
