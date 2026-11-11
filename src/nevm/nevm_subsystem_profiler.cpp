//============================================================================
// nevm_subsystem_profiler.cpp
// RawrXD N-EVM - Subsystem Performance Profiler
// Breaks down decode time by component for bottleneck identification
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_transformer_engine.hpp"
#include "nevm_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <windows.h>

using namespace RawrXD::NEVM;

//============================================================================
// High-Resolution Timer
//============================================================================

class PreciseTimer {
public:
    PreciseTimer() {
        QueryPerformanceFrequency(&freq_);
    }
    
    void Start() {
        QueryPerformanceCounter(&start_);
    }
    
    double Stop() {
        QueryPerformanceCounter(&end_);
        return ElapsedNs();
    }
    
    double ElapsedNs() const {
        return ((end_.QuadPart - start_.QuadPart) * 1e9) / freq_.QuadPart;
    }
    
private:
    LARGE_INTEGER freq_, start_, end_;
};

//============================================================================
// Subsystem Timing Breakdown
//============================================================================

struct SubsystemTiming {
    const char* name;
    double avg_ns;
    double min_ns;
    double max_ns;
    uint64_t call_count;
    double total_ns;
    float percent_of_decode;
};

class SubsystemProfiler {
public:
    enum class Component {
        MMU_LOOKUP,
        RESIDENCY_MANAGER,
        PRECISION_CONTROLLER,
        KERNEL_DISPATCH,
        KERNEL_EXECUTION,
        SAMPLING,
        TRACE_RECORDING,
        MEMORY_MIGRATION,
        PREFETCH_SCHEDULING,
        COUNT
    };
    
    struct TimingData {
        double total_ns = 0.0;
        double min_ns = 1e18;
        double max_ns = 0.0;
        uint64_t count = 0;
    };
    
    TimingData data[static_cast<int>(Component::COUNT)];
    PreciseTimer timer;
    Component current_component;
    
    void Start(Component c) {
        current_component = c;
        timer.Start();
    }
    
    void Stop() {
        double elapsed = timer.Stop();
        auto& d = data[static_cast<int>(current_component)];
        d.total_ns += elapsed;
        d.min_ns = std::min(d.min_ns, elapsed);
        d.max_ns = std::max(d.max_ns, elapsed);
        d.count++;
    }
    
    std::vector<SubsystemTiming> GetResults(double total_decode_ns) const {
        std::vector<SubsystemTiming> results;
        
        const char* names[] = {
            "MMU Lookup",
            "Residency Manager",
            "Precision Controller",
            "Kernel Dispatch",
            "Kernel Execution",
            "Sampling",
            "Trace Recording",
            "Memory Migration",
            "Prefetch Scheduling"
        };
        
        for (int i = 0; i < static_cast<int>(Component::COUNT); ++i) {
            const auto& d = data[i];
            if (d.count > 0) {
                SubsystemTiming st;
                st.name = names[i];
                st.avg_ns = d.total_ns / d.count;
                st.min_ns = d.min_ns;
                st.max_ns = d.max_ns;
                st.call_count = d.count;
                st.total_ns = d.total_ns;
                st.percent_of_decode = (d.total_ns / total_decode_ns) * 100.0f;
                results.push_back(st);
            }
        }
        
        // Sort by total time (descending)
        std::sort(results.begin(), results.end(),
                 [](const SubsystemTiming& a, const SubsystemTiming& b) {
                     return a.total_ns > b.total_ns;
                 });
        
        return results;
    }
    
    void Reset() {
        for (int i = 0; i < static_cast<int>(Component::COUNT); ++i) {
            data[i] = TimingData();
        }
    }
};

//============================================================================
// Residency Decision Validator
//============================================================================

struct ResidencyMetrics {
    uint64_t migrations_requested;
    uint64_t migrations_useful;
    uint64_t migrations_wasted;
    float migration_accuracy;
    double avg_residency_lifetime_tokens;
    double avg_reuse_count;
    std::map<ResidencyState, uint64_t> state_distribution;
};

class ResidencyValidator {
public:
    struct MigrationRecord {
        uint64_t vta;
        uint32_t migration_token;
        uint32_t first_use_token;
        uint32_t last_use_token;
        uint32_t use_count;
        bool was_useful;
    };
    
    std::vector<MigrationRecord> migrations;
    std::map<uint64_t, MigrationRecord*> active_migrations;
    
    void RecordMigrationRequested(uint64_t vta, uint32_t token) {
        MigrationRecord rec;
        rec.vta = vta;
        rec.migration_token = token;
        rec.first_use_token = 0;
        rec.last_use_token = 0;
        rec.use_count = 0;
        rec.was_useful = false;
        
        migrations.push_back(rec);
        active_migrations[vta] = &migrations.back();
    }
    
    void RecordTensorUsed(uint64_t vta, uint32_t token) {
        auto it = active_migrations.find(vta);
        if (it != active_migrations.end()) {
            auto& rec = *it->second;
            if (rec.use_count == 0) {
                rec.first_use_token = token;
            }
            rec.last_use_token = token;
            rec.use_count++;
        }
    }
    
    void Finalize(uint32_t final_token, uint32_t usefulness_window) {
        for (auto& rec : migrations) {
            // Migration is useful if tensor was used within window
            if (rec.use_count > 0 && 
                (rec.first_use_token - rec.migration_token) <= usefulness_window) {
                rec.was_useful = true;
            }
        }
    }
    
    ResidencyMetrics CalculateMetrics() const {
        ResidencyMetrics metrics = {};
        metrics.migrations_requested = migrations.size();
        
        uint64_t total_lifetime = 0;
        uint64_t total_reuses = 0;
        
        for (const auto& rec : migrations) {
            if (rec.was_useful) {
                metrics.migrations_useful++;
                if (rec.last_use_token > rec.first_use_token) {
                    total_lifetime += (rec.last_use_token - rec.first_use_token);
                }
                total_reuses += rec.use_count;
            } else {
                metrics.migrations_wasted++;
            }
        }
        
        if (metrics.migrations_requested > 0) {
            metrics.migration_accuracy = 
                metrics.migrations_useful / (float)metrics.migrations_requested;
        }
        
        if (metrics.migrations_useful > 0) {
            metrics.avg_residency_lifetime_tokens = 
                total_lifetime / (double)metrics.migrations_useful;
            metrics.avg_reuse_count = 
                total_reuses / (double)metrics.migrations_useful;
        }
        
        return metrics;
    }
};

//============================================================================
// Precision Effectiveness Tracker
//============================================================================

struct PrecisionEffectiveness {
    struct PrecisionStats {
        uint64_t block_count;
        double avg_error;
        double max_error;
        double min_error;
        uint64_t transitions_in;
        uint64_t transitions_out;
    };
    
    std::map<PrecisionMode, PrecisionStats> stats;
    
    void RecordBlockError(PrecisionMode mode, double error) {
        auto& s = stats[mode];
        s.block_count++;
        s.avg_error += error;
        s.max_error = std::max(s.max_error, error);
        s.min_error = std::min(s.min_error, error);
    }
    
    void RecordTransition(PrecisionMode from, PrecisionMode to) {
        stats[from].transitions_out++;
        stats[to].transitions_in++;
    }
    
    void PrintReport() const {
        std::cout << "\nPrecision Effectiveness:\n";
        std::cout << "------------------------\n";
        std::cout << std::left << std::setw(12) << "Precision"
                  << std::setw(10) << "Blocks"
                  << std::setw(12) << "Avg Error"
                  << std::setw(12) << "Min Error"
                  << std::setw(12) << "Max Error"
                  << std::setw(12) <> "Transitions"
                  << "\n";
        
        const char* names[] = {"Binary", "Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "FP16", "FP32"};
        
        for (const auto& [mode, s] : stats) {
            std::cout << std::left << std::setw(12) << names[static_cast<int>(mode)]
                      << std::setw(10) << s.block_count
                      << std::setw(12) << std::scientific << std::setprecision(3) << (s.avg_error / s.block_count)
                      << std::setw(12) << s.min_error
                      << std::setw(12) << s.max_error
                      << std::setw(12) << (s.transitions_in + s.transitions_out)
                      << "\n";
        }
    }
};

//============================================================================
// Scheduler Timing Metrics
//============================================================================

struct SchedulerMetrics {
    double avg_prefetch_lead_time_tokens;
    double avg_wait_time_ns;
    double pct_arriving_before_use;
    double pct_arriving_late;
    uint64_t prefetches_issued;
    uint64_t prefetches_completed_before_use;
    uint64_t prefetches_completed_late;
};

class SchedulerValidator {
public:
    struct PrefetchRecord {
        uint64_t vta;
        uint32_t issue_token;
        uint32_t complete_token;
        uint32_t first_use_token;
        bool completed_before_use;
    };
    
    std::vector<PrefetchRecord> prefetches;
    
    void RecordPrefetchIssued(uint64_t vta, uint32_t token) {
        PrefetchRecord rec;
        rec.vta = vta;
        rec.issue_token = token;
        rec.complete_token = 0;
        rec.first_use_token = 0;
        rec.completed_before_use = false;
        prefetches.push_back(rec);
    }
    
    void RecordPrefetchCompleted(uint64_t vta, uint32_t token) {
        for (auto& rec : prefetches) {
            if (rec.vta == vta && rec.complete_token == 0) {
                rec.complete_token = token;
                break;
            }
        }
    }
    
    void RecordTensorUsed(uint64_t vta, uint32_t token) {
        for (auto& rec : prefetches) {
            if (rec.vta == vta && rec.first_use_token == 0) {
                rec.first_use_token = token;
                rec.completed_before_use = (rec.complete_token <= token);
                break;
            }
        }
    }
    
    SchedulerMetrics CalculateMetrics() const {
        SchedulerMetrics metrics = {};
        metrics.prefetches_issued = prefetches.size();
        
        double total_lead = 0.0;
        uint64_t lead_count = 0;
        
        for (const auto& rec : prefetches) {
            if (rec.complete_token > 0 && rec.first_use_token > 0) {
                int lead = rec.first_use_token - rec.issue_token;
                total_lead += lead;
                lead_count++;
                
                if (rec.completed_before_use) {
                    metrics.prefetches_completed_before_use++;
                } else {
                    metrics.prefetches_completed_late++;
                }
            }
        }
        
        if (lead_count > 0) {
            metrics.avg_prefetch_lead_time_tokens = total_lead / lead_count;
        }
        
        if (metrics.prefetches_issued > 0) {
            metrics.pct_arriving_before_use = 
                (metrics.prefetches_completed_before_use / (double)metrics.prefetches_issued) * 100.0;
            metrics.pct_arriving_late = 
                (metrics.prefetches_completed_late / (double)metrics.prefetches_issued) * 100.0;
        }
        
        return metrics;
    }
};

//============================================================================
// Kernel Dispatch Statistics
//============================================================================

struct DispatchStats {
    struct BackendStats {
        uint64_t call_count;
        double avg_dispatch_time_ns;
        double total_time_ns;
    };
    
    std::map<std::string, BackendStats> backends;
    uint64_t fallbacks;
    uint64_t failures;
    
    void RecordDispatch(const std::string& backend, double dispatch_time_ns) {
        auto& s = backends[backend];
        s.call_count++;
        s.total_time_ns += dispatch_time_ns;
        s.avg_dispatch_time_ns = s.total_time_ns / s.call_count;
    }
    
    void RecordFallback() { fallbacks++; }
    void RecordFailure() { failures++; }
    
    void PrintReport() const {
        std::cout << "\nKernel Dispatch Statistics:\n";
        std::cout << "---------------------------\n";
        std::cout << std::left << std::setw(15) << "Backend"
                  << std::setw(12) << "Calls"
                  << std::setw(15) << "Avg Time (ns)"
                  << std::setw(15) << "Total Time (ns)"
                  << std::setw(10) << "Pct"
                  << "\n";
        
        uint64_t total_calls = 0;
        for (const auto& [name, s] : backends) {
            total_calls += s.call_count;
        }
        
        for (const auto& [name, s] : backends) {
            float pct = total_calls > 0 ? (s.call_count / (float)total_calls) * 100.0f : 0.0f;
            std::cout << std::left << std::setw(15) << name
                      << std::setw(12) << s.call_count
                      << std::setw(15) << std::fixed << std::setprecision(2) << s.avg_dispatch_time_ns
                      << std::setw(15) << s.total_time_ns
                      << std::setw(10) << std::setprecision(1) << pct << "%"
                      << "\n";
        }
        
        std::cout << "\nFallbacks: " << fallbacks << "\n";
        std::cout << "Failures:  " << failures << "\n";
    }
};

//============================================================================
// Memory Residency Timeline
//============================================================================

class ResidencyTimeline {
public:
    struct TimelineEntry {
        uint32_t token;
        ResidencyState state;
        uint64_t vram_bytes;
        uint64_t ram_bytes;
        uint64_t mapped_bytes;
    };
    
    std::vector<TimelineEntry> entries;
    uint32_t current_token = 0;
    
    void RecordState(uint32_t token, ResidencyState state, 
                     uint64_t vram, uint64_t ram, uint64_t mapped) {
        TimelineEntry entry;
        entry.token = token;
        entry.state = state;
        entry.vram_bytes = vram;
        entry.ram_bytes = ram;
        entry.mapped_bytes = mapped;
        entries.push_back(entry);
    }
    
    void ExportASCII(const std::string& path, int width = 80) {
        std::ofstream file(path);
        if (!file.is_open()) return;
        
        if (entries.empty()) return;
        
        uint32_t max_token = entries.back().token;
        int step = std::max(1, (int)max_token / width);
        
        file << "Memory Residency Timeline\n";
        file << "=======================\n\n";
        file << "Token →\n";
        
        // VRAM line
        file << "VRAM ";
        for (int t = 0; t <= max_token; t += step) {
            auto it = std::find_if(entries.begin(), entries.end(),
                [t](const TimelineEntry& e) { return e.token >= t; });
            if (it != entries.end() && it->vram_bytes > 0) {
                file << "█";
            } else {
                file <> "░";
            }
        }
        file << "\n";
        
        // RAM line
        file << "RAM  ";
        for (int t = 0; t <= max_token; t += step) {
            auto it = std::find_if(entries.begin(), entries.end(),
                [t](const TimelineEntry& e) { return e.token >= t; });
            if (it != entries.end() && it->ram_bytes > 0) {
                file << "█";
            } else {
                file << "░";
            }
        }
        file << "\n";
        
        // Mapped line
        file << "MAP  ";
        for (int t = 0; t <= max_token; t += step) {
            auto it = std::find_if(entries.begin(), entries.end(),
                [t](const TimelineEntry& e) { return e.token >= t; });
            if (it != entries.end() && it->mapped_bytes > 0) {
                file << "█";
            } else {
                file << "░";
            }
        }
        file << "\n";
    }
};

//============================================================================
// Main Profiler Interface
//============================================================================

class NEVMProfiler {
public:
    SubsystemProfiler subsystem;
    ResidencyValidator residency;
    PrecisionEffectiveness precision;
    SchedulerValidator scheduler;
    DispatchStats dispatch;
    ResidencyTimeline timeline;
    
    void PrintSubsystemReport(double total_decode_ns) const {
        auto results = subsystem.GetResults(total_decode_ns);
        
        std::cout << "\nSubsystem Timing Breakdown:\n";
        std::cout << "---------------------------\n";
        std::cout << std::left << std::setw(25) << "Component"
                  << std::setw(15) << "Avg (ns)"
                  << std::setw(12) << "Calls"
                  << std::setw(12) << "% Decode"
                  << "\n";
        
        for (const auto& r : results) {
            std::cout << std::left << std::setw(25) << r.name
                      << std::setw(15) << std::fixed << std::setprecision(1) << r.avg_ns
                      << std::setw(12) << r.call_count
                      << std::setw(12) << std::setprecision(2) << r.percent_of_decode
                      << "\n";
        }
    }
    
    void PrintResidencyReport() const {
        auto metrics = residency.CalculateMetrics();
        
        std::cout << "\nResidency Decision Metrics:\n";
        std::cout << "---------------------------\n";
        std::cout << "Migrations requested:  " << metrics.migrations_requested << "\n";
        std::cout << "Migrations useful:     " << metrics.migrations_useful << "\n";
        std::cout << "Migrations wasted:     " << metrics.migrations_wasted << "\n";
        std::cout << "Migration accuracy:    " << std::fixed << std::setprecision(2) << (metrics.migration_accuracy * 100.0f) << "%\n";
        std::cout << "Avg residency lifetime:" << metrics.avg_residency_lifetime_tokens << " tokens\n";
        std::cout << "Avg reuse count:       " << metrics.avg_reuse_count << "\n";
    }
    
    void PrintSchedulerReport() const {
        auto metrics = scheduler.CalculateMetrics();
        
        std::cout << "\nScheduler Metrics:\n";
        std::cout << "------------------\n";
        std::cout << "Prefetches issued:        " << metrics.prefetches_issued << "\n";
        std::cout << "Avg lead time:            " << std::fixed << std::setprecision(2) << metrics.avg_prefetch_lead_time_tokens << " tokens\n";
        std::cout << "Arriving before use:      " << std::setprecision(1) << metrics.pct_arriving_before_use << "%\n";
        std::cout << "Arriving late:            " << metrics.pct_arriving_late << "%\n";
    }
    
    void PrintAllReports(double total_decode_ns) const {
        PrintSubsystemReport(total_decode_ns);
        PrintResidencyReport();
        precision.PrintReport();
        PrintSchedulerReport();
        dispatch.PrintReport();
    }
};

// Global profiler instance
NEVMProfiler g_profiler;

//============================================================================
// C API for Integration
//============================================================================

extern "C" {

void NEVM_Profiler_Start(int component) {
    g_profiler.subsystem.Start(static_cast<SubsystemProfiler::Component>(component));
}

void NEVM_Profiler_Stop() {
    g_profiler.subsystem.Stop();
}

void NEVM_Profiler_Reset() {
    g_profiler.subsystem.Reset();
}

void NEVM_Profiler_PrintReport(double total_decode_ns) {
    g_profiler.PrintAllReports(total_decode_ns);
}

} // extern "C"
