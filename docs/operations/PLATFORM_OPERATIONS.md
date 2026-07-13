# Phase P.5/5: Platform Operations Guide

## Platform Operations Guide

This guide covers RawrXD's platform operations capabilities including cost tracking, auto-scaling, resource optimization, and maintenance scheduling.

---

## Table of Contents

1. [Cost Tracking](#cost-tracking)
2. [Auto-Scaling](#auto-scaling)
3. [Resource Optimization](#resource-optimization)
4. [Maintenance Scheduling](#maintenance-scheduling)
5. [Best Practices](#best-practices)

---

## Cost Tracking

### Overview

Track infrastructure costs with detailed breakdowns by resource, tenant, and model.

### Quick Start

```cpp
#include <RawrXD/Operations/CostTracker.hpp>

// Initialize cost tracking
RawrXD::Operations::InitializeCostTracking("/config/cost-rates.yaml");

// Set cost rates
RawrXD::Operations::CostRate gpu_rate{
    .resource_type = RawrXD::Operations::ResourceType::GPU_COMPUTE,
    .region = "us-east-1",
    .rate_per_unit = 2.50,  // $2.50 per hour
    .unit = "hour"
};
g_cost_tracker->SetCostRate(gpu_rate);
```

### Recording Usage

```cpp
// Record GPU usage
RawrXD::Operations::ResourceUsage usage{
    .resource_id = "gpu-worker-1",
    .type = RawrXD::Operations::ResourceType::GPU_COMPUTE,
    .tenant_id = "tenant-123",
    .user_id = "user-456",
    .model_id = "llama-3-8b",
    .quantity = 2.5,  // 2.5 hours
    .unit = "hour",
    .start_time = start,
    .end_time = end
};

g_cost_tracker->RecordUsage(usage);

// Cost is automatically calculated
auto cost = g_cost_tracker->CalculateCost(usage);
std::cout << "Cost: $" << cost.cost_amount << "\n";
```

### Budget Management

```cpp
// Create budget
RawrXD::Operations::BudgetConfig budget{
    .id = "budget-1",
    .name = "Production Budget",
    .tenant_id = "tenant-123",
    .monthly_limit = 10000.0,  // $10,000/month
    .alert_threshold_50 = true,
    .alert_threshold_80 = true,
    .alert_threshold_100 = true,
    .enforce_limit = true  // Hard stop at limit
};

g_cost_tracker->CreateBudget(budget);

// Check utilization
double utilization = g_cost_tracker->GetBudgetUtilization("budget-1");
if (utilization > 0.8) {
    std::cout << "Warning: Budget at " << (utilization * 100) << "%\n";
}
```

### Cost Forecasting

```cpp
// Forecast next 30 days
auto forecast = g_cost_tracker->GetSpendForecast(
    "tenant-123",
    90,   // 90 days of history
    30    // 30 days to forecast
);

for (size_t i = 0; i < forecast.size(); i++) {
    std::cout << "Day " << i << ": $" << forecast[i] << "\n";
}
```

---

## Auto-Scaling

### Overview

Automatically scale resources based on demand, metrics, and schedules.

### Target Tracking Policy

```cpp
#include <RawrXD/Operations/AutoScaler.hpp>

// Create target tracking policy
RawrXD::Operations::ScalingPolicy policy{
    .id = "policy-1",
    .name = "GPU Utilization Target",
    .type = RawrXD::Operations::ScalingPolicyType::TARGET_TRACKING,
    .target_resource = "inference-pool",
    .target_tracking = {
        .metric = RawrXD::Operations::ScalingMetric::GPU_UTILIZATION,
        .target_value = 70.0,  // Target 70% GPU utilization
        .scale_out_cooldown_seconds = 300,
        .scale_in_cooldown_seconds = 600
    },
    .min_capacity = 2,
    .max_capacity = 20
};

std::string policy_id = g_auto_scaler->CreatePolicy(policy);
g_auto_scaler->EnablePolicy(policy_id);
```

### Step Scaling Policy

```cpp
RawrXD::Operations::ScalingPolicy step_policy{
    .id = "policy-2",
    .name = "Step Scaling",
    .type = RawrXD::Operations::ScalingPolicyType::STEP_SCALING,
    .target_resource = "inference-pool",
    .step_scaling = {
        .steps = {
            {.metric_lower_bound = 0, .metric_upper_bound = 30, .scaling_adjustment = -2},
            {.metric_lower_bound = 30, .metric_upper_bound = 70, .scaling_adjustment = 0},
            {.metric_lower_bound = 70, .metric_upper_bound = 100, .scaling_adjustment = 2}
        },
        .aggregation_period_seconds = 60
    },
    .min_capacity = 2,
    .max_capacity = 20
};
```

### Scheduled Scaling

```cpp
RawrXD::Operations::ScalingPolicy scheduled_policy{
    .id = "policy-3",
    .name = "Business Hours Scale",
    .type = RawrXD::Operations::ScalingPolicyType::SCHEDULED,
    .target_resource = "inference-pool",
    .scheduled_scaling = {
        .schedule_expression = "0 9 * * 1-5",  // 9 AM weekdays
        .min_capacity = 5,
        .max_capacity = 20,
        .desired_capacity = 10
    }
};
```

### Submitting Metrics

```cpp
RawrXD::Operations::ResourceMetrics metrics{
    .resource_id = "inference-pool",
    .timestamp = std::chrono::system_clock::now(),
    .gpu_utilization_percent = 75.0,
    .gpu_memory_utilization_percent = 60.0,
    .request_latency_ms_p99 = 150.0,
    .active_requests = 45
};

g_auto_scaler->SubmitMetrics(metrics);
```

---

## Resource Optimization

### Overview

Analyze and optimize resource utilization for cost efficiency.

### Analyzing Resources

```cpp
#include <RawrXD/Operations/ResourceOptimizer.hpp>

// Analyze specific resource
auto metrics = g_resource_optimizer->AnalyzeResource(
    "gpu-worker-1",
    std::chrono::hours(168)  // 1 week lookback
);

std::cout << "GPU Utilization: " << metrics.gpu_utilization_avg << "%\n";
std::cout << "Cost per token: $" << metrics.cost_per_token << "\n";
std::cout << "Idle time: " << metrics.idle_time_percentage << "%\n";
```

### Generating Recommendations

```cpp
// Get all recommendations
auto recommendations = g_resource_optimizer->GenerateRecommendations();

for (const auto& rec : recommendations) {
    std::cout << rec.title << ":\n";
    std::cout << "  Savings: $" << rec.impact.cost_savings_monthly << "/month\n";
    std::cout << "  Effort: " << rec.implementation_effort_hours << " hours\n";
    
    if (rec.can_auto_apply) {
        g_resource_optimizer->ApplyRecommendation(rec.id);
    }
}
```

### Right-Sizing

```cpp
// Get right-sizing recommendation
auto right_size = g_resource_optimizer->RecommendRightSizing("gpu-worker-1");

if (right_size) {
    std::cout << "Current: " << right_size->current_metrics.gpu_memory_allocated_mb << " MB\n";
    std::cout << "Recommended: " << right_size->action.target_config << "\n";
    std::cout << "Savings: $" << right_size->impact.cost_savings_monthly << "/month\n";
}
```

### Bin Packing

```cpp
// Optimize workload placement
std::vector<RawrXD::Operations::WorkloadProfile> workloads = {
    // Define workloads...
};

auto result = g_resource_optimizer->OptimizeBinPacking(
    workloads,
    24576  // 24GB GPU memory per bin
);

std::cout << "Bins needed: " << result.total_bins_needed << "\n";
std::cout << "Bins saved: " << result.total_bins_saved << "\n";
```

---

## Maintenance Scheduling

### Overview

Schedule and manage planned maintenance windows.

### Creating Maintenance Windows

```cpp
#include <RawrXD/Operations/MaintenanceScheduler.hpp>

// Create maintenance window
RawrXD::Operations::MaintenanceWindow window{
    .name = "Security Patch",
    .description = "Apply critical security updates",
    .type = RawrXD::Operations::MaintenanceType::SECURITY_PATCH,
    .impact_level = RawrXD::Operations::ImpactLevel::MEDIUM,
    .scheduled_start = std::chrono::system_clock::now() + std::chrono::hours(24),
    .scheduled_end = std::chrono::system_clock::now() + std::chrono::hours(26),
    .estimated_duration = std::chrono::minutes(90),
    .affected_services = {"inference-api", "model-registry"},
    .tasks = {
        {.id = "task-1", .name = "Backup", .command = "backup.sh", .timeout_seconds = 300},
        {.id = "task-2", .name = "Patch", .command = "patch.sh", .timeout_seconds = 600},
        {.id = "task-3", .name = "Verify", .command = "verify.sh", .timeout_seconds = 300}
    }
};

std::string window_id = g_maintenance_scheduler->CreateWindow(window);
```

### Recurring Schedules

```cpp
RawrXD::Operations::RecurringSchedule schedule{
    .name = "Weekly Backup",
    .type = RawrXD::Operations::MaintenanceType::BACKUP,
    .schedule_expression = "0 2 * * 0",  // Sundays at 2 AM
    .duration = std::chrono::minutes(60),
    .target_services = {"database", "object-storage"},
    .auto_approve = true,
    .enabled = true
};

std::string schedule_id = g_maintenance_scheduler->CreateRecurringSchedule(schedule);
```

### Approval Workflow

```cpp
// Request approval
g_maintenance_scheduler->RequestApproval(window_id);

// Approve (as administrator)
g_maintenance_scheduler->ApproveWindow(
    window_id,
    "admin@company.com",
    "Approved for deployment"
);
```

### Execution

```cpp
// Start maintenance
g_maintenance_scheduler->StartWindow(window_id);

// Execute individual tasks
for (const auto& task : window.tasks) {
    bool success = g_maintenance_scheduler->ExecuteTask(window_id, task.id);
    if (!success) {
        // Rollback if needed
        g_maintenance_scheduler->RollbackTask(window_id, task.id);
        break;
    }
}

// Complete maintenance
g_maintenance_scheduler->CompleteWindow(window_id, "All tasks completed successfully");
```

---

## Best Practices

### Cost Management

1. **Set budgets early**: Define budgets before production deployment
2. **Use alerts**: Configure alerts at 50%, 80%, and 100%
3. **Tag resources**: Tag all resources for accurate allocation
4. **Review regularly**: Weekly cost reviews
5. **Optimize continuously**: Apply recommendations monthly

### Auto-Scaling

1. **Start conservative**: Use target tracking with 70% utilization
2. **Set cooldowns**: Prevent flapping with 5-minute cooldowns
3. **Test policies**: Validate in staging first
4. **Monitor costs**: Ensure scaling doesn't break budget
5. **Use predictive**: Enable predictive scaling for known patterns

### Resource Optimization

1. **Analyze weekly**: Regular utilization analysis
2. **Right-size quarterly**: Adjust resource allocations
3. **Use spot instances**: For fault-tolerant workloads
4. **Implement bin packing**: Maximize GPU utilization
5. **Monitor efficiency**: Track tokens per dollar

### Maintenance

1. **Schedule regularly**: Weekly maintenance windows
2. **Communicate early**: Notify users 48 hours in advance
3. **Test procedures**: Validate rollback procedures
4. **Monitor health**: Pre and post-maintenance checks
5. **Document everything**: Keep detailed maintenance logs

---

## Integration Example

Complete operational workflow:

```cpp
// 1. Initialize all operations systems
RawrXD::Operations::InitializeCostTracking("cost-config.yaml");
RawrXD::Operations::InitializeAutoScaling("scaling-config.yaml");
RawrXD::Operations::InitializeResourceOptimization("optimization-config.yaml");
RawrXD::Operations::InitializeMaintenanceScheduling("maintenance-config.yaml");

// 2. Set up cost tracking with budget
RawrXD::Operations::BudgetConfig budget{
    .name = "Production",
    .monthly_limit = 50000.0,
    .alert_threshold_80 = true,
    .enforce_limit = true
};
g_cost_tracker->CreateBudget(budget);

// 3. Configure auto-scaling
RawrXD::Operations::ScalingPolicy policy{
    .name = "GPU Target",
    .type = RawrXD::Operations::ScalingPolicyType::TARGET_TRACKING,
    .target_tracking = {
        .metric = RawrXD::Operations::ScalingMetric::GPU_UTILIZATION,
        .target_value = 70.0
    },
    .min_capacity = 2,
    .max_capacity = 50
};
g_auto_scaler->CreatePolicy(policy);

// 4. Schedule weekly optimization
RawrXD::Operations::RecurringSchedule optimization{
    .name = "Weekly Optimization",
    .type = RawrXD::Operations::MaintenanceType::CUSTOM,
    .schedule_expression = "0 3 * * 1",  // Mondays at 3 AM
    .tasks = {
        {.name = "Analyze", .command = "optimize.sh"}
    },
    .auto_approve = true
};
g_maintenance_scheduler->CreateRecurringSchedule(optimization);

// 5. Record usage and costs
RawrXD::Operations::ResourceUsage usage{
    .type = RawrXD::Operations::ResourceType::GPU_COMPUTE,
    .quantity = 1.0,
    .unit = "hour"
};
g_cost_tracker->RecordUsage(usage);

// 6. Generate monthly report
g_cost_tracker->GenerateCostReport(
    "/reports/monthly-cost.csv",
    month_start,
    month_end,
    "csv"
);
```

---

## API Reference

See header files for complete API:
- `src/operations/CostTracker.hpp`
- `src/operations/AutoScaler.hpp`
- `src/operations/ResourceOptimizer.hpp`
- `src/operations/MaintenanceScheduler.hpp`

---

**Document Version:** 1.0.0
**Last Updated:** 2026-07-13
**RawrXD Version:** 1.0.0+
