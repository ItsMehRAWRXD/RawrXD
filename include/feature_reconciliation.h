/**
 * Feature Reconciliation Layer Header
 * 
 * Bridges Failure Mode Firewall with Feature Registry
 */

#pragma once

#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize reconciliation layer at startup
void InitializeFeatureReconciliation();

// Update reconciliation from FMF telemetry
void UpdateFeatureReconciliation();

// Generate reconciliation report
const char* GetFeatureReconciliationReport();

// Export reconciliation to JSON
void ExportFeatureReconciliationJSON(const char* filepath);

// Check if feature is safe to use
bool IsFeatureSafe(const char* featureName);

// Get features by risk level
const char** GetFeaturesByRisk(const char* riskLevel, int* count);

#ifdef __cplusplus
}
#endif