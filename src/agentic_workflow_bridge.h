// ============================================================================
// agentic_workflow_bridge.h — Dependency-free bridge for Browser Testing &
//                               GitHub Cloud Agents
// ============================================================================
// Adapts the nlohmann/json-based BrowserTestEngine and GitHubIntegration
// modules to a plain C++ tool interface. No Qt, no external dependencies
// beyond the vendored nlohmann/json and the Windows SDK.
//
// Provides Cursor-like workflow tools:
//   Browser testing:  browser_navigate, browser_click, browser_type,
//                     browser_screenshot, browser_evaluate, browser_run_test
//   GitHub cloud:     github_create_pr, github_create_issue, github_review_pr,
//                     github_trigger_workflow, github_cloud_agent
//
// The bridge owns shared, lazily-initialized sessions (a Playwright browser
// and a GitHub client) so tool calls share state across an agent loop.
//
// Every tool takes a nlohmann::json parameter object and returns a
// nlohmann::json result object of the form:
//   { "success": bool, "tool": string, "data": object, "error": string? }
// ============================================================================

#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace RawrXD {
namespace Workflow {

using json = nlohmann::json;

// ---- Tool schemas ----------------------------------------------------------
// Returns the schemas for every workflow tool, to be merged into the
// agent's available-tool list. Each schema is a JSON object:
//   { "name", "description", "parameters": {...}, "required": [...] }
std::vector<json> workflowToolSchemas();

// ---- Dispatch --------------------------------------------------------------
// Handle a workflow tool call. Returns true if toolName is a workflow tool
// (and result is populated), false if the caller should handle it.
bool dispatchWorkflowTool(const std::string& toolName,
                          const json& params,
                          json& result);

// ---- Session management ----------------------------------------------------
// Reset shared browser/github sessions (used on workspace change or shutdown).
void resetWorkflowSessions();

} // namespace Workflow
} // namespace RawrXD
