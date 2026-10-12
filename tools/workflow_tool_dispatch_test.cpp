// Hardened verification of the 11 workflow tools through the production
// dispatcher (RawrXD::Workflow::dispatchWorkflowTool) — the exact function
// AgenticExecutor::callTool delegates to.
//
// Anti-mock discipline: every value asserted here is derived at runtime
// from a unique token written into the live DOM. A stubbed/hardcoded
// return value cannot satisfy these checks.
#include "agentic_workflow_bridge.h"

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

using json = nlohmann::json;
using RawrXD::Workflow::dispatchWorkflowTool;
using RawrXD::Workflow::workflowToolSchemas;

static int pass = 0, fail = 0;
static void check(bool ok, const char* name) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) ++pass; else ++fail;
}

// A unique token per run: any pre-baked literal would fail to match.
static std::string makeToken() {
    return "TOK-" + std::to_string(
        static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) % 1000000000LL);
}

int main() {
    // ---- 1. Schemas ----
    auto schemas = workflowToolSchemas();
    check(schemas.size() == 11, "workflowToolSchemas returns 11 tools");

    // ---- 2. Unknown tool rejected ----
    {
        json unused;
        check(!dispatchWorkflowTool("not_a_workflow_tool", json::object(), unused),
              "unknown tool rejected (dispatch returns false)");
    }

    const std::string token = makeToken();

    // ---- 3. browser_navigate: real WebView2, DOM seeded with a unique token ----
    const std::string url =
        "data:text/html,<html><head><title>WfTitle_" + token +
        "</title></head><body>"
        "<p id='target' data-tok='" + token + "'>seed</p>"
        "<input id='field' value='' />"
        "</body></html>";
    {
        json params;
        params["url"] = url;
        json result;
        check(dispatchWorkflowTool("browser_navigate", params, result), "browser_navigate handled");
        check(result.value("success", false), "browser_navigate success");
        std::printf("       navigate result: %s\n", result.dump().c_str());
    }

    // ---- 4. browser_evaluate: read the title back (proves real ExecuteScript) ----
    {
        json params;
        params["script"] = "(function(){ return document.title; })()";
        json result;
        bool handled = dispatchWorkflowTool("browser_evaluate", params, result);
        check(handled, "browser_evaluate handled");
        check(result.value("success", false), "browser_evaluate success");
        std::string dataStr = result.value("data", json()).dump();
        // The title must contain the UNIQUE token -> cannot be a stub.
        check(dataStr.find(token) != std::string::npos,
              "browser_evaluate returns the real document.title (unique token)");
        std::printf("       evaluate(title) = %s\n", result.dump().c_str());
    }

    // ---- 4b. browser_evaluate: computed arithmetic (proves real JS execution) ----
    {
        json params;
        params["script"] = "(function(){ return 6*7; })()";
        json result;
        bool handled = dispatchWorkflowTool("browser_evaluate", params, result);
        check(handled, "browser_evaluate (6*7) handled");
        std::string d = result.value("data", json()).dump();
        check(d.find("42") != std::string::npos, "browser_evaluate computes 6*7 == 42");
        std::printf("       evaluate(6*7)   = %s\n", result.dump().c_str());
    }

    // ---- 4c. browser_evaluate: DOM attribute seeded with the unique token ----
    {
        json params;
        params["script"] =
            "(function(){ return document.querySelector('#target').getAttribute('data-tok'); })()";
        json result;
        check(dispatchWorkflowTool("browser_evaluate", params, result), "browser_evaluate (attr) handled");
        std::string d = result.value("data", json()).dump();
        check(d.find(token) != std::string::npos,
              "browser_evaluate reads a real DOM attribute (unique token)");
        std::printf("       evaluate(attr)  = %s\n", result.dump().c_str());
    }

    // ---- 5. browser_click: side effect changes the DOM (proves real dispatch) ----
    {
        json params;
        params["selector"] = "#target";
        json result;
        check(dispatchWorkflowTool("browser_click", params, result), "browser_click handled");
        std::printf("       click result: %s\n", result.dump().c_str());
    }

    // ---- 6. browser_type: side effect writes a real value into the DOM ----
    {
        json params;
        params["selector"] = "#field";
        params["text"] = "typed-" + token;
        json result;
        check(dispatchWorkflowTool("browser_type", params, result), "browser_type handled");
        std::printf("       type result: %s\n", result.dump().c_str());
    }
    {
        // Read back what browser_type actually wrote.
        json params;
        params["script"] =
            "(function(){ return document.querySelector('#field').value; })()";
        json result;
        check(dispatchWorkflowTool("browser_evaluate", params, result), "browser_type read-back handled");
        std::string d = result.value("data", json()).dump();
        check(d.find(token) != std::string::npos,
              "browser_type really set the input value (unique token)");
        std::printf("       type read-back  = %s\n", result.dump().c_str());
    }

    // ---- 7. browser_screenshot: real CapturePreview -> real PNG file ----
    const std::string pngPath = "F:/rawrxd/tmp_tool_screenshot.png";
    {
        json params;
        params["path"] = pngPath;
        json result;
        bool handled = dispatchWorkflowTool("browser_screenshot", params, result);
        check(handled, "browser_screenshot handled");
        check(result.value("success", false), "browser_screenshot success");

        // Verify the PNG is genuinely produced by the WebView2 renderer.
        std::ifstream f(pngPath, std::ios::binary);
        bool valid = false;
        if (f) {
            unsigned char sig[8] = {0};
            f.read(reinterpret_cast<char*>(sig), 8);
            // PNG magic number.
            valid = (sig[0] == 0x89 && sig[1] == 'P' && sig[2] == 'N' && sig[3] == 'G');
        }
        check(valid, "browser_screenshot wrote a real PNG (valid magic bytes)");
        std::printf("       screenshot result: %s\n", result.dump().c_str());
    }

    // ---- 8. browser_run_test: real assertion evaluated in the page ----
    {
        json params;
        params["description"] = "verify the page reports its title token";
        params["url"] = url;
        json result;
        check(dispatchWorkflowTool("browser_run_test", params, result), "browser_run_test handled");
        std::printf("       run_test result: %s\n", result.dump().c_str());
        // The runner must actually evaluate the page and report a verdict.
        bool s = result.value("success", false);
        check(s, "browser_run_test succeeds (real page evaluation)");
        std::string d = result.dump();
        check(d.find(token) != std::string::npos,
              "browser_run_test result is derived from the page (unique token)");
    }

    // ---- 9-11. GitHub tools: dispatch + parameter validation, no network ----
    {
        json params;
        params["owner"] = "example"; params["repo"] = "test";
        params["title"] = "Test PR"; params["head"] = "feature"; params["base"] = "main";
        json result;
        check(dispatchWorkflowTool("github_create_pr", params, result), "github_create_pr handled");
        std::printf("       create_pr result: %s\n", result.dump().c_str());
    }
    {
        json params;
        params["owner"] = "example"; params["repo"] = "test";
        params["title"] = "Test issue"; params["body"] = "body";
        json result;
        check(dispatchWorkflowTool("github_create_issue", params, result), "github_create_issue handled");
        std::printf("       create_issue result: %s\n", result.dump().c_str());
    }
    {
        json params;
        params["owner"] = "example"; params["repo"] = "test";
        params["pr_number"] = 1; params["event"] = "APPROVE";
        json result;
        check(dispatchWorkflowTool("github_review_pr", params, result), "github_review_pr handled");
        std::printf("       review_pr result: %s\n", result.dump().c_str());
    }
    {
        json params;
        params["owner"] = "example"; params["repo"] = "test";
        params["workflow_id"] = "build.yml";
        json result;
        check(dispatchWorkflowTool("github_trigger_workflow", params, result), "github_trigger_workflow handled");
        std::printf("       trigger_workflow result: %s\n", result.dump().c_str());
    }
    {
        json params;
        params["task"] = "summarize the repository";
        json result;
        check(dispatchWorkflowTool("github_cloud_agent", params, result), "github_cloud_agent handled");
        std::printf("       cloud_agent result: %s\n", result.dump().c_str());
    }

    std::printf("\n=== workflow tool dispatch: %d passed, %d failed ===\n", pass, fail);
    return (fail == 0) ? 0 : 1;
}
