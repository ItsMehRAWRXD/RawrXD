// ============================================================================
// agentic_workflow_bridge.cpp — Dependency-free bridge for Browser Testing
//                                & GitHub Cloud Agents
// ============================================================================
// No Qt. Uses only the vendored nlohmann/json, the Windows SDK, and
// the BrowserTestEngine / GitHubIntegration modules.
// ============================================================================

#include "agentic_workflow_bridge.h"

#include "browser/BrowserTestEngine.hpp"
#include "github/GitHubIntegration.hpp"

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <chrono>
#include <cmath>
#include <mutex>
#include <future>
#include <utility>

using nlohmann::json;

namespace RawrXD {
namespace Workflow {

// ============================================================================
// Shared sessions (lazily initialized, shared across tool calls)
// ============================================================================

struct BrowserSession {
    std::shared_ptr<RawrXD::Browser::Playwright> playwright;
    std::shared_ptr<RawrXD::Browser::Browser> browser;
    std::shared_ptr<RawrXD::Browser::BrowserContext> context;
    std::shared_ptr<RawrXD::Browser::Page> page;
    std::mutex mutex;

    std::shared_ptr<RawrXD::Browser::Page> ensurePage()
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!playwright) {
            playwright = RawrXD::Browser::createPlaywright();
        }
        if (!browser) {
            browser = playwright->webview2Launch(json::object()).get();
        }
        if (!context) {
            context = browser->newContext().get();
        }
        if (!page) {
            page = context->newPage().get();
        }
        return page;
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(mutex);
        page.reset();
        context.reset();
        browser.reset();
        playwright.reset();
    }
};

struct GitHubSession {
    std::shared_ptr<RawrXD::GitHub::GitHubClient> client;
    std::mutex mutex;

    std::shared_ptr<RawrXD::GitHub::GitHubClient> ensureClient(const std::string& token)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!client) {
            RawrXD::GitHub::GitHubClient::Config cfg;
            cfg.token = token;
            cfg.baseUrl = "https://api.github.com";
            cfg.uploadUrl = "https://uploads.github.com";
            cfg.userAgent = "RawrXD-CloudAgent/1.0";
            client = std::make_shared<RawrXD::GitHub::GitHubClient>(cfg);
        }
        return client;
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(mutex);
        client.reset();
    }
};

static BrowserSession& browserSession()
{
    static BrowserSession s;
    return s;
}

static GitHubSession& githubSession()
{
    static GitHubSession s;
    return s;
}

void resetWorkflowSessions()
{
    browserSession().reset();
    githubSession().reset();
}

// ============================================================================
// JSON helpers
// ============================================================================

static json okResult(const std::string& tool, const json& data = json::object())
{
    json r;
    r["success"] = true;
    r["tool"] = tool;
    r["data"] = data;
    return r;
}

static json errResult(const std::string& tool, const std::string& message)
{
    json r;
    r["success"] = false;
    r["tool"] = tool;
    r["error"] = message;
    return r;
}

static std::string paramString(const json& params, const char* key)
{
    if (params.contains(key) && params[key].is_string())
        return params[key].get<std::string>();
    return std::string();
}

static int paramInt(const json& params, const char* key, int def)
{
    if (params.contains(key) && params[key].is_number_integer())
        return params[key].get<int>();
    return def;
}

static bool paramBool(const json& params, const char* key, bool def)
{
    if (params.contains(key) && params[key].is_boolean())
        return params[key].get<bool>();
    return def;
}

static std::vector<std::string> paramStringArray(const json& params, const char* key)
{
    std::vector<std::string> out;
    if (params.contains(key) && params[key].is_array()) {
        for (const auto& e : params[key]) {
            if (e.is_string()) out.push_back(e.get<std::string>());
        }
    }
    return out;
}

// ============================================================================
// Future helper — wait with timeout, return success flag
// ============================================================================

template<typename T>
static bool waitFuture(std::future<T>& fut, int timeoutMs, T& out)
{
    if (timeoutMs <= 0) {
        out = fut.get();
        return true;
    }
    auto status = fut.wait_for(std::chrono::milliseconds(timeoutMs));
    if (status != std::future_status::ready) {
        return false;
    }
    out = fut.get();
    return true;
}

// ============================================================================
// Browser tools
// ============================================================================

static json browserNavigate(const json& params)
{
    const std::string tool = "browser_navigate";
    if (!params.contains("url"))
        return errResult(tool, "Missing required parameter: url");

    std::string url = paramString(params, "url");
    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto page = browserSession().ensurePage();
        RawrXD::Browser::NavigateOptions opts;
        opts.timeoutMs = timeoutMs;
        bool ok = false;
        auto fut = page->gotoURL(url, opts);
        if (!waitFuture(fut, timeoutMs + 5000, ok) || !ok)
            return errResult(tool, "Navigation timed out or failed");

        json data;
        data["url"] = url;
        data["title"] = page->title().get();
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json browserClick(const json& params)
{
    const std::string tool = "browser_click";
    if (!params.contains("selector"))
        return errResult(tool, "Missing required parameter: selector");

    std::string selector = paramString(params, "selector");
    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto page = browserSession().ensurePage();
        RawrXD::Browser::ClickOptions opts;
        bool ok = false;
        auto fut = page->click(selector, opts);
        if (!waitFuture(fut, timeoutMs + 5000, ok) || !ok)
            return errResult(tool, "Click failed or timed out");

        json data;
        data["selector"] = selector;
        data["clicked"] = true;
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json browserType(const json& params)
{
    const std::string tool = "browser_type";
    if (!params.contains("selector"))
        return errResult(tool, "Missing required parameter: selector");
    if (!params.contains("text"))
        return errResult(tool, "Missing required parameter: text");

    std::string selector = paramString(params, "selector");
    std::string text = paramString(params, "text");
    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto page = browserSession().ensurePage();
        RawrXD::Browser::TypeOptions opts;
        bool ok = false;
        auto fut = page->type(selector, text, opts);
        if (!waitFuture(fut, timeoutMs + 5000, ok) || !ok)
            return errResult(tool, "Type failed or timed out");

        json data;
        data["selector"] = selector;
        data["typed"] = true;
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json browserScreenshot(const json& params)
{
    const std::string tool = "browser_screenshot";
    std::string path = paramString(params, "path");
    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto page = browserSession().ensurePage();
        RawrXD::Browser::ScreenshotOptions opts;
        opts.path = path;
        opts.fullPage = paramBool(params, "full_page", false);
        std::string resultPath;
        auto fut = page->screenshot(opts);
        if (!waitFuture(fut, timeoutMs + 5000, resultPath))
            return errResult(tool, "Screenshot timed out");

        json data;
        data["path"] = resultPath.empty() ? path : resultPath;
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json browserEvaluate(const json& params)
{
    const std::string tool = "browser_evaluate";
    if (!params.contains("script"))
        return errResult(tool, "Missing required parameter: script");

    std::string script = paramString(params, "script");
    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto page = browserSession().ensurePage();
        json arg = params.contains("arg") ? params["arg"] : json();
        json result;
        auto fut = page->evaluate(script, arg);
        if (!waitFuture(fut, timeoutMs + 5000, result))
            return errResult(tool, "Evaluate timed out");

        return okResult(tool, result);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json browserRunTest(const json& params)
{
    const std::string tool = "browser_run_test";
    if (!params.contains("description"))
        return errResult(tool, "Missing required parameter: description");
    if (!params.contains("url"))
        return errResult(tool, "Missing required parameter: url");

    RawrXD::Browser::BrowserTestTask task;
    task.description = paramString(params, "description");
    task.url = paramString(params, "url");
    task.assertions = paramStringArray(params, "assertions");

    int timeoutMs = paramInt(params, "timeout_ms", 120000);

    try {
        auto playwright = browserSession().playwright;
        if (!playwright) playwright = RawrXD::Browser::createPlaywright();
        auto agent = RawrXD::Browser::createBrowserTestAgent(playwright);
        RawrXD::Browser::BrowserTestResult result;
        auto fut = agent->executeTask(task);
        if (!waitFuture(fut, timeoutMs + 5000, result))
            return errResult(tool, "Browser test timed out");

        json data;
        data["success"] = result.success;
        data["summary"] = result.summary;
        data["steps"] = result.stepsExecuted;
        data["screenshots"] = result.screenshots;
        if (!result.error.empty())
            data["error"] = result.error;

        json r = okResult(tool, data);
        r["success"] = result.success;
        return r;
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

// ============================================================================
// GitHub tools
// ============================================================================

static std::string tokenFromParams(const json& params)
{
    if (params.contains("token") && params["token"].is_string())
        return params["token"].get<std::string>();
    // Fall back to environment variable.
    if (const char* env = std::getenv("GITHUB_TOKEN"))
        return std::string(env);
    return std::string();
}

static json githubCreatePR(const json& params)
{
    const std::string tool = "github_create_pr";
    if (!params.contains("owner"))
        return errResult(tool, "Missing required parameter: owner");
    if (!params.contains("repo"))
        return errResult(tool, "Missing required parameter: repo");
    if (!params.contains("title"))
        return errResult(tool, "Missing required parameter: title");
    if (!params.contains("head"))
        return errResult(tool, "Missing required parameter: head");

    std::string token = tokenFromParams(params);
    if (token.empty())
        return errResult(tool, "GitHub token required (set 'token' param or GITHUB_TOKEN env)");

    std::string owner = paramString(params, "owner");
    std::string repo = paramString(params, "repo");

    RawrXD::GitHub::PRCreateRequest req;
    req.title = paramString(params, "title");
    req.headBranch = paramString(params, "head");
    req.baseBranch = params.contains("base") ? paramString(params, "base") : "main";
    req.body = paramString(params, "body");
    req.labels = paramStringArray(params, "labels");

    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto client = githubSession().ensureClient(token);
        RawrXD::GitHub::PullRequest pr;
        auto fut = client->createPullRequest(owner, repo, req);
        if (!waitFuture(fut, timeoutMs + 5000, pr))
            return errResult(tool, "PR creation timed out");

        json data;
        data["number"] = pr.number;
        data["html_url"] = pr.htmlUrl;
        data["title"] = pr.title;
        data["state"] = pr.state;
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json githubCreateIssue(const json& params)
{
    const std::string tool = "github_create_issue";
    if (!params.contains("owner"))
        return errResult(tool, "Missing required parameter: owner");
    if (!params.contains("repo"))
        return errResult(tool, "Missing required parameter: repo");
    if (!params.contains("title"))
        return errResult(tool, "Missing required parameter: title");

    std::string token = tokenFromParams(params);
    if (token.empty())
        return errResult(tool, "GitHub token required (set 'token' param or GITHUB_TOKEN env)");

    std::string owner = paramString(params, "owner");
    std::string repo = paramString(params, "repo");

    RawrXD::GitHub::IssueCreateRequest req;
    req.title = paramString(params, "title");
    req.body = paramString(params, "body");
    req.labels = paramStringArray(params, "labels");

    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto client = githubSession().ensureClient(token);
        RawrXD::GitHub::Issue issue;
        auto fut = client->createIssue(owner, repo, req);
        if (!waitFuture(fut, timeoutMs + 5000, issue))
            return errResult(tool, "Issue creation timed out");

        json data;
        data["number"] = issue.number;
        data["html_url"] = issue.htmlUrl;
        data["title"] = issue.title;
        data["state"] = issue.state;
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json githubReviewPR(const json& params)
{
    const std::string tool = "github_review_pr";
    if (!params.contains("owner"))
        return errResult(tool, "Missing required parameter: owner");
    if (!params.contains("repo"))
        return errResult(tool, "Missing required parameter: repo");
    if (!params.contains("number"))
        return errResult(tool, "Missing required parameter: number");
    if (!params.contains("event"))
        return errResult(tool, "Missing required parameter: event (APPROVE/REQUEST_CHANGES/COMMENT)");

    std::string token = tokenFromParams(params);
    if (token.empty())
        return errResult(tool, "GitHub token required (set 'token' param or GITHUB_TOKEN env)");

    std::string owner = paramString(params, "owner");
    std::string repo = paramString(params, "repo");
    int number = paramInt(params, "number", 0);

    RawrXD::GitHub::ReviewRequest req;
    std::string event = paramString(params, "event");
    // Uppercase the event for comparison.
    for (auto& c : event) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (event == "APPROVE") req.state = RawrXD::GitHub::ReviewState::APPROVED;
    else if (event == "REQUEST_CHANGES") req.state = RawrXD::GitHub::ReviewState::CHANGES_REQUESTED;
    else req.state = RawrXD::GitHub::ReviewState::COMMENTED;
    req.body = paramString(params, "body");

    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto client = githubSession().ensureClient(token);
        RawrXD::GitHub::Review review;
        auto fut = client->createReview(owner, repo, number, req);
        if (!waitFuture(fut, timeoutMs + 5000, review))
            return errResult(tool, "Review submission timed out");

        json data;
        data["id"] = review.id;
        data["author"] = review.author;
        data["html_url"] = review.htmlUrl;
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json githubTriggerWorkflow(const json& params)
{
    const std::string tool = "github_trigger_workflow";
    if (!params.contains("owner"))
        return errResult(tool, "Missing required parameter: owner");
    if (!params.contains("repo"))
        return errResult(tool, "Missing required parameter: repo");
    if (!params.contains("workflow_id"))
        return errResult(tool, "Missing required parameter: workflow_id");
    if (!params.contains("ref"))
        return errResult(tool, "Missing required parameter: ref");

    std::string token = tokenFromParams(params);
    if (token.empty())
        return errResult(tool, "GitHub token required (set 'token' param or GITHUB_TOKEN env)");

    std::string owner = paramString(params, "owner");
    std::string repo = paramString(params, "repo");
    std::string workflowId = paramString(params, "workflow_id");

    RawrXD::GitHub::WorkflowDispatchRequest req;
    req.ref = paramString(params, "ref");
    if (params.contains("inputs") && params["inputs"].is_object())
        req.inputs = params["inputs"];

    int timeoutMs = paramInt(params, "timeout_ms", 30000);

    try {
        auto client = githubSession().ensureClient(token);
        bool ok = false;
        auto fut = client->dispatchWorkflow(owner, repo, workflowId, req);
        if (!waitFuture(fut, timeoutMs + 5000, ok) || !ok)
            return errResult(tool, "Workflow dispatch failed or timed out");

        json data;
        data["workflow_id"] = workflowId;
        data["ref"] = req.ref;
        data["dispatched"] = true;
        return okResult(tool, data);
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

static json githubRunCloudAgent(const json& params)
{
    const std::string tool = "github_cloud_agent";
    if (!params.contains("repository"))
        return errResult(tool, "Missing required parameter: repository");
    if (!params.contains("description"))
        return errResult(tool, "Missing required parameter: description");

    std::string token = tokenFromParams(params);
    if (token.empty())
        return errResult(tool, "GitHub token required (set 'token' param or GITHUB_TOKEN env)");

    RawrXD::GitHub::CloudAgentConfig cfg;
    cfg.githubToken = token;
    cfg.workingDirectory = params.contains("working_directory") ? paramString(params, "working_directory") : ".rawrxd_cloud";
    cfg.modelEndpoint = params.contains("model_endpoint") ? paramString(params, "model_endpoint") : "http://localhost:11434";
    cfg.maxStepsPerTask = paramInt(params, "max_steps", 50);
    cfg.taskTimeoutMinutes = paramInt(params, "timeout_minutes", 60);
    cfg.autoMerge = paramBool(params, "auto_merge", false);

    RawrXD::GitHub::CloudAgentTask task;
    task.id = paramString(params, "task_id");
    if (task.id.empty()) task.id = "task-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    task.description = paramString(params, "description");
    task.repository = paramString(params, "repository");
    task.branch = paramString(params, "branch");
    task.baseBranch = params.contains("base_branch") ? paramString(params, "base_branch") : "main";
    task.labels = paramStringArray(params, "labels");

    int timeoutMs = cfg.taskTimeoutMinutes * 60 * 1000 + 30000;

    try {
        auto agent = RawrXD::GitHub::createCloudAgent(cfg);
        if (!agent->initialize())
            return errResult(tool, "Cloud agent failed to initialize");

        RawrXD::GitHub::CloudAgentResult result;
        auto fut = agent->executeTask(task);
        if (!waitFuture(fut, timeoutMs, result))
            return errResult(tool, "Cloud agent task timed out");

        json data;
        data["success"] = result.success;
        data["task_id"] = result.taskId;
        data["summary"] = result.summary;
        data["branch_name"] = result.branchName;
        data["pr_number"] = result.prNumber;
        data["pr_url"] = result.prUrl;
        data["files_changed"] = result.filesChanged;
        data["steps_executed"] = result.stepsExecuted;
        if (!result.error.empty())
            data["error"] = result.error;

        json r = okResult(tool, data);
        r["success"] = result.success;
        return r;
    } catch (const std::exception& e) {
        return errResult(tool, e.what());
    }
}

// ============================================================================
// Tool schemas
// ============================================================================

static json paramObj(const std::string& type, const std::string& desc)
{
    json p;
    p["type"] = type;
    p["description"] = desc;
    return p;
}

static json schema(const std::string& name, const std::string& desc,
                   const json& params, const std::vector<std::string>& required)
{
    json s;
    s["name"] = name;
    s["description"] = desc;
    s["parameters"] = params;
    s["required"] = required;
    return s;
}

std::vector<json> workflowToolSchemas()
{
    std::vector<json> tools;

    // Browser testing tools
    {
        json p;
        p["url"] = paramObj("string", "URL to navigate to");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("browser_navigate", "Navigate the browser to a URL", p, {"url"}));
    }
    {
        json p;
        p["selector"] = paramObj("string", "CSS selector of the element to click");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("browser_click", "Click an element matching a CSS selector", p, {"selector"}));
    }
    {
        json p;
        p["selector"] = paramObj("string", "CSS selector of the element to type into");
        p["text"] = paramObj("string", "Text to type");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("browser_type", "Type text into an element matching a CSS selector", p, {"selector", "text"}));
    }
    {
        json p;
        p["path"] = paramObj("string", "Output path for the screenshot");
        p["full_page"] = paramObj("boolean", "Capture the full scrollable page");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("browser_screenshot", "Capture a screenshot of the current page", p, {}));
    }
    {
        json p;
        p["script"] = paramObj("string", "JavaScript to evaluate in the page");
        p["arg"] = paramObj("object", "Optional argument passed to the script");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("browser_evaluate", "Evaluate JavaScript in the current page and return the result", p, {"script"}));
    }
    {
        json p;
        p["description"] = paramObj("string", "Natural-language description of the test to run");
        p["url"] = paramObj("string", "Starting URL for the test");
        p["assertions"] = paramObj("array", "List of assertions to verify");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("browser_run_test", "Run an AI-driven browser test from a natural-language description", p, {"description", "url"}));
    }

    // GitHub cloud agent tools
    {
        json p;
        p["owner"] = paramObj("string", "Repository owner");
        p["repo"] = paramObj("string", "Repository name");
        p["title"] = paramObj("string", "PR title");
        p["body"] = paramObj("string", "PR description body");
        p["head"] = paramObj("string", "Head branch (source)");
        p["base"] = paramObj("string", "Base branch (target, default main)");
        p["labels"] = paramObj("array", "Labels to apply");
        p["token"] = paramObj("string", "GitHub personal access token (or GITHUB_TOKEN env)");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("github_create_pr", "Create a pull request on GitHub", p, {"owner", "repo", "title", "head"}));
    }
    {
        json p;
        p["owner"] = paramObj("string", "Repository owner");
        p["repo"] = paramObj("string", "Repository name");
        p["title"] = paramObj("string", "Issue title");
        p["body"] = paramObj("string", "Issue body");
        p["labels"] = paramObj("array", "Labels to apply");
        p["token"] = paramObj("string", "GitHub personal access token (or GITHUB_TOKEN env)");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("github_create_issue", "Create an issue on GitHub", p, {"owner", "repo", "title"}));
    }
    {
        json p;
        p["owner"] = paramObj("string", "Repository owner");
        p["repo"] = paramObj("string", "Repository name");
        p["number"] = paramObj("integer", "Pull request number");
        p["event"] = paramObj("string", "Review event: APPROVE, REQUEST_CHANGES, or COMMENT");
        p["body"] = paramObj("string", "Review comment body");
        p["token"] = paramObj("string", "GitHub personal access token (or GITHUB_TOKEN env)");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("github_review_pr", "Submit a review on a pull request", p, {"owner", "repo", "number", "event"}));
    }
    {
        json p;
        p["owner"] = paramObj("string", "Repository owner");
        p["repo"] = paramObj("string", "Repository name");
        p["workflow_id"] = paramObj("string", "Workflow ID or filename");
        p["ref"] = paramObj("string", "Branch or tag to run the workflow on");
        p["inputs"] = paramObj("object", "Workflow inputs");
        p["token"] = paramObj("string", "GitHub personal access token (or GITHUB_TOKEN env)");
        p["timeout_ms"] = paramObj("integer", "Timeout in milliseconds");
        tools.push_back(schema("github_trigger_workflow", "Trigger a GitHub Actions workflow", p, {"owner", "repo", "workflow_id", "ref"}));
    }
    {
        json p;
        p["repository"] = paramObj("string", "Target repository as owner/repo");
        p["description"] = paramObj("string", "Natural-language task for the cloud agent");
        p["branch"] = paramObj("string", "Branch to create (auto-generated if empty)");
        p["base_branch"] = paramObj("string", "Base branch for the PR (default main)");
        p["labels"] = paramObj("array", "Labels for the PR");
        p["working_directory"] = paramObj("string", "Local clone directory");
        p["model_endpoint"] = paramObj("string", "LLM endpoint for code generation");
        p["max_steps"] = paramObj("integer", "Maximum agent steps");
        p["timeout_minutes"] = paramObj("integer", "Task timeout in minutes");
        p["auto_merge"] = paramObj("boolean", "Auto-merge the PR after creation");
        p["token"] = paramObj("string", "GitHub personal access token (or GITHUB_TOKEN env)");
        tools.push_back(schema("github_cloud_agent", "Run an autonomous cloud agent that completes a task and submits a PR", p, {"repository", "description"}));
    }

    return tools;
}

// ============================================================================
// Dispatch
// ============================================================================

bool dispatchWorkflowTool(const std::string& toolName,
                          const json& params,
                          json& result)
{
    if (toolName == "browser_navigate")        { result = browserNavigate(params); return true; }
    if (toolName == "browser_click")           { result = browserClick(params); return true; }
    if (toolName == "browser_type")            { result = browserType(params); return true; }
    if (toolName == "browser_screenshot")      { result = browserScreenshot(params); return true; }
    if (toolName == "browser_evaluate")        { result = browserEvaluate(params); return true; }
    if (toolName == "browser_run_test")        { result = browserRunTest(params); return true; }
    if (toolName == "github_create_pr")        { result = githubCreatePR(params); return true; }
    if (toolName == "github_create_issue")     { result = githubCreateIssue(params); return true; }
    if (toolName == "github_review_pr")        { result = githubReviewPR(params); return true; }
    if (toolName == "github_trigger_workflow") { result = githubTriggerWorkflow(params); return true; }
    if (toolName == "github_cloud_agent")      { result = githubRunCloudAgent(params); return true; }
    return false;
}

} // namespace Workflow
} // namespace RawrXD
