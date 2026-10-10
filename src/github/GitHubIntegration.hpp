// ============================================================================
// GitHubIntegration.hpp — GitHub API Integration for Cloud Agents
// ============================================================================
// Provides Cursor-like cloud agent capabilities:
//   - Repository operations (clone, fork, branch)
//   - PR creation, review, merge
//   - Issue management
//   - Code review comments
//   - Workflow dispatch (GitHub Actions)
//   - Webhook handling
//   - Integration with Agent framework for autonomous PR submission
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <future>
#include <chrono>
#include <atomic>
#include <mutex>
#include <optional>
#include <variant>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace GitHub {

using json = nlohmann::json;

// ============================================================================
// Core Types
// ============================================================================

enum class PRState {
    OPEN,
    CLOSED,
    MERGED,
    ALL
};

enum class PRMergeMethod {
    MERGE,      // Create a merge commit
    SQUASH,     // Squash commits into one
    REBASE      // Rebase and merge
};

enum class IssueState {
    OPEN,
    CLOSED,
    ALL
};

enum class ReviewState {
    APPROVED,
    CHANGES_REQUESTED,
    COMMENTED,
    PENDING
};

enum class EventType {
    PUSH,
    PULL_REQUEST,
    ISSUES,
    ISSUE_COMMENT,
    COMMIT_COMMENT,
    REVIEW,
    WORKFLOW_RUN,
    RELEASE,
    FORK,
    STAR,
    WATCH
};

struct Repository {
    std::string owner;
    std::string name;
    std::string fullName;      // "owner/name"
    std::string description;
    std::string htmlUrl;
    std::string cloneUrl;
    std::string sshUrl;
    std::string defaultBranch;
    bool isPrivate = false;
    bool isFork = false;
    int starCount = 0;
    int forkCount = 0;
    int openIssuesCount = 0;
    std::string language;
    json metadata;
};

struct Branch {
    std::string name;
    std::string sha;
    std::string commitUrl;
    bool isProtected = false;
    json protection;
};

struct Commit {
    std::string sha;
    std::string message;
    std::string authorName;
    std::string authorEmail;
    std::string committerName;
    std::string committerEmail;
    std::chrono::system_clock::time_point date;
    std::string htmlUrl;
    std::vector<std::string> parentShas;
    json stats;  // additions, deletions, total
    std::vector<json> files;
};

struct PullRequest {
    int number;
    std::string title;
    std::string body;
    std::string state;         // "open", "closed", "merged"
    bool merged = false;
    bool mergeable = false;
    bool rebaseable = false;
    std::string mergeableState;  // "clean", "dirty", "unknown"
    std::string headBranch;
    std::string baseBranch;
    std::string headSha;
    std::string baseSha;
    std::string htmlUrl;
    std::string diffUrl;
    std::string patchUrl;
    std::string author;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    std::optional<std::chrono::system_clock::time_point> closedAt;
    std::optional<std::chrono::system_clock::time_point> mergedAt;
    std::optional<std::string> mergeCommitSha;
    int reviewComments = 0;
    int comments = 0;
    int commits = 0;
    int additions = 0;
    int deletions = 0;
    int changedFiles = 0;
    std::vector<std::string> labels;
    std::vector<std::string> assignees;
    std::vector<std::string> reviewers;
    json metadata;
};

struct PRCreateRequest {
    std::string title;
    std::string body;
    std::string headBranch;
    std::string baseBranch;
    std::vector<std::string> labels;
    std::vector<std::string> assignees;
    std::vector<std::string> reviewers;
    bool maintainerCanModify = true;
};

struct PRUpdateRequest {
    std::optional<std::string> title;
    std::optional<std::string> body;
    std::optional<std::string> state;
    std::optional<std::vector<std::string>> labels;
    std::optional<std::vector<std::string>> assignees;
};

struct Review {
    std::string id;
    std::string author;
    ReviewState state;
    std::string body;
    std::chrono::system_clock::time_point submittedAt;
    std::string htmlUrl;
    std::vector<json> comments;
};

struct ReviewRequest {
    ReviewState state;
    std::string body;
    std::vector<json> comments;  // Inline comments
    std::string commitId;        // Optional: specific commit to review
};

struct ReviewComment {
    std::string id;
    std::string path;
    int line = 0;
    int startLine = 0;
    std::string body;
    std::string author;
    std::chrono::system_clock::time_point createdAt;
    std::string htmlUrl;
    std::string diffHunk;
};

struct Issue {
    int number;
    std::string title;
    std::string body;
    std::string state;
    bool isPullRequest = false;
    std::string author;
    std::vector<std::string> labels;
    std::vector<std::string> assignees;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    std::optional<std::chrono::system_clock::time_point> closedAt;
    int comments = 0;
    std::string htmlUrl;
    json metadata;
};

struct IssueCreateRequest {
    std::string title;
    std::string body;
    std::vector<std::string> labels;
    std::vector<std::string> assignees;
    std::optional<int> milestone;
};

struct IssueUpdateRequest {
    std::optional<std::string> title;
    std::optional<std::string> body;
    std::optional<std::string> state;
    std::optional<std::vector<std::string>> labels;
    std::optional<std::vector<std::string>> assignees;
};

struct IssueComment {
    std::string id;
    std::string body;
    std::string author;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    std::string htmlUrl;
};

struct CommentCreateRequest {
    std::string body;
};

struct WorkflowRun {
    long long id;
    std::string name;
    std::string status;      // "queued", "in_progress", "completed"
    std::string conclusion;  // "success", "failure", "cancelled"
    std::string branch;
    std::string sha;
    std::string event;       // "push", "pull_request"
    std::string htmlUrl;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point updatedAt;
    std::chrono::system_clock::time_point runStartedAt;
    int runNumber = 0;
    std::string workflowId;
};

struct WorkflowDispatchRequest {
    std::string ref;  // Branch or tag
    json inputs;      // Workflow inputs
};

struct Release {
    int id;
    std::string tagName;
    std::string name;
    std::string body;
    bool isDraft = false;
    bool isPrerelease = false;
    std::string htmlUrl;
    std::chrono::system_clock::time_point publishedAt;
    std::chrono::system_clock::time_point createdAt;
    std::vector<json> assets;
};

struct ReleaseCreateRequest {
    std::string tagName;
    std::optional<std::string> name;
    std::optional<std::string> body;
    bool isDraft = false;
    bool isPrerelease = false;
    std::optional<std::string> targetCommitish;
};

struct FileContent {
    std::string path;
    std::string content;  // Base64 encoded
    std::string sha;
    int size = 0;
    std::string encoding;
    std::string downloadUrl;
};

struct FileCreateRequest {
    std::string path;
    std::string content;  // Will be base64 encoded
    std::string message;
    std::optional<std::string> branch;
    std::optional<std::string> sha;  // For updates
};

struct TreeEntry {
    std::string path;
    std::string mode;   // "100644" file, "100755" executable, "040000" dir, "120000" symlink, "160000" submodule
    std::string type;   // "blob", "tree", "commit"
    std::optional<std::string> sha;
    std::optional<std::string> content;
};

struct TreeCreateRequest {
    std::string baseTree;  // Optional: SHA of base tree
    std::vector<TreeEntry> entries;
};

struct SearchResult {
    int totalCount = 0;
    bool incompleteResults = false;
    json items;
};

struct SearchRequest {
    std::string query;
    std::string sort;      // "stars", "forks", "help-wanted-issues", "best-match"
    std::string order;     // "asc", "desc"
    int perPage = 30;
    int page = 1;
};

struct WebhookEvent {
    EventType type;
    std::string deliveryId;
    json payload;
    std::string signature;  // HMAC-SHA256 signature
    std::chrono::system_clock::time_point receivedAt;
};

struct WebhookConfig {
    std::string url;
    std::string contentType;  // "json", "form"
    std::string secret;
    bool insecureSsl = false;
    std::vector<EventType> events;
    bool active = true;
};

// ============================================================================
// GitHub Client — REST API + GraphQL
// ============================================================================

class GitHubClient {
public:
    struct Config {
        std::string token;              // Personal access token
        std::string baseUrl;            // API base URL (default: https://api.github.com)
        std::string uploadUrl;          // Upload URL (default: https://uploads.github.com)
        std::string userAgent;          // User-Agent header
        int timeoutMs = 30000;
        int maxRetries = 3;
        int retryDelayMs = 1000;
        bool followRedirects = true;
        std::map<std::string, std::string> extraHeaders;
    };

    explicit GitHubClient(const Config& config);
    ~GitHubClient();

    // Authentication
    bool authenticate();
    bool isAuthenticated() const;
    std::string getToken() const;
    void setToken(const std::string& token);

    // Rate limit
    struct RateLimit {
        int limit = 0;
        int remaining = 0;
        int resetTime = 0;
        bool isExceeded() const { return remaining <= 0; }
    };
    RateLimit getRateLimit() const;

    // User
    json getCurrentUser();
    json getUser(const std::string& username);

    // Repository operations
    std::future<Repository> getRepository(const std::string& owner, const std::string& repo);
    std::future<Repository> createRepository(const std::string& name, const json& options = json());
    std::future<bool> deleteRepository(const std::string& owner, const std::string& repo);
    std::future<Repository> forkRepository(const std::string& owner, const std::string& repo);
    std::future<bool> starRepository(const std::string& owner, const std::string& repo);
    std::future<bool> unstarRepository(const std::string& owner, const std::string& repo);
    std::future<bool> watchRepository(const std::string& owner, const std::string& repo);

    // Branch operations
    std::future<std::vector<Branch>> listBranches(const std::string& owner, const std::string& repo);
    std::future<Branch> getBranch(const std::string& owner, const std::string& repo, const std::string& branch);
    std::future<Branch> createBranch(const std::string& owner, const std::string& repo,
        const std::string& branchName, const std::string& sha);
    std::future<bool> deleteBranch(const std::string& owner, const std::string& repo, const std::string& branch);
    std::future<bool> protectBranch(const std::string& owner, const std::string& repo,
        const std::string& branch, const json& protection);

    // Commit operations
    std::future<std::vector<Commit>> listCommits(const std::string& owner, const std::string& repo,
        const std::string& branch = "", int perPage = 30, int page = 1);
    std::future<Commit> getCommit(const std::string& owner, const std::string& repo, const std::string& sha);
    std::future<std::vector<Commit>> compareCommits(const std::string& owner, const std::string& repo,
        const std::string& base, const std::string& head);

    // Pull Request operations
    std::future<std::vector<PullRequest>> listPullRequests(const std::string& owner, const std::string& repo,
        PRState state = PRState::OPEN, int perPage = 30, int page = 1);
    std::future<PullRequest> getPullRequest(const std::string& owner, const std::string& repo, int number);
    std::future<PullRequest> createPullRequest(const std::string& owner, const std::string& repo,
        const PRCreateRequest& request);
    std::future<PullRequest> updatePullRequest(const std::string& owner, const std::string& repo,
        int number, const PRUpdateRequest& request);
    std::future<bool> mergePullRequest(const std::string& owner, const std::string& repo,
        int number, const std::string& commitTitle = "", const std::string& commitMessage = "",
        PRMergeMethod method = PRMergeMethod::MERGE);
    std::future<bool> closePullRequest(const std::string& owner, const std::string& repo, int number);
    std::future<std::vector<Commit>> listPRCommits(const std::string& owner, const std::string& repo, int number);
    std::future<std::vector<ReviewComment>> listPRReviewComments(const std::string& owner, const std::string& repo, int number);
    std::future<std::vector<json>> listPRFiles(const std::string& owner, const std::string& repo, int number);

    // Review operations
    std::future<std::vector<Review>> listReviews(const std::string& owner, const std::string& repo, int number);
    std::future<Review> createReview(const std::string& owner, const std::string& repo,
        int number, const ReviewRequest& request);
    std::future<Review> submitReview(const std::string& owner, const std::string& repo,
        int number, const ReviewRequest& request);
    std::future<ReviewComment> createReviewComment(const std::string& owner, const std::string& repo,
        int number, const std::string& path, int line, const std::string& body, const std::string& commitId = "");
    std::future<bool> deleteReviewComment(const std::string& owner, const std::string& repo, const std::string& commentId);

    // Issue operations
    std::future<std::vector<Issue>> listIssues(const std::string& owner, const std::string& repo,
        IssueState state = IssueState::OPEN, int perPage = 30, int page = 1);
    std::future<Issue> getIssue(const std::string& owner, const std::string& repo, int number);
    std::future<Issue> createIssue(const std::string& owner, const std::string& repo,
        const IssueCreateRequest& request);
    std::future<Issue> updateIssue(const std::string& owner, const std::string& repo,
        int number, const IssueUpdateRequest& request);
    std::future<bool> closeIssue(const std::string& owner, const std::string& repo, int number);
    std::future<std::vector<IssueComment>> listIssueComments(const std::string& owner, const std::string& repo, int number);
    std::future<IssueComment> createIssueComment(const std::string& owner, const std::string& repo,
        int number, const CommentCreateRequest& request);

    // File operations
    std::future<FileContent> getFileContent(const std::string& owner, const std::string& repo,
        const std::string& path, const std::string& ref = "");
    std::future<FileContent> createOrUpdateFile(const std::string& owner, const std::string& repo,
        const FileCreateRequest& request);
    std::future<bool> deleteFile(const std::string& owner, const std::string& repo,
        const std::string& path, const std::string& message, const std::string& sha,
        const std::string& branch = "");

    // Tree operations
    std::future<json> getTree(const std::string& owner, const std::string& repo,
        const std::string& sha, bool recursive = false);
    std::future<json> createTree(const std::string& owner, const std::string& repo,
        const TreeCreateRequest& request);

    // Workflow operations
    std::future<std::vector<WorkflowRun>> listWorkflowRuns(const std::string& owner, const std::string& repo,
        const std::string& branch = "", int perPage = 30, int page = 1);
    std::future<WorkflowRun> getWorkflowRun(const std::string& owner, const std::string& repo, long long runId);
    std::future<bool> dispatchWorkflow(const std::string& owner, const std::string& repo,
        const std::string& workflowId, const WorkflowDispatchRequest& request);
    std::future<bool> cancelWorkflowRun(const std::string& owner, const std::string& repo, long long runId);
    std::future<bool> rerunWorkflowRun(const std::string& owner, const std::string& repo, long long runId);

    // Release operations
    std::future<std::vector<Release>> listReleases(const std::string& owner, const std::string& repo,
        int perPage = 30, int page = 1);
    std::future<Release> getRelease(const std::string& owner, const std::string& repo, int releaseId);
    std::future<Release> getReleaseByTag(const std::string& owner, const std::string& repo, const std::string& tag);
    std::future<Release> createRelease(const std::string& owner, const std::string& repo,
        const ReleaseCreateRequest& request);
    std::future<bool> deleteRelease(const std::string& owner, const std::string& repo, int releaseId);

    // Search operations
    std::future<SearchResult> searchRepositories(const SearchRequest& request);
    std::future<SearchResult> searchCode(const SearchRequest& request);
    std::future<SearchResult> searchIssues(const SearchRequest& request);
    std::future<SearchResult> searchUsers(const SearchRequest& request);
    std::future<SearchResult> searchCommits(const SearchRequest& request);

    // GraphQL API
    json graphqlQuery(const std::string& query, const json& variables = json());

    // Webhook operations
    std::future<json> createWebhook(const std::string& owner, const std::string& repo,
        const WebhookConfig& config);
    std::future<bool> deleteWebhook(const std::string& owner, const std::string& repo, int hookId);
    bool verifyWebhookSignature(const std::string& payload, const std::string& signature,
        const std::string& secret);

    // Utility
    std::string base64Encode(const std::string& data) const;
    std::string base64Decode(const std::string& data) const;
    std::string computeHMAC(const std::string& data, const std::string& key) const;

private:
    Config m_config;
    mutable std::mutex m_mutex;
    RateLimit m_rateLimit;

    // HTTP helpers
    json httpGet(const std::string& path, const std::map<std::string, std::string>& params = {});
    json httpPost(const std::string& path, const json& body = json());
    json httpPatch(const std::string& path, const json& body = json());
    json httpPut(const std::string& path, const json& body = json());
    bool httpDelete(const std::string& path, const json& body = json());
    std::string rawGet(const std::string& url, const std::map<std::string, std::string>& headers = {});
    std::string rawRequest(const std::string& method, const std::string& url,
        const std::string& body = "", const std::map<std::string, std::string>& headers = {});

    // URL helpers
    std::string apiUrl(const std::string& path) const;
    std::string buildUrl(const std::string& base, const std::map<std::string, std::string>& params) const;

    // Retry logic
    json requestWithRetry(const std::string& method, const std::string& url,
        const std::string& body = "", const std::map<std::string, std::string>& headers = {});

    // Allow CodeReviewAgent to fetch raw diffs
    friend class CodeReviewAgent;
    friend class WorkflowAutomation;
};

// ============================================================================
// CloudAgent — Autonomous agent that completes tasks and submits PRs
// ============================================================================

struct CloudAgentTask {
    std::string id;
    std::string description;          // Natural language task description
    std::string repository;           // "owner/repo"
    std::string branch;               // Target branch (default: main)
    std::string baseBranch;           // Base branch for PR (default: main)
    std::vector<std::string> labels;  // Labels for the PR
    std::vector<std::string> assignees;
    std::vector<std::string> reviewers;
    json context;                     // Additional context
    int maxSteps = 50;
    int timeoutMinutes = 60;
};

struct CloudAgentResult {
    bool success;
    std::string taskId;
    std::string summary;
    std::string branchName;           // Branch created by agent
    int prNumber = -1;                // PR number if created
    std::string prUrl;                // PR URL
    std::vector<std::string> commits; // Commit SHAs
    std::vector<std::string> filesChanged;
    std::vector<std::string> stepsExecuted;
    json findings;
    std::string error;
    std::chrono::milliseconds duration;
};

struct CloudAgentConfig {
    std::string githubToken;
    std::string workingDirectory;     // Local clone directory
    std::string modelEndpoint;        // LLM endpoint for code generation
    int maxConcurrentTasks = 3;
    int maxStepsPerTask = 50;
    int taskTimeoutMinutes = 60;
    bool autoMerge = false;
    bool requireReview = true;
    std::vector<std::string> allowedLabels;
    std::vector<std::string> blockedLabels;
};

class CloudAgent {
public:
    explicit CloudAgent(const CloudAgentConfig& config);
    ~CloudAgent();

    // Lifecycle
    bool initialize();
    void shutdown();
    bool isInitialized() const;

    // Task execution
    std::future<CloudAgentResult> executeTask(const CloudAgentTask& task);
    std::future<CloudAgentResult> executeTaskAsync(const CloudAgentTask& task);
    std::future<bool> cancelTask(const std::string& taskId);
    std::future<CloudAgentResult> getTaskResult(const std::string& taskId);

    // Task management
    std::vector<std::string> listActiveTasks() const;
    std::vector<CloudAgentResult> listCompletedTasks() const;
    std::vector<CloudAgentResult> listFailedTasks() const;

    // Configuration
    void setConfig(const CloudAgentConfig& config);
    const CloudAgentConfig& getConfig() const;

    // Statistics
    struct AgentStats {
        uint64_t totalTasks = 0;
        uint64_t successfulTasks = 0;
        uint64_t failedTasks = 0;
        uint64_t activeTasks = 0;
        uint64_t totalPRsCreated = 0;
        uint64_t totalCommits = 0;
        uint64_t totalFilesChanged = 0;
        double averageTaskDurationMs = 0.0;
        double successRate = 0.0;
    };
    AgentStats getStats() const;

    // Callbacks
    using TaskCallback = std::function<void(const CloudAgentTask&, const CloudAgentResult&)>;
    using ProgressCallback = std::function<void(const std::string& taskId, const std::string& step, const json& details)>;
    void setTaskCallback(TaskCallback cb);
    void setProgressCallback(ProgressCallback cb);

private:
    CloudAgentConfig m_config;
    std::shared_ptr<GitHubClient> m_github;
    bool m_initialized = false;
    mutable std::mutex m_mutex;

    // Task tracking
    struct TaskState {
        CloudAgentTask task;
        CloudAgentResult result;
        std::atomic<bool> cancelled{false};
        std::atomic<bool> completed{false};
        std::chrono::steady_clock::time_point startTime;
    };
    std::map<std::string, std::shared_ptr<TaskState>> m_activeTasks;
    std::vector<CloudAgentResult> m_completedTasks;
    std::vector<CloudAgentResult> m_failedTasks;

    // Callbacks
    TaskCallback m_taskCallback;
    ProgressCallback m_progressCallback;

    // Internal execution
    CloudAgentResult executeTaskInternal(const CloudAgentTask& task, std::shared_ptr<TaskState> state);
    bool cloneRepository(const CloudAgentTask& task, const std::string& localPath);
    bool createBranch(const std::string& localPath, const std::string& branchName);
    bool commitChanges(const std::string& localPath, const std::string& message);
    bool pushBranch(const std::string& localPath, const std::string& branchName);
    std::string generateBranchName(const CloudAgentTask& task);
    std::string generateCommitMessage(const CloudAgentTask& task, const std::vector<std::string>& changes);
    std::string generatePRDescription(const CloudAgentTask& task, const std::vector<std::string>& changes);
    std::vector<std::string> analyzeChanges(const std::string& localPath);
    bool runTests(const std::string& localPath);
    bool runLinter(const std::string& localPath);

    // LLM integration
    std::string callLLM(const std::string& prompt, const json& context = json());
    json planTask(const CloudAgentTask& task);
    json executeStep(const std::string& step, const json& context);
};

// ============================================================================
// PRBuilder — Fluent API for building PRs
// ============================================================================

class PRBuilder {
public:
    PRBuilder(std::shared_ptr<GitHubClient> client, const std::string& owner, const std::string& repo);

    // Configuration
    PRBuilder& title(const std::string& title);
    PRBuilder& body(const std::string& body);
    PRBuilder& head(const std::string& branch);
    PRBuilder& base(const std::string& branch);
    PRBuilder& label(const std::string& label);
    PRBuilder& labels(const std::vector<std::string>& labels);
    PRBuilder& assignee(const std::string& assignee);
    PRBuilder& assignees(const std::vector<std::string>& assignees);
    PRBuilder& reviewer(const std::string& reviewer);
    PRBuilder& reviewers(const std::vector<std::string>& reviewers);

    // Build and submit
    std::future<PullRequest> create();
    std::future<PullRequest> createAndMerge(PRMergeMethod method = PRMergeMethod::MERGE);

private:
    std::shared_ptr<GitHubClient> m_client;
    std::string m_owner;
    std::string m_repo;
    PRCreateRequest m_request;
};

// ============================================================================
// IssueBuilder — Fluent API for building issues
// ============================================================================

class IssueBuilder {
public:
    IssueBuilder(std::shared_ptr<GitHubClient> client, const std::string& owner, const std::string& repo);

    // Configuration
    IssueBuilder& title(const std::string& title);
    IssueBuilder& body(const std::string& body);
    IssueBuilder& label(const std::string& label);
    IssueBuilder& labels(const std::vector<std::string>& labels);
    IssueBuilder& assignee(const std::string& assignee);
    IssueBuilder& assignees(const std::vector<std::string>& assignees);
    IssueBuilder& milestone(int milestone);

    // Build and submit
    std::future<Issue> create();

private:
    std::shared_ptr<GitHubClient> m_client;
    std::string m_owner;
    std::string m_repo;
    IssueCreateRequest m_request;
};

// ============================================================================
// CodeReview — Automated code review
// ============================================================================

struct CodeReviewRequest {
    std::string owner;
    std::string repo;
    int prNumber;
    std::string commitId;
    std::vector<std::string> files;  // Specific files to review (empty = all)
    bool includeStyle = true;
    bool includeSecurity = true;
    bool includePerformance = true;
    bool includeDocumentation = true;
    std::string customPrompt;
};

struct CodeReviewResult {
    bool success;
    std::string summary;
    std::vector<ReviewComment> comments;
    ReviewState recommendation;  // APPROVED, CHANGES_REQUESTED, COMMENTED
    json findings;
    std::string error;
};

class CodeReviewAgent {
public:
    explicit CodeReviewAgent(std::shared_ptr<GitHubClient> client);
    ~CodeReviewAgent();

    // Review a PR
    std::future<CodeReviewResult> reviewPR(const CodeReviewRequest& request);

    // Review a specific file
    std::future<CodeReviewResult> reviewFile(const std::string& owner, const std::string& repo,
        const std::string& path, const std::string& ref = "");

    // Review a diff
    std::future<CodeReviewResult> reviewDiff(const std::string& diff, const std::string& context = "");

    // Configuration
    void setStyleRules(const json& rules);
    void setSecurityRules(const json& rules);
    void setPerformanceRules(const json& rules);

private:
    std::shared_ptr<GitHubClient> m_client;
    json m_styleRules;
    json m_securityRules;
    json m_performanceRules;

    // Internal
    json analyzeCode(const std::string& code, const std::string& language, const std::string& context);
    std::vector<ReviewComment> generateComments(const json& analysis, const std::string& diff);
    ReviewState determineRecommendation(const json& analysis);
};

// ============================================================================
// WorkflowAutomation — GitHub Actions integration
// ============================================================================

struct WorkflowTrigger {
    std::string workflowId;
    std::string ref;
    json inputs;
};

struct WorkflowStatus {
    long long runId;
    std::string status;
    std::string conclusion;
    std::vector<json> jobs;
    std::chrono::system_clock::time_point startedAt;
    std::chrono::system_clock::time_point completedAt;
};

class WorkflowAutomation {
public:
    explicit WorkflowAutomation(std::shared_ptr<GitHubClient> client);
    ~WorkflowAutomation();

    // Trigger a workflow
    std::future<WorkflowStatus> triggerWorkflow(const std::string& owner, const std::string& repo,
        const WorkflowTrigger& trigger);

    // Wait for workflow completion
    std::future<WorkflowStatus> waitForCompletion(const std::string& owner, const std::string& repo,
        long long runId, int timeoutMinutes = 60);

    // Get workflow logs
    std::future<std::string> getWorkflowLogs(const std::string& owner, const std::string& repo,
        long long runId);

    // List workflows
    std::future<std::vector<json>> listWorkflows(const std::string& owner, const std::string& repo);

    // Cancel workflow
    std::future<bool> cancelWorkflow(const std::string& owner, const std::string& repo, long long runId);

private:
    std::shared_ptr<GitHubClient> m_client;
};

// ============================================================================
// Factory Functions
// ============================================================================

std::shared_ptr<GitHubClient> createGitHubClient(const GitHubClient::Config& config);
std::shared_ptr<CloudAgent> createCloudAgent(const CloudAgentConfig& config);
std::shared_ptr<CodeReviewAgent> createCodeReviewAgent(std::shared_ptr<GitHubClient> client);
std::shared_ptr<WorkflowAutomation> createWorkflowAutomation(std::shared_ptr<GitHubClient> client);
std::shared_ptr<PRBuilder> createPRBuilder(std::shared_ptr<GitHubClient> client,
    const std::string& owner, const std::string& repo);
std::shared_ptr<IssueBuilder> createIssueBuilder(std::shared_ptr<GitHubClient> client,
    const std::string& owner, const std::string& repo);

} // namespace GitHub
} // namespace RawrXD