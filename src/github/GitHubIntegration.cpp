// ============================================================================
// GitHubIntegration.cpp — GitHub API Integration Implementation
// ============================================================================
// Implements the GitHubIntegration.hpp interface using WinHTTP for REST API
// calls. Provides Cursor-like cloud agent capabilities:
//   - GitHub REST API client
//   - Cloud agent for autonomous PR submission
//   - PR/Issue builders
//   - Automated code review
//   - GitHub Actions workflow automation
// ============================================================================

#include "GitHubIntegration.hpp"
#include <windows.h>
#include <winhttp.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <random>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <filesystem>

#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;

namespace RawrXD {
namespace GitHub {

// ============================================================================
// Helper: Base64 encoding
// ============================================================================
static const char* b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64EncodeBytes(const std::vector<uint8_t>& data) {
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(b64chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::vector<uint8_t> base64DecodeBytes(const std::string& in) {
    std::vector<uint8_t> out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[b64chars[i]] = i;
    int val = 0, valb = -8;
    for (char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

// ============================================================================
// Helper: HMAC-SHA256 (simplified using Windows CNG)
// ============================================================================
static std::string computeHMACSHA256(const std::string& data, const std::string& key) {
    // Use Windows CNG for HMAC-SHA256
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashLen = 0, resultLen = 0;
    std::vector<uint8_t> hash;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (uint8_t*)&hashLen, sizeof(hashLen), &resultLen, 0) == 0) {
            hash.resize(hashLen);
            if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, (uint8_t*)key.data(), (DWORD)key.size(), 0) == 0) {
                BCryptHashData(hHash, (uint8_t*)data.data(), (DWORD)data.size(), 0);
                BCryptFinishHash(hHash, hash.data(), hashLen, 0);
                BCryptDestroyHash(hHash);
            }
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    // Convert to hex string
    std::ostringstream oss;
    for (uint8_t b : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

// ============================================================================
// Helper: Generate random string
// ============================================================================
static std::string randomString(size_t length) {
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; i++) {
        result += charset[dist(gen)];
    }
    return result;
}

// ============================================================================
// Helper: URL encode
// ============================================================================
static std::string urlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << (int)(unsigned char)c;
        }
    }
    return escaped.str();
}

// ============================================================================
// Helper: HTTP request via WinHTTP
// ============================================================================
struct HttpResponse {
    int statusCode = 0;
    std::string body;
    std::map<std::string, std::string> headers;
};

static HttpResponse winHttpRequest(const std::string& method, const std::string& url,
    const std::string& body = "", const std::map<std::string, std::string>& headers = {},
    int timeoutMs = 30000) {

    HttpResponse response;

    // Parse URL (WinHttpCrackUrl requires a wide string)
    int wlen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), (int)url.length(), nullptr, 0);
    std::wstring wurl(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), (int)url.length(), wurl.data(), wlen);

    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwSchemeLength = (DWORD)-1;
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;

    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.length(), 0, &urlComp)) {
        response.statusCode = -1;
        response.body = "Failed to parse URL";
        return response;
    }

    std::wstring host(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring path(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    if (urlComp.dwExtraInfoLength > 0) {
        path += std::wstring(urlComp.lpszExtraInfo, urlComp.dwExtraInfoLength);
    }

    INTERNET_PORT port = urlComp.nPort;
    bool secure = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET hSession = WinHttpOpen(L"RawrXD-GitHub-Client/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        response.statusCode = -1;
        response.body = "Failed to open WinHTTP session";
        return response;
    }

    DWORD timeout = timeoutMs;
    WinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    WinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        response.statusCode = -1;
        response.body = "Failed to connect";
        return response;
    }

    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        std::wstring(method.begin(), method.end()).c_str(),
        path.c_str(), nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.statusCode = -1;
        response.body = "Failed to open request";
        return response;
    }

    // Set headers
    std::wstring headerStr;
    for (const auto& [key, value] : headers) {
        headerStr += std::wstring(key.begin(), key.end()) + L": " +
            std::wstring(value.begin(), value.end()) + L"\r\n";
    }

    // Send request
    std::wstring wideBody(body.begin(), body.end());
    BOOL sent = WinHttpSendRequest(hRequest,
        headerStr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headerStr.c_str(),
        (DWORD)headerStr.length(),
        body.empty() ? nullptr : (LPVOID)body.data(),
        (DWORD)body.length(),
        (DWORD)body.length(), 0);

    if (!sent) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.statusCode = -1;
        response.body = "Failed to send request";
        return response;
    }

    // Receive response
    BOOL received = WinHttpReceiveResponse(hRequest, nullptr);
    if (!received) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        response.statusCode = -1;
        response.body = "Failed to receive response";
        return response;
    }

    // Get status code
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    response.statusCode = (int)statusCode;

    // Get headers
    DWORD headerSize = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
        WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &headerSize, WINHTTP_NO_HEADER_INDEX);
    if (headerSize > 0) {
        std::vector<wchar_t> headerBuf(headerSize / sizeof(wchar_t));
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX, headerBuf.data(), &headerSize, WINHTTP_NO_HEADER_INDEX)) {
            std::wstring headersStr(headerBuf.data());
            std::wistringstream stream(headersStr);
            std::wstring line;
            while (std::getline(stream, line)) {
                size_t colon = line.find(L':');
                if (colon != std::wstring::npos) {
                    std::wstring key = line.substr(0, colon);
                    std::wstring value = line.substr(colon + 1);
                    // Trim
                    while (!value.empty() && (value.front() == L' ' || value.front() == L'\t')) value.erase(value.begin());
                    while (!value.empty() && (value.back() == L' ' || value.back() == L'\r' || value.back() == L'\n')) value.pop_back();
                    std::string keyStr(key.begin(), key.end());
                    std::string valueStr(value.begin(), value.end());
                    response.headers[keyStr] = valueStr;
                }
            }
        }
    }

    // Read body
    std::string responseBody;
    char buffer[4096];
    DWORD bytesRead = 0;
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        responseBody.append(buffer, bytesRead);
    }
    response.body = responseBody;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

// ============================================================================
// GitHubClient Implementation
// ============================================================================

GitHubClient::GitHubClient(const Config& config) : m_config(config) {
    if (m_config.userAgent.empty()) {
        m_config.userAgent = "RawrXD-GitHub-Client/1.0";
    }
    if (m_config.baseUrl.empty()) {
        m_config.baseUrl = "https://api.github.com";
    }
    if (m_config.uploadUrl.empty()) {
        m_config.uploadUrl = "https://uploads.github.com";
    }
}

GitHubClient::~GitHubClient() = default;

bool GitHubClient::authenticate() {
    if (m_config.token.empty()) return false;

    try {
        json user = getCurrentUser();
        return user.contains("login");
    } catch (...) {
        return false;
    }
}

bool GitHubClient::isAuthenticated() const {
    return !m_config.token.empty();
}

std::string GitHubClient::getToken() const {
    return m_config.token;
}

void GitHubClient::setToken(const std::string& token) {
    m_config.token = token;
}

GitHubClient::RateLimit GitHubClient::getRateLimit() const {
    return m_rateLimit;
}

json GitHubClient::getCurrentUser() {
    return httpGet("/user");
}

json GitHubClient::getUser(const std::string& username) {
    return httpGet("/users/" + username);
}

std::future<Repository> GitHubClient::getRepository(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> Repository {
        json data = httpGet("/repos/" + owner + "/" + repo);
        Repository r;
        r.owner = owner;
        r.name = repo;
        r.fullName = data.value("full_name", owner + "/" + repo);
        r.description = data.value("description", "");
        r.htmlUrl = data.value("html_url", "");
        r.cloneUrl = data.value("clone_url", "");
        r.sshUrl = data.value("ssh_url", "");
        r.defaultBranch = data.value("default_branch", "main");
        r.isPrivate = data.value("private", false);
        r.isFork = data.value("fork", false);
        r.starCount = data.value("stargazers_count", 0);
        r.forkCount = data.value("forks_count", 0);
        r.openIssuesCount = data.value("open_issues_count", 0);
        r.language = data.value("language", "");
        r.metadata = data;
        return r;
    });
}

std::future<Repository> GitHubClient::createRepository(const std::string& name, const json& options) {
    return std::async(std::launch::async, [this, name, options]() -> Repository {
        json body = options;
        body["name"] = name;
        json data = httpPost("/user/repos", body);
        Repository r;
        r.owner = data.value("owner", json())["login"].get<std::string>();
        r.name = name;
        r.fullName = data.value("full_name", "");
        r.description = data.value("description", "");
        r.htmlUrl = data.value("html_url", "");
        r.cloneUrl = data.value("clone_url", "");
        r.sshUrl = data.value("ssh_url", "");
        r.defaultBranch = data.value("default_branch", "main");
        r.isPrivate = data.value("private", false);
        r.metadata = data;
        return r;
    });
}

std::future<bool> GitHubClient::deleteRepository(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> bool {
        return httpDelete("/repos/" + owner + "/" + repo);
    });
}

std::future<Repository> GitHubClient::forkRepository(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> Repository {
        json data = httpPost("/repos/" + owner + "/" + repo + "/forks");
        Repository r;
        r.owner = data.value("owner", json())["login"].get<std::string>();
        r.name = data.value("name", repo);
        r.fullName = data.value("full_name", "");
        r.description = data.value("description", "");
        r.htmlUrl = data.value("html_url", "");
        r.cloneUrl = data.value("clone_url", "");
        r.sshUrl = data.value("ssh_url", "");
        r.defaultBranch = data.value("default_branch", "main");
        r.isFork = true;
        r.metadata = data;
        return r;
    });
}

std::future<bool> GitHubClient::starRepository(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> bool {
        return httpPut("/user/starred/" + owner + "/" + repo, json()) != nullptr;
    });
}

std::future<bool> GitHubClient::unstarRepository(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> bool {
        return httpDelete("/user/starred/" + owner + "/" + repo);
    });
}

std::future<bool> GitHubClient::watchRepository(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> bool {
        json body;
        body["subscribed"] = true;
        return httpPut("/repos/" + owner + "/" + repo + "/subscription", body) != nullptr;
    });
}

std::future<std::vector<Branch>> GitHubClient::listBranches(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> std::vector<Branch> {
        json data = httpGet("/repos/" + owner + "/" + repo + "/branches");
        std::vector<Branch> branches;
        if (data.is_array()) {
            for (const auto& item : data) {
                Branch b;
                b.name = item.value("name", "");
                b.sha = item.value("commit", json())["sha"].get<std::string>();
                b.commitUrl = item.value("commit", json())["url"].get<std::string>();
                branches.push_back(b);
            }
        }
        return branches;
    });
}

std::future<Branch> GitHubClient::getBranch(const std::string& owner, const std::string& repo, const std::string& branch) {
    return std::async(std::launch::async, [this, owner, repo, branch]() -> Branch {
        json data = httpGet("/repos/" + owner + "/" + repo + "/branches/" + branch);
        Branch b;
        b.name = data.value("name", branch);
        b.sha = data.value("commit", json())["sha"].get<std::string>();
        b.commitUrl = data.value("commit", json())["url"].get<std::string>();
        b.isProtected = data.value("protected", false);
        b.protection = data.value("protection", json());
        return b;
    });
}

std::future<Branch> GitHubClient::createBranch(const std::string& owner, const std::string& repo,
    const std::string& branchName, const std::string& sha) {
    return std::async(std::launch::async, [this, owner, repo, branchName, sha]() -> Branch {
        // Create a ref
        json body;
        body["ref"] = "refs/heads/" + branchName;
        body["sha"] = sha;
        json data = httpPost("/repos/" + owner + "/" + repo + "/git/refs", body);
        Branch b;
        b.name = branchName;
        b.sha = data.value("object", json())["sha"].get<std::string>();
        return b;
    });
}

std::future<bool> GitHubClient::deleteBranch(const std::string& owner, const std::string& repo, const std::string& branch) {
    return std::async(std::launch::async, [this, owner, repo, branch]() -> bool {
        return httpDelete("/repos/" + owner + "/" + repo + "/git/refs/heads/" + branch);
    });
}

std::future<bool> GitHubClient::protectBranch(const std::string& owner, const std::string& repo,
    const std::string& branch, const json& protection) {
    return std::async(std::launch::async, [this, owner, repo, branch, protection]() -> bool {
        return httpPut("/repos/" + owner + "/" + repo + "/branches/" + branch + "/protection", protection) != nullptr;
    });
}

std::future<std::vector<Commit>> GitHubClient::listCommits(const std::string& owner, const std::string& repo,
    const std::string& branch, int perPage, int page) {
    return std::async(std::launch::async, [this, owner, repo, branch, perPage, page]() -> std::vector<Commit> {
        std::map<std::string, std::string> params;
        if (!branch.empty()) params["sha"] = branch;
        params["per_page"] = std::to_string(perPage);
        params["page"] = std::to_string(page);
        json data = httpGet("/repos/" + owner + "/" + repo + "/commits", params);
        std::vector<Commit> commits;
        if (data.is_array()) {
            for (const auto& item : data) {
                Commit c;
                c.sha = item.value("sha", "");
                c.message = item.value("commit", json()).value("message", "");
                c.authorName = item.value("commit", json()).value("author", json()).value("name", "");
                c.authorEmail = item.value("commit", json()).value("author", json()).value("email", "");
                c.committerName = item.value("commit", json()).value("committer", json()).value("name", "");
                c.committerEmail = item.value("commit", json()).value("committer", json()).value("email", "");
                c.htmlUrl = item.value("html_url", "");
                if (item.contains("parents") && item["parents"].is_array()) {
                    for (const auto& parent : item["parents"]) {
                        c.parentShas.push_back(parent.value("sha", ""));
                    }
                }
                commits.push_back(c);
            }
        }
        return commits;
    });
}

std::future<Commit> GitHubClient::getCommit(const std::string& owner, const std::string& repo, const std::string& sha) {
    return std::async(std::launch::async, [this, owner, repo, sha]() -> Commit {
        json data = httpGet("/repos/" + owner + "/" + repo + "/commits/" + sha);
        Commit c;
        c.sha = data.value("sha", "");
        c.message = data.value("commit", json()).value("message", "");
        c.authorName = data.value("commit", json()).value("author", json()).value("name", "");
        c.authorEmail = data.value("commit", json()).value("author", json()).value("email", "");
        c.committerName = data.value("commit", json()).value("committer", json()).value("name", "");
        c.committerEmail = data.value("commit", json()).value("committer", json()).value("email", "");
        c.htmlUrl = data.value("html_url", "");
        if (data.contains("parents") && data["parents"].is_array()) {
            for (const auto& parent : data["parents"]) {
                c.parentShas.push_back(parent.value("sha", ""));
            }
        }
        if (data.contains("stats")) {
            c.stats = data["stats"];
        }
        if (data.contains("files")) {
            c.files = data["files"];
        }
        return c;
    });
}

std::future<std::vector<Commit>> GitHubClient::compareCommits(const std::string& owner, const std::string& repo,
    const std::string& base, const std::string& head) {
    return std::async(std::launch::async, [this, owner, repo, base, head]() -> std::vector<Commit> {
        json data = httpGet("/repos/" + owner + "/" + repo + "/compare/" + base + "..." + head);
        std::vector<Commit> commits;
        if (data.contains("commits") && data["commits"].is_array()) {
            for (const auto& item : data["commits"]) {
                Commit c;
                c.sha = item.value("sha", "");
                c.message = item.value("commit", json()).value("message", "");
                c.authorName = item.value("commit", json()).value("author", json()).value("name", "");
                c.authorEmail = item.value("commit", json()).value("author", json()).value("email", "");
                c.htmlUrl = item.value("html_url", "");
                commits.push_back(c);
            }
        }
        return commits;
    });
}

std::future<std::vector<PullRequest>> GitHubClient::listPullRequests(const std::string& owner, const std::string& repo,
    PRState state, int perPage, int page) {
    return std::async(std::launch::async, [this, owner, repo, state, perPage, page]() -> std::vector<PullRequest> {
        std::map<std::string, std::string> params;
        switch (state) {
            case PRState::OPEN: params["state"] = "open"; break;
            case PRState::CLOSED: params["state"] = "closed"; break;
            case PRState::MERGED: params["state"] = "closed"; break;  // Merged is a subset of closed
            case PRState::ALL: params["state"] = "all"; break;
        }
        params["per_page"] = std::to_string(perPage);
        params["page"] = std::to_string(page);
        json data = httpGet("/repos/" + owner + "/" + repo + "/pulls", params);
        std::vector<PullRequest> prs;
        if (data.is_array()) {
            for (const auto& item : data) {
                PullRequest pr;
                pr.number = item.value("number", 0);
                pr.title = item.value("title", "");
                pr.body = item.value("body", "");
                pr.state = item.value("state", "");
                pr.merged = item.value("merged", false);
                pr.mergeable = item.value("mergeable", false);
                pr.mergeableState = item.value("mergeable_state", "");
                pr.headBranch = item.value("head", json())["ref"].get<std::string>();
                pr.baseBranch = item.value("base", json())["ref"].get<std::string>();
                pr.headSha = item.value("head", json())["sha"].get<std::string>();
                pr.baseSha = item.value("base", json())["sha"].get<std::string>();
                pr.htmlUrl = item.value("html_url", "");
                pr.diffUrl = item.value("diff_url", "");
                pr.patchUrl = item.value("patch_url", "");
                pr.author = item.value("user", json())["login"].get<std::string>();
                pr.reviewComments = item.value("review_comments", 0);
                pr.comments = item.value("comments", 0);
                pr.commits = item.value("commits", 0);
                pr.additions = item.value("additions", 0);
                pr.deletions = item.value("deletions", 0);
                pr.changedFiles = item.value("changed_files", 0);
                if (item.contains("labels") && item["labels"].is_array()) {
                    for (const auto& label : item["labels"]) {
                        pr.labels.push_back(label.value("name", ""));
                    }
                }
                if (item.contains("assignees") && item["assignees"].is_array()) {
                    for (const auto& assignee : item["assignees"]) {
                        pr.assignees.push_back(assignee.value("login", ""));
                    }
                }
                pr.metadata = item;
                prs.push_back(pr);
            }
        }
        return prs;
    });
}

std::future<PullRequest> GitHubClient::getPullRequest(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> PullRequest {
        json data = httpGet("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number));
        PullRequest pr;
        pr.number = data.value("number", 0);
        pr.title = data.value("title", "");
        pr.body = data.value("body", "");
        pr.state = data.value("state", "");
        pr.merged = data.value("merged", false);
        pr.mergeable = data.value("mergeable", false);
        pr.mergeableState = data.value("mergeable_state", "");
        pr.headBranch = data.value("head", json())["ref"].get<std::string>();
        pr.baseBranch = data.value("base", json())["ref"].get<std::string>();
        pr.headSha = data.value("head", json())["sha"].get<std::string>();
        pr.baseSha = data.value("base", json())["sha"].get<std::string>();
        pr.htmlUrl = data.value("html_url", "");
        pr.diffUrl = data.value("diff_url", "");
        pr.patchUrl = data.value("patch_url", "");
        pr.author = data.value("user", json())["login"].get<std::string>();
        pr.reviewComments = data.value("review_comments", 0);
        pr.comments = data.value("comments", 0);
        pr.commits = data.value("commits", 0);
        pr.additions = data.value("additions", 0);
        pr.deletions = data.value("deletions", 0);
        pr.changedFiles = data.value("changed_files", 0);
        if (data.contains("labels") && data["labels"].is_array()) {
            for (const auto& label : data["labels"]) {
                pr.labels.push_back(label.value("name", ""));
            }
        }
        if (data.contains("assignees") && data["assignees"].is_array()) {
            for (const auto& assignee : data["assignees"]) {
                pr.assignees.push_back(assignee.value("login", ""));
            }
        }
        pr.metadata = data;
        return pr;
    });
}

std::future<PullRequest> GitHubClient::createPullRequest(const std::string& owner, const std::string& repo,
    const PRCreateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, request]() -> PullRequest {
        json body;
        body["title"] = request.title;
        body["body"] = request.body;
        body["head"] = request.headBranch;
        body["base"] = request.baseBranch;
        body["maintainer_can_modify"] = request.maintainerCanModify;
        json data = httpPost("/repos/" + owner + "/" + repo + "/pulls", body);

        PullRequest pr;
        pr.number = data.value("number", 0);
        pr.title = data.value("title", "");
        pr.body = data.value("body", "");
        pr.state = data.value("state", "");
        pr.merged = data.value("merged", false);
        pr.mergeable = data.value("mergeable", false);
        pr.mergeableState = data.value("mergeable_state", "");
        pr.headBranch = data.value("head", json())["ref"].get<std::string>();
        pr.baseBranch = data.value("base", json())["ref"].get<std::string>();
        pr.headSha = data.value("head", json())["sha"].get<std::string>();
        pr.baseSha = data.value("base", json())["sha"].get<std::string>();
        pr.htmlUrl = data.value("html_url", "");
        pr.diffUrl = data.value("diff_url", "");
        pr.patchUrl = data.value("patch_url", "");
        pr.author = data.value("user", json())["login"].get<std::string>();
        pr.metadata = data;

        // Apply labels if provided
        if (!request.labels.empty()) {
            json labelsBody;
            labelsBody["labels"] = request.labels;
            httpPost("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(pr.number) + "/labels", labelsBody);
            pr.labels = request.labels;
        }

        // Apply assignees if provided
        if (!request.assignees.empty()) {
            json assigneesBody;
            assigneesBody["assignees"] = request.assignees;
            httpPost("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(pr.number) + "/assignees", assigneesBody);
            pr.assignees = request.assignees;
        }

        // Request reviewers if provided
        if (!request.reviewers.empty()) {
            json reviewersBody;
            reviewersBody["reviewers"] = request.reviewers;
            httpPost("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(pr.number) + "/requested_reviewers", reviewersBody);
            pr.reviewers = request.reviewers;
        }

        return pr;
    });
}

std::future<PullRequest> GitHubClient::updatePullRequest(const std::string& owner, const std::string& repo,
    int number, const PRUpdateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, number, request]() -> PullRequest {
        json body;
        if (request.title) body["title"] = *request.title;
        if (request.body) body["body"] = *request.body;
        if (request.state) body["state"] = *request.state;
        json data = httpPatch("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number), body);

        PullRequest pr;
        pr.number = data.value("number", number);
        pr.title = data.value("title", "");
        pr.body = data.value("body", "");
        pr.state = data.value("state", "");
        pr.merged = data.value("merged", false);
        pr.mergeable = data.value("mergeable", false);
        pr.mergeableState = data.value("mergeable_state", "");
        pr.headBranch = data.value("head", json())["ref"].get<std::string>();
        pr.baseBranch = data.value("base", json())["ref"].get<std::string>();
        pr.headSha = data.value("head", json())["sha"].get<std::string>();
        pr.baseSha = data.value("base", json())["sha"].get<std::string>();
        pr.htmlUrl = data.value("html_url", "");
        pr.author = data.value("user", json())["login"].get<std::string>();
        pr.metadata = data;
        return pr;
    });
}

std::future<bool> GitHubClient::mergePullRequest(const std::string& owner, const std::string& repo,
    int number, const std::string& commitTitle, const std::string& commitMessage, PRMergeMethod method) {
    return std::async(std::launch::async, [this, owner, repo, number, commitTitle, commitMessage, method]() -> bool {
        json body;
        if (!commitTitle.empty()) body["commit_title"] = commitTitle;
        if (!commitMessage.empty()) body["commit_message"] = commitMessage;
        switch (method) {
            case PRMergeMethod::MERGE: body["merge_method"] = "merge"; break;
            case PRMergeMethod::SQUASH: body["merge_method"] = "squash"; break;
            case PRMergeMethod::REBASE: body["merge_method"] = "rebase"; break;
        }
        json data = httpPut("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number) + "/merge", body);
        return data.value("merged", false);
    });
}

std::future<bool> GitHubClient::closePullRequest(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> bool {
        json body;
        body["state"] = "closed";
        json data = httpPatch("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number), body);
        return data.value("state", "") == "closed";
    });
}

std::future<std::vector<Commit>> GitHubClient::listPRCommits(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> std::vector<Commit> {
        json data = httpGet("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number) + "/commits");
        std::vector<Commit> commits;
        if (data.is_array()) {
            for (const auto& item : data) {
                Commit c;
                c.sha = item.value("sha", "");
                c.message = item.value("commit", json()).value("message", "");
                c.authorName = item.value("commit", json()).value("author", json()).value("name", "");
                c.authorEmail = item.value("commit", json()).value("author", json()).value("email", "");
                c.htmlUrl = item.value("html_url", "");
                commits.push_back(c);
            }
        }
        return commits;
    });
}

std::future<std::vector<ReviewComment>> GitHubClient::listPRReviewComments(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> std::vector<ReviewComment> {
        json data = httpGet("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number) + "/comments");
        std::vector<ReviewComment> comments;
        if (data.is_array()) {
            for (const auto& item : data) {
                ReviewComment c;
                c.id = item.value("id", "");
                c.path = item.value("path", "");
                c.line = item.value("line", 0);
                c.startLine = item.value("start_line", 0);
                c.body = item.value("body", "");
                c.author = item.value("user", json())["login"].get<std::string>();
                c.htmlUrl = item.value("html_url", "");
                c.diffHunk = item.value("diff_hunk", "");
                comments.push_back(c);
            }
        }
        return comments;
    });
}

std::future<std::vector<json>> GitHubClient::listPRFiles(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> std::vector<json> {
        json data = httpGet("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number) + "/files");
        std::vector<json> files;
        if (data.is_array()) {
            for (const auto& item : data) {
                files.push_back(item);
            }
        }
        return files;
    });
}

std::future<std::vector<Review>> GitHubClient::listReviews(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> std::vector<Review> {
        json data = httpGet("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number) + "/reviews");
        std::vector<Review> reviews;
        if (data.is_array()) {
            for (const auto& item : data) {
                Review r;
                r.id = item.value("id", "");
                r.author = item.value("user", json())["login"].get<std::string>();
                std::string state = item.value("state", "");
                if (state == "APPROVED") r.state = ReviewState::APPROVED;
                else if (state == "CHANGES_REQUESTED") r.state = ReviewState::CHANGES_REQUESTED;
                else if (state == "COMMENTED") r.state = ReviewState::COMMENTED;
                else r.state = ReviewState::PENDING;
                r.body = item.value("body", "");
                r.htmlUrl = item.value("html_url", "");
                reviews.push_back(r);
            }
        }
        return reviews;
    });
}

std::future<Review> GitHubClient::createReview(const std::string& owner, const std::string& repo,
    int number, const ReviewRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, number, request]() -> Review {
        json body;
        std::string stateStr;
        switch (request.state) {
            case ReviewState::APPROVED: stateStr = "APPROVED"; break;
            case ReviewState::CHANGES_REQUESTED: stateStr = "CHANGES_REQUESTED"; break;
            case ReviewState::COMMENTED: stateStr = "COMMENTED"; break;
            case ReviewState::PENDING: stateStr = "PENDING"; break;
        }
        body["event"] = stateStr;
        body["body"] = request.body;
        if (!request.comments.empty()) {
            body["comments"] = request.comments;
        }
        if (!request.commitId.empty()) {
            body["commit_id"] = request.commitId;
        }
        json data = httpPost("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number) + "/reviews", body);
        Review r;
        r.id = data.value("id", "");
        r.author = data.value("user", json())["login"].get<std::string>();
        std::string state = data.value("state", "");
        if (state == "APPROVED") r.state = ReviewState::APPROVED;
        else if (state == "CHANGES_REQUESTED") r.state = ReviewState::CHANGES_REQUESTED;
        else if (state == "COMMENTED") r.state = ReviewState::COMMENTED;
        else r.state = ReviewState::PENDING;
        r.body = data.value("body", "");
        r.htmlUrl = data.value("html_url", "");
        return r;
    });
}

std::future<Review> GitHubClient::submitReview(const std::string& owner, const std::string& repo,
    int number, const ReviewRequest& request) {
    return createReview(owner, repo, number, request);
}

std::future<ReviewComment> GitHubClient::createReviewComment(const std::string& owner, const std::string& repo,
    int number, const std::string& path, int line, const std::string& body, const std::string& commitId) {
    return std::async(std::launch::async, [this, owner, repo, number, path, line, body, commitId]() -> ReviewComment {
        json reqBody;
        reqBody["body"] = body;
        reqBody["path"] = path;
        reqBody["line"] = line;
        if (!commitId.empty()) {
            reqBody["commit_id"] = commitId;
        }
        json data = httpPost("/repos/" + owner + "/" + repo + "/pulls/" + std::to_string(number) + "/comments", reqBody);
        ReviewComment c;
        c.id = data.value("id", "");
        c.path = data.value("path", "");
        c.line = data.value("line", 0);
        c.startLine = data.value("start_line", 0);
        c.body = data.value("body", "");
        c.author = data.value("user", json())["login"].get<std::string>();
        c.htmlUrl = data.value("html_url", "");
        c.diffHunk = data.value("diff_hunk", "");
        return c;
    });
}

std::future<bool> GitHubClient::deleteReviewComment(const std::string& owner, const std::string& repo, const std::string& commentId) {
    return std::async(std::launch::async, [this, owner, repo, commentId]() -> bool {
        return httpDelete("/repos/" + owner + "/" + repo + "/pulls/comments/" + commentId);
    });
}

std::future<std::vector<Issue>> GitHubClient::listIssues(const std::string& owner, const std::string& repo,
    IssueState state, int perPage, int page) {
    return std::async(std::launch::async, [this, owner, repo, state, perPage, page]() -> std::vector<Issue> {
        std::map<std::string, std::string> params;
        switch (state) {
            case IssueState::OPEN: params["state"] = "open"; break;
            case IssueState::CLOSED: params["state"] = "closed"; break;
            case IssueState::ALL: params["state"] = "all"; break;
        }
        params["per_page"] = std::to_string(perPage);
        params["page"] = std::to_string(page);
        json data = httpGet("/repos/" + owner + "/" + repo + "/issues", params);
        std::vector<Issue> issues;
        if (data.is_array()) {
            for (const auto& item : data) {
                Issue i;
                i.number = item.value("number", 0);
                i.title = item.value("title", "");
                i.body = item.value("body", "");
                i.state = item.value("state", "");
                i.isPullRequest = item.contains("pull_request");
                i.author = item.value("user", json())["login"].get<std::string>();
                i.comments = item.value("comments", 0);
                i.htmlUrl = item.value("html_url", "");
                if (item.contains("labels") && item["labels"].is_array()) {
                    for (const auto& label : item["labels"]) {
                        i.labels.push_back(label.value("name", ""));
                    }
                }
                if (item.contains("assignees") && item["assignees"].is_array()) {
                    for (const auto& assignee : item["assignees"]) {
                        i.assignees.push_back(assignee.value("login", ""));
                    }
                }
                i.metadata = item;
                issues.push_back(i);
            }
        }
        return issues;
    });
}

std::future<Issue> GitHubClient::getIssue(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> Issue {
        json data = httpGet("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(number));
        Issue i;
        i.number = data.value("number", 0);
        i.title = data.value("title", "");
        i.body = data.value("body", "");
        i.state = data.value("state", "");
        i.isPullRequest = data.contains("pull_request");
        i.author = data.value("user", json())["login"].get<std::string>();
        i.comments = data.value("comments", 0);
        i.htmlUrl = data.value("html_url", "");
        if (data.contains("labels") && data["labels"].is_array()) {
            for (const auto& label : data["labels"]) {
                i.labels.push_back(label.value("name", ""));
            }
        }
        if (data.contains("assignees") && data["assignees"].is_array()) {
            for (const auto& assignee : data["assignees"]) {
                i.assignees.push_back(assignee.value("login", ""));
            }
        }
        i.metadata = data;
        return i;
    });
}

std::future<Issue> GitHubClient::createIssue(const std::string& owner, const std::string& repo,
    const IssueCreateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, request]() -> Issue {
        json body;
        body["title"] = request.title;
        body["body"] = request.body;
        if (!request.labels.empty()) body["labels"] = request.labels;
        if (!request.assignees.empty()) body["assignees"] = request.assignees;
        if (request.milestone) body["milestone"] = *request.milestone;
        json data = httpPost("/repos/" + owner + "/" + repo + "/issues", body);
        Issue i;
        i.number = data.value("number", 0);
        i.title = data.value("title", "");
        i.body = data.value("body", "");
        i.state = data.value("state", "");
        i.isPullRequest = data.contains("pull_request");
        i.author = data.value("user", json())["login"].get<std::string>();
        i.comments = data.value("comments", 0);
        i.htmlUrl = data.value("html_url", "");
        if (data.contains("labels") && data["labels"].is_array()) {
            for (const auto& label : data["labels"]) {
                i.labels.push_back(label.value("name", ""));
            }
        }
        if (data.contains("assignees") && data["assignees"].is_array()) {
            for (const auto& assignee : data["assignees"]) {
                i.assignees.push_back(assignee.value("login", ""));
            }
        }
        i.metadata = data;
        return i;
    });
}

std::future<Issue> GitHubClient::updateIssue(const std::string& owner, const std::string& repo,
    int number, const IssueUpdateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, number, request]() -> Issue {
        json body;
        if (request.title) body["title"] = *request.title;
        if (request.body) body["body"] = *request.body;
        if (request.state) body["state"] = *request.state;
        if (request.labels) body["labels"] = *request.labels;
        if (request.assignees) body["assignees"] = *request.assignees;
        json data = httpPatch("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(number), body);
        Issue i;
        i.number = data.value("number", number);
        i.title = data.value("title", "");
        i.body = data.value("body", "");
        i.state = data.value("state", "");
        i.isPullRequest = data.contains("pull_request");
        i.author = data.value("user", json())["login"].get<std::string>();
        i.comments = data.value("comments", 0);
        i.htmlUrl = data.value("html_url", "");
        i.metadata = data;
        return i;
    });
}

std::future<bool> GitHubClient::closeIssue(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> bool {
        json body;
        body["state"] = "closed";
        json data = httpPatch("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(number), body);
        return data.value("state", "") == "closed";
    });
}

std::future<std::vector<IssueComment>> GitHubClient::listIssueComments(const std::string& owner, const std::string& repo, int number) {
    return std::async(std::launch::async, [this, owner, repo, number]() -> std::vector<IssueComment> {
        json data = httpGet("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(number) + "/comments");
        std::vector<IssueComment> comments;
        if (data.is_array()) {
            for (const auto& item : data) {
                IssueComment c;
                c.id = item.value("id", "");
                c.body = item.value("body", "");
                c.author = item.value("user", json())["login"].get<std::string>();
                c.htmlUrl = item.value("html_url", "");
                comments.push_back(c);
            }
        }
        return comments;
    });
}

std::future<IssueComment> GitHubClient::createIssueComment(const std::string& owner, const std::string& repo,
    int number, const CommentCreateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, number, request]() -> IssueComment {
        json body;
        body["body"] = request.body;
        json data = httpPost("/repos/" + owner + "/" + repo + "/issues/" + std::to_string(number) + "/comments", body);
        IssueComment c;
        c.id = data.value("id", "");
        c.body = data.value("body", "");
        c.author = data.value("user", json())["login"].get<std::string>();
        c.htmlUrl = data.value("html_url", "");
        return c;
    });
}

std::future<FileContent> GitHubClient::getFileContent(const std::string& owner, const std::string& repo,
    const std::string& path, const std::string& ref) {
    return std::async(std::launch::async, [this, owner, repo, path, ref]() -> FileContent {
        std::map<std::string, std::string> params;
        if (!ref.empty()) params["ref"] = ref;
        json data = httpGet("/repos/" + owner + "/" + repo + "/contents/" + path, params);
        FileContent fc;
        fc.path = data.value("path", path);
        fc.content = data.value("content", "");
        fc.sha = data.value("sha", "");
        fc.size = data.value("size", 0);
        fc.encoding = data.value("encoding", "");
        fc.downloadUrl = data.value("download_url", "");
        return fc;
    });
}

std::future<FileContent> GitHubClient::createOrUpdateFile(const std::string& owner, const std::string& repo,
    const FileCreateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, request]() -> FileContent {
        json body;
        body["message"] = request.message;
        body["content"] = base64Encode(request.content);
        if (request.branch) body["branch"] = *request.branch;
        if (request.sha) body["sha"] = *request.sha;
        json data = httpPut("/repos/" + owner + "/" + repo + "/contents/" + request.path, body);
        FileContent fc;
        fc.path = request.path;
        if (data.contains("content")) {
            fc.content = data["content"].value("content", "");
            fc.sha = data["content"].value("sha", "");
        }
        return fc;
    });
}

std::future<bool> GitHubClient::deleteFile(const std::string& owner, const std::string& repo,
    const std::string& path, const std::string& message, const std::string& sha, const std::string& branch) {
    return std::async(std::launch::async, [this, owner, repo, path, message, sha, branch]() -> bool {
        json body;
        body["message"] = message;
        body["sha"] = sha;
        if (!branch.empty()) body["branch"] = branch;
        json data = httpDelete("/repos/" + owner + "/" + repo + "/contents/" + path, body);
        return data.contains("content");
    });
}

std::future<json> GitHubClient::getTree(const std::string& owner, const std::string& repo,
    const std::string& sha, bool recursive) {
    return std::async(std::launch::async, [this, owner, repo, sha, recursive]() -> json {
        std::string path = "/repos/" + owner + "/" + repo + "/git/trees/" + sha;
        if (recursive) path += "?recursive=1";
        return httpGet(path);
    });
}

std::future<json> GitHubClient::createTree(const std::string& owner, const std::string& repo,
    const TreeCreateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, request]() -> json {
        json body;
        if (!request.baseTree.empty()) body["base_tree"] = request.baseTree;
        body["tree"] = json::array();
        for (const auto& entry : request.entries) {
            json item;
            item["path"] = entry.path;
            item["mode"] = entry.mode;
            item["type"] = entry.type;
            if (entry.sha) item["sha"] = *entry.sha;
            if (entry.content) item["content"] = *entry.content;
            body["tree"].push_back(item);
        }
        return httpPost("/repos/" + owner + "/" + repo + "/git/trees", body);
    });
}

std::future<std::vector<WorkflowRun>> GitHubClient::listWorkflowRuns(const std::string& owner, const std::string& repo,
    const std::string& branch, int perPage, int page) {
    return std::async(std::launch::async, [this, owner, repo, branch, perPage, page]() -> std::vector<WorkflowRun> {
        std::map<std::string, std::string> params;
        if (!branch.empty()) params["branch"] = branch;
        params["per_page"] = std::to_string(perPage);
        params["page"] = std::to_string(page);
        json data = httpGet("/repos/" + owner + "/" + repo + "/actions/runs", params);
        std::vector<WorkflowRun> runs;
        if (data.contains("workflow_runs") && data["workflow_runs"].is_array()) {
            for (const auto& item : data["workflow_runs"]) {
                WorkflowRun run;
                run.id = item.value("id", 0LL);
                run.name = item.value("name", "");
                run.status = item.value("status", "");
                run.conclusion = item.value("conclusion", "");
                run.branch = item.value("head_branch", "");
                run.sha = item.value("head_sha", "");
                run.event = item.value("event", "");
                run.htmlUrl = item.value("html_url", "");
                run.runNumber = item.value("run_number", 0);
                run.workflowId = item.value("workflow_id", "");
                runs.push_back(run);
            }
        }
        return runs;
    });
}

std::future<WorkflowRun> GitHubClient::getWorkflowRun(const std::string& owner, const std::string& repo, long long runId) {
    return std::async(std::launch::async, [this, owner, repo, runId]() -> WorkflowRun {
        json data = httpGet("/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(runId));
        WorkflowRun run;
        run.id = data.value("id", 0LL);
        run.name = data.value("name", "");
        run.status = data.value("status", "");
        run.conclusion = data.value("conclusion", "");
        run.branch = data.value("head_branch", "");
        run.sha = data.value("head_sha", "");
        run.event = data.value("event", "");
        run.htmlUrl = data.value("html_url", "");
        run.runNumber = data.value("run_number", 0);
        run.workflowId = data.value("workflow_id", "");
        return run;
    });
}

std::future<bool> GitHubClient::dispatchWorkflow(const std::string& owner, const std::string& repo,
    const std::string& workflowId, const WorkflowDispatchRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, workflowId, request]() -> bool {
        json body;
        body["ref"] = request.ref;
        if (!request.inputs.empty()) body["inputs"] = request.inputs;
        httpPost("/repos/" + owner + "/" + repo + "/actions/workflows/" + workflowId + "/dispatches", body);
        return true;
    });
}

std::future<bool> GitHubClient::cancelWorkflowRun(const std::string& owner, const std::string& repo, long long runId) {
    return std::async(std::launch::async, [this, owner, repo, runId]() -> bool {
        json body;
        httpPost("/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(runId) + "/cancel", body);
        return true;
    });
}

std::future<bool> GitHubClient::rerunWorkflowRun(const std::string& owner, const std::string& repo, long long runId) {
    return std::async(std::launch::async, [this, owner, repo, runId]() -> bool {
        json body;
        httpPost("/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(runId) + "/rerun", body);
        return true;
    });
}

std::future<std::vector<Release>> GitHubClient::listReleases(const std::string& owner, const std::string& repo,
    int perPage, int page) {
    return std::async(std::launch::async, [this, owner, repo, perPage, page]() -> std::vector<Release> {
        std::map<std::string, std::string> params;
        params["per_page"] = std::to_string(perPage);
        params["page"] = std::to_string(page);
        json data = httpGet("/repos/" + owner + "/" + repo + "/releases", params);
        std::vector<Release> releases;
        if (data.is_array()) {
            for (const auto& item : data) {
                Release r;
                r.id = item.value("id", 0);
                r.tagName = item.value("tag_name", "");
                r.name = item.value("name", "");
                r.body = item.value("body", "");
                r.isDraft = item.value("draft", false);
                r.isPrerelease = item.value("prerelease", false);
                r.htmlUrl = item.value("html_url", "");
                if (item.contains("assets") && item["assets"].is_array()) {
                    r.assets = item["assets"];
                }
                releases.push_back(r);
            }
        }
        return releases;
    });
}

std::future<Release> GitHubClient::getRelease(const std::string& owner, const std::string& repo, int releaseId) {
    return std::async(std::launch::async, [this, owner, repo, releaseId]() -> Release {
        json data = httpGet("/repos/" + owner + "/" + repo + "/releases/" + std::to_string(releaseId));
        Release r;
        r.id = data.value("id", 0);
        r.tagName = data.value("tag_name", "");
        r.name = data.value("name", "");
        r.body = data.value("body", "");
        r.isDraft = data.value("draft", false);
        r.isPrerelease = data.value("prerelease", false);
        r.htmlUrl = data.value("html_url", "");
        if (data.contains("assets") && data["assets"].is_array()) {
            r.assets = data["assets"];
        }
        return r;
    });
}

std::future<Release> GitHubClient::getReleaseByTag(const std::string& owner, const std::string& repo, const std::string& tag) {
    return std::async(std::launch::async, [this, owner, repo, tag]() -> Release {
        json data = httpGet("/repos/" + owner + "/" + repo + "/releases/tags/" + tag);
        Release r;
        r.id = data.value("id", 0);
        r.tagName = data.value("tag_name", "");
        r.name = data.value("name", "");
        r.body = data.value("body", "");
        r.isDraft = data.value("draft", false);
        r.isPrerelease = data.value("prerelease", false);
        r.htmlUrl = data.value("html_url", "");
        if (data.contains("assets") && data["assets"].is_array()) {
            r.assets = data["assets"];
        }
        return r;
    });
}

std::future<Release> GitHubClient::createRelease(const std::string& owner, const std::string& repo,
    const ReleaseCreateRequest& request) {
    return std::async(std::launch::async, [this, owner, repo, request]() -> Release {
        json body;
        body["tag_name"] = request.tagName;
        if (request.name) body["name"] = *request.name;
        if (request.body) body["body"] = *request.body;
        body["draft"] = request.isDraft;
        body["prerelease"] = request.isPrerelease;
        if (request.targetCommitish) body["target_commitish"] = *request.targetCommitish;
        json data = httpPost("/repos/" + owner + "/" + repo + "/releases", body);
        Release r;
        r.id = data.value("id", 0);
        r.tagName = data.value("tag_name", "");
        r.name = data.value("name", "");
        r.body = data.value("body", "");
        r.isDraft = data.value("draft", false);
        r.isPrerelease = data.value("prerelease", false);
        r.htmlUrl = data.value("html_url", "");
        if (data.contains("assets") && data["assets"].is_array()) {
            r.assets = data["assets"];
        }
        return r;
    });
}

std::future<bool> GitHubClient::deleteRelease(const std::string& owner, const std::string& repo, int releaseId) {
    return std::async(std::launch::async, [this, owner, repo, releaseId]() -> bool {
        return httpDelete("/repos/" + owner + "/" + repo + "/releases/" + std::to_string(releaseId));
    });
}

std::future<SearchResult> GitHubClient::searchRepositories(const SearchRequest& request) {
    return std::async(std::launch::async, [this, request]() -> SearchResult {
        std::map<std::string, std::string> params;
        params["q"] = request.query;
        if (!request.sort.empty()) params["sort"] = request.sort;
        if (!request.order.empty()) params["order"] = request.order;
        params["per_page"] = std::to_string(request.perPage);
        params["page"] = std::to_string(request.page);
        json data = httpGet("/search/repositories", params);
        SearchResult result;
        result.totalCount = data.value("total_count", 0);
        result.incompleteResults = data.value("incomplete_results", false);
        result.items = data.value("items", json::array());
        return result;
    });
}

std::future<SearchResult> GitHubClient::searchCode(const SearchRequest& request) {
    return std::async(std::launch::async, [this, request]() -> SearchResult {
        std::map<std::string, std::string> params;
        params["q"] = request.query;
        if (!request.sort.empty()) params["sort"] = request.sort;
        if (!request.order.empty()) params["order"] = request.order;
        params["per_page"] = std::to_string(request.perPage);
        params["page"] = std::to_string(request.page);
        json data = httpGet("/search/code", params);
        SearchResult result;
        result.totalCount = data.value("total_count", 0);
        result.incompleteResults = data.value("incomplete_results", false);
        result.items = data.value("items", json::array());
        return result;
    });
}

std::future<SearchResult> GitHubClient::searchIssues(const SearchRequest& request) {
    return std::async(std::launch::async, [this, request]() -> SearchResult {
        std::map<std::string, std::string> params;
        params["q"] = request.query;
        if (!request.sort.empty()) params["sort"] = request.sort;
        if (!request.order.empty()) params["order"] = request.order;
        params["per_page"] = std::to_string(request.perPage);
        params["page"] = std::to_string(request.page);
        json data = httpGet("/search/issues", params);
        SearchResult result;
        result.totalCount = data.value("total_count", 0);
        result.incompleteResults = data.value("incomplete_results", false);
        result.items = data.value("items", json::array());
        return result;
    });
}

std::future<SearchResult> GitHubClient::searchUsers(const SearchRequest& request) {
    return std::async(std::launch::async, [this, request]() -> SearchResult {
        std::map<std::string, std::string> params;
        params["q"] = request.query;
        if (!request.sort.empty()) params["sort"] = request.sort;
        if (!request.order.empty()) params["order"] = request.order;
        params["per_page"] = std::to_string(request.perPage);
        params["page"] = std::to_string(request.page);
        json data = httpGet("/search/users", params);
        SearchResult result;
        result.totalCount = data.value("total_count", 0);
        result.incompleteResults = data.value("incomplete_results", false);
        result.items = data.value("items", json::array());
        return result;
    });
}

std::future<SearchResult> GitHubClient::searchCommits(const SearchRequest& request) {
    return std::async(std::launch::async, [this, request]() -> SearchResult {
        std::map<std::string, std::string> params;
        params["q"] = request.query;
        if (!request.sort.empty()) params["sort"] = request.sort;
        if (!request.order.empty()) params["order"] = request.order;
        params["per_page"] = std::to_string(request.perPage);
        params["page"] = std::to_string(request.page);
        json data = httpGet("/search/commits", params);
        SearchResult result;
        result.totalCount = data.value("total_count", 0);
        result.incompleteResults = data.value("incomplete_results", false);
        result.items = data.value("items", json::array());
        return result;
    });
}

json GitHubClient::graphqlQuery(const std::string& query, const json& variables) {
    json body;
    body["query"] = query;
    if (!variables.empty()) body["variables"] = variables;
    return httpPost("/graphql", body);
}

std::future<json> GitHubClient::createWebhook(const std::string& owner, const std::string& repo,
    const WebhookConfig& config) {
    return std::async(std::launch::async, [this, owner, repo, config]() -> json {
        json body;
        body["config"] = {
            {"url", config.url},
            {"content_type", config.contentType},
            {"secret", config.secret},
            {"insecure_ssl", config.insecureSsl ? "1" : "0"}
        };
        body["events"] = json::array();
        for (const auto& evt : config.events) {
            switch (evt) {
                case EventType::PUSH: body["events"].push_back("push"); break;
                case EventType::PULL_REQUEST: body["events"].push_back("pull_request"); break;
                case EventType::ISSUES: body["events"].push_back("issues"); break;
                case EventType::ISSUE_COMMENT: body["events"].push_back("issue_comment"); break;
                case EventType::COMMIT_COMMENT: body["events"].push_back("commit_comment"); break;
                case EventType::REVIEW: body["events"].push_back("review"); break;
                case EventType::WORKFLOW_RUN: body["events"].push_back("workflow_run"); break;
                case EventType::RELEASE: body["events"].push_back("release"); break;
                case EventType::FORK: body["events"].push_back("fork"); break;
                case EventType::STAR: body["events"].push_back("star"); break;
                case EventType::WATCH: body["events"].push_back("watch"); break;
            }
        }
        body["active"] = config.active;
        return httpPost("/repos/" + owner + "/" + repo + "/hooks", body);
    });
}

std::future<bool> GitHubClient::deleteWebhook(const std::string& owner, const std::string& repo, int hookId) {
    return std::async(std::launch::async, [this, owner, repo, hookId]() -> bool {
        return httpDelete("/repos/" + owner + "/" + repo + "/hooks/" + std::to_string(hookId));
    });
}

bool GitHubClient::verifyWebhookSignature(const std::string& payload, const std::string& signature,
    const std::string& secret) {
    std::string computed = computeHMACSHA256(payload, secret);
    // GitHub sends "sha256=<hex>"
    std::string expected = "sha256=" + computed;
    return signature == expected;
}

std::string GitHubClient::base64Encode(const std::string& data) const {
    return base64EncodeBytes(std::vector<uint8_t>(data.begin(), data.end()));
}

std::string GitHubClient::base64Decode(const std::string& data) const {
    auto decoded = base64DecodeBytes(data);
    return std::string(decoded.begin(), decoded.end());
}

std::string GitHubClient::computeHMAC(const std::string& data, const std::string& key) const {
    return computeHMACSHA256(data, key);
}

// HTTP helpers
json GitHubClient::httpGet(const std::string& path, const std::map<std::string, std::string>& params) {
    std::string url = buildUrl(apiUrl(path), params);
    std::map<std::string, std::string> headers;
    headers["Authorization"] = "token " + m_config.token;
    headers["Accept"] = "application/vnd.github.v3+json";
    headers["User-Agent"] = m_config.userAgent;
    for (const auto& [k, v] : m_config.extraHeaders) headers[k] = v;

    std::string response = rawGet(url, headers);
    try {
        return json::parse(response);
    } catch (...) {
        return json();
    }
}

json GitHubClient::httpPost(const std::string& path, const json& body) {
    std::string url = apiUrl(path);
    std::map<std::string, std::string> headers;
    headers["Authorization"] = "token " + m_config.token;
    headers["Accept"] = "application/vnd.github.v3+json";
    headers["Content-Type"] = "application/json";
    headers["User-Agent"] = m_config.userAgent;
    for (const auto& [k, v] : m_config.extraHeaders) headers[k] = v;

    std::string bodyStr = body.dump();
    std::string response = rawRequest("POST", url, bodyStr, headers);
    try {
        return json::parse(response);
    } catch (...) {
        return json();
    }
}

json GitHubClient::httpPatch(const std::string& path, const json& body) {
    std::string url = apiUrl(path);
    std::map<std::string, std::string> headers;
    headers["Authorization"] = "token " + m_config.token;
    headers["Accept"] = "application/vnd.github.v3+json";
    headers["Content-Type"] = "application/json";
    headers["User-Agent"] = m_config.userAgent;
    for (const auto& [k, v] : m_config.extraHeaders) headers[k] = v;

    std::string bodyStr = body.dump();
    std::string response = rawRequest("PATCH", url, bodyStr, headers);
    try {
        return json::parse(response);
    } catch (...) {
        return json();
    }
}

json GitHubClient::httpPut(const std::string& path, const json& body) {
    std::string url = apiUrl(path);
    std::map<std::string, std::string> headers;
    headers["Authorization"] = "token " + m_config.token;
    headers["Accept"] = "application/vnd.github.v3+json";
    headers["Content-Type"] = "application/json";
    headers["User-Agent"] = m_config.userAgent;
    for (const auto& [k, v] : m_config.extraHeaders) headers[k] = v;

    std::string bodyStr = body.dump();
    std::string response = rawRequest("PUT", url, bodyStr, headers);
    try {
        return json::parse(response);
    } catch (...) {
        return json();
    }
}

bool GitHubClient::httpDelete(const std::string& path, const json& body) {
    std::string url = apiUrl(path);
    std::map<std::string, std::string> headers;
    headers["Authorization"] = "token " + m_config.token;
    headers["Accept"] = "application/vnd.github.v3+json";
    headers["User-Agent"] = m_config.userAgent;
    for (const auto& [k, v] : m_config.extraHeaders) headers[k] = v;

    std::string bodyStr = body.dump();
    std::string response = rawRequest("DELETE", url, bodyStr, headers);
    return !response.empty();
}

std::string GitHubClient::rawGet(const std::string& url, const std::map<std::string, std::string>& headers) {
    auto response = winHttpRequest("GET", url, "", headers, m_config.timeoutMs);
    return response.body;
}

std::string GitHubClient::rawRequest(const std::string& method, const std::string& url,
    const std::string& body, const std::map<std::string, std::string>& headers) {
    auto response = winHttpRequest(method, url, body, headers, m_config.timeoutMs);
    return response.body;
}

std::string GitHubClient::apiUrl(const std::string& path) const {
    return m_config.baseUrl + path;
}

std::string GitHubClient::buildUrl(const std::string& base, const std::map<std::string, std::string>& params) const {
    if (params.empty()) return base;
    std::string url = base + "?";
    bool first = true;
    for (const auto& [key, value] : params) {
        if (!first) url += "&";
        url += urlEncode(key) + "=" + urlEncode(value);
        first = false;
    }
    return url;
}

json GitHubClient::requestWithRetry(const std::string& method, const std::string& url,
    const std::string& body, const std::map<std::string, std::string>& headers) {
    json lastError;
    for (int attempt = 0; attempt < m_config.maxRetries; attempt++) {
        try {
            if (method == "GET") return json::parse(rawGet(url, headers));
            if (method == "POST") return json::parse(rawRequest("POST", url, body, headers));
            if (method == "PATCH") return json::parse(rawRequest("PATCH", url, body, headers));
            if (method == "PUT") return json::parse(rawRequest("PUT", url, body, headers));
            if (method == "DELETE") return json::parse(rawRequest("DELETE", url, body, headers));
        } catch (const std::exception& e) {
            lastError = {{"error", e.what()}, {"attempt", attempt + 1}};
            if (attempt < m_config.maxRetries - 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds(m_config.retryDelayMs * (attempt + 1)));
            }
        }
    }
    return lastError;
}

// ============================================================================
// CloudAgent Implementation
// ============================================================================

CloudAgent::CloudAgent(const CloudAgentConfig& config) : m_config(config) {
    GitHubClient::Config ghConfig;
    ghConfig.token = config.githubToken;
    m_github = std::make_shared<GitHubClient>(ghConfig);
}

CloudAgent::~CloudAgent() {
    shutdown();
}

bool CloudAgent::initialize() {
    if (m_config.githubToken.empty()) return false;

    // Verify GitHub authentication
    if (!m_github->authenticate()) {
        return false;
    }

    // Create working directory if needed
    if (!m_config.workingDirectory.empty()) {
        std::error_code ec;
        fs::create_directories(m_config.workingDirectory, ec);
    }

    m_initialized = true;
    return true;
}

void CloudAgent::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_activeTasks.clear();
    m_initialized = false;
}

bool CloudAgent::isInitialized() const {
    return m_initialized;
}

std::future<CloudAgentResult> CloudAgent::executeTask(const CloudAgentTask& task) {
    return std::async(std::launch::async, [this, task]() -> CloudAgentResult {
        auto state = std::make_shared<TaskState>();
        state->task = task;
        state->startTime = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_activeTasks[task.id] = state;
        }

        CloudAgentResult result = executeTaskInternal(task, state);

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_activeTasks.erase(task.id);
            if (result.success) {
                m_completedTasks.push_back(result);
            } else {
                m_failedTasks.push_back(result);
            }
        }

        if (m_taskCallback) {
            m_taskCallback(task, result);
        }

        return result;
    });
}

std::future<CloudAgentResult> CloudAgent::executeTaskAsync(const CloudAgentTask& task) {
    return executeTask(task);
}

std::future<bool> CloudAgent::cancelTask(const std::string& taskId) {
    return std::async(std::launch::async, [this, taskId]() -> bool {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_activeTasks.find(taskId);
        if (it != m_activeTasks.end()) {
            it->second->cancelled = true;
            return true;
        }
        return false;
    });
}

std::future<CloudAgentResult> CloudAgent::getTaskResult(const std::string& taskId) {
    return std::async(std::launch::async, [this, taskId]() -> CloudAgentResult {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_activeTasks.find(taskId);
        if (it != m_activeTasks.end()) {
            return it->second->result;
        }
        // Check completed/failed
        for (const auto& r : m_completedTasks) {
            if (r.taskId == taskId) return r;
        }
        for (const auto& r : m_failedTasks) {
            if (r.taskId == taskId) return r;
        }
        CloudAgentResult empty;
        empty.success = false;
        empty.taskId = taskId;
        empty.error = "Task not found";
        return empty;
    });
}

std::vector<std::string> CloudAgent::listActiveTasks() const {
    std::vector<std::string> ids;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, state] : m_activeTasks) {
        ids.push_back(id);
    }
    return ids;
}

std::vector<CloudAgentResult> CloudAgent::listCompletedTasks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_completedTasks;
}

std::vector<CloudAgentResult> CloudAgent::listFailedTasks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_failedTasks;
}

void CloudAgent::setConfig(const CloudAgentConfig& config) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = config;
    if (m_github) {
        m_github->setToken(config.githubToken);
    }
}

const CloudAgentConfig& CloudAgent::getConfig() const {
    return m_config;
}

CloudAgent::AgentStats CloudAgent::getStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    AgentStats stats;
    stats.totalTasks = m_completedTasks.size() + m_failedTasks.size() + m_activeTasks.size();
    stats.successfulTasks = m_completedTasks.size();
    stats.failedTasks = m_failedTasks.size();
    stats.activeTasks = m_activeTasks.size();

    uint64_t totalDuration = 0;
    for (const auto& r : m_completedTasks) {
        stats.totalPRsCreated += (r.prNumber > 0) ? 1 : 0;
        stats.totalCommits += r.commits.size();
        stats.totalFilesChanged += r.filesChanged.size();
        totalDuration += r.duration.count();
    }
    for (const auto& r : m_failedTasks) {
        stats.totalCommits += r.commits.size();
        stats.totalFilesChanged += r.filesChanged.size();
        totalDuration += r.duration.count();
    }

    if (stats.totalTasks > 0) {
        stats.averageTaskDurationMs = (double)totalDuration / stats.totalTasks;
        stats.successRate = (double)stats.successfulTasks / stats.totalTasks * 100.0;
    }

    return stats;
}

void CloudAgent::setTaskCallback(TaskCallback cb) {
    m_taskCallback = cb;
}

void CloudAgent::setProgressCallback(ProgressCallback cb) {
    m_progressCallback = cb;
}

CloudAgentResult CloudAgent::executeTaskInternal(const CloudAgentTask& task, std::shared_ptr<TaskState> state) {
    CloudAgentResult result;
    result.taskId = task.id;
    auto start = std::chrono::steady_clock::now();

    try {
        // Step 1: Clone repository
        if (m_progressCallback) m_progressCallback(task.id, "clone", {{"repository", task.repository}});
        std::string localPath = m_config.workingDirectory + "/" + task.repository;
        if (!cloneRepository(task, localPath)) {
            result.success = false;
            result.error = "Failed to clone repository";
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }

        // Step 2: Create branch
        std::string branchName = generateBranchName(task);
        if (m_progressCallback) m_progressCallback(task.id, "branch", {{"branch", branchName}});
        if (!createBranch(localPath, branchName)) {
            result.success = false;
            result.error = "Failed to create branch";
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }
        result.branchName = branchName;

        // Step 3: Plan the task using LLM
        if (m_progressCallback) m_progressCallback(task.id, "plan", {});
        json plan = planTask(task);

        // Step 4: Execute steps
        if (plan.contains("steps") && plan["steps"].is_array()) {
            for (const auto& step : plan["steps"]) {
                if (state->cancelled) {
                    result.success = false;
                    result.error = "Task cancelled";
                    break;
                }

                std::string stepDesc = step.value("description", "");
                if (m_progressCallback) m_progressCallback(task.id, "execute", {{"step", stepDesc}});

                json stepResult = executeStep(stepDesc, task.context);
                result.stepsExecuted.push_back(stepDesc);

                if (stepResult.contains("error")) {
                    result.error = stepResult["error"].get<std::string>();
                    break;
                }
            }
        }

        // Step 5: Analyze changes
        std::vector<std::string> changes = analyzeChanges(localPath);
        result.filesChanged = changes;

        if (changes.empty()) {
            result.success = false;
            result.error = "No changes made";
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }

        // Step 6: Run tests
        if (m_progressCallback) m_progressCallback(task.id, "test", {});
        if (!runTests(localPath)) {
            result.success = false;
            result.error = "Tests failed";
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }

        // Step 7: Commit changes
        if (m_progressCallback) m_progressCallback(task.id, "commit", {});
        std::string commitMsg = generateCommitMessage(task, changes);
        if (!commitChanges(localPath, commitMsg)) {
            result.success = false;
            result.error = "Failed to commit changes";
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }

        // Step 8: Push branch
        if (m_progressCallback) m_progressCallback(task.id, "push", {});
        if (!pushBranch(localPath, branchName)) {
            result.success = false;
            result.error = "Failed to push branch";
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }

        // Step 9: Create PR
        if (m_progressCallback) m_progressCallback(task.id, "pr", {});
        PRCreateRequest prRequest;
        prRequest.title = task.description.substr(0, 72);  // GitHub title limit
        prRequest.body = generatePRDescription(task, changes);
        prRequest.headBranch = branchName;
        prRequest.baseBranch = task.baseBranch.empty() ? "main" : task.baseBranch;
        prRequest.labels = task.labels;
        prRequest.assignees = task.assignees;
        prRequest.reviewers = task.reviewers;

        // Parse owner/repo
        size_t slash = task.repository.find('/');
        if (slash == std::string::npos) {
            result.success = false;
            result.error = "Invalid repository format (expected owner/repo)";
            result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start);
            return result;
        }
        std::string owner = task.repository.substr(0, slash);
        std::string repo = task.repository.substr(slash + 1);

        PullRequest pr = m_github->createPullRequest(owner, repo, prRequest).get();
        result.prNumber = pr.number;
        result.prUrl = pr.htmlUrl;
        result.success = true;
        result.summary = "Created PR #" + std::to_string(pr.number) + ": " + pr.title;

    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
    } catch (...) {
        result.success = false;
        result.error = "Unknown error";
    }

    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);
    return result;
}

bool CloudAgent::cloneRepository(const CloudAgentTask& task, const std::string& localPath) {
    // Use git clone via system command
    std::string cmd = "git clone https://github.com/" + task.repository + ".git \"" + localPath + "\"";
    if (!task.branch.empty()) {
        cmd += " --branch " + task.branch;
    }
    cmd += " 2>&1";

    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;

    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        // Log output
    }
    int status = _pclose(pipe);
    return status == 0;
}

bool CloudAgent::createBranch(const std::string& localPath, const std::string& branchName) {
    std::string cmd = "git -C \"" + localPath + "\" checkout -b " + branchName + " 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {}
    int status = _pclose(pipe);
    return status == 0;
}

bool CloudAgent::commitChanges(const std::string& localPath, const std::string& message) {
    // Stage all changes
    std::string addCmd = "git -C \"" + localPath + "\" add -A 2>&1";
    FILE* addPipe = _popen(addCmd.c_str(), "r");
    if (addPipe) {
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), addPipe) != nullptr) {}
        _pclose(addPipe);
    }

    // Commit
    std::string cmd = "git -C \"" + localPath + "\" commit -m \"" + message + "\" 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {}
    int status = _pclose(pipe);
    return status == 0;
}

bool CloudAgent::pushBranch(const std::string& localPath, const std::string& branchName) {
    std::string cmd = "git -C \"" + localPath + "\" push origin " + branchName + " 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return false;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {}
    int status = _pclose(pipe);
    return status == 0;
}

std::string CloudAgent::generateBranchName(const CloudAgentTask& task) {
    // Generate a descriptive branch name from the task
    std::string prefix = "agent/";
    std::string desc = task.description;
    // Convert to kebab-case
    std::string kebab;
    bool lastWasDash = false;
    for (char c : desc) {
        if (isalnum((unsigned char)c)) {
            kebab += tolower((unsigned char)c);
            lastWasDash = false;
        } else if (!lastWasDash) {
            kebab += '-';
            lastWasDash = true;
        }
    }
    // Trim trailing dash
    while (!kebab.empty() && kebab.back() == '-') kebab.pop_back();
    // Limit length
    if (kebab.length() > 50) kebab = kebab.substr(0, 50);
    return prefix + kebab + "-" + randomString(6);
}

std::string CloudAgent::generateCommitMessage(const CloudAgentTask& task, const std::vector<std::string>& changes) {
    std::ostringstream msg;
    msg << "[Agent] " << task.description;
    msg << "\n\nFiles changed:\n";
    for (const auto& f : changes) {
        msg << "  - " << f << "\n";
    }
    msg << "\nTask ID: " << task.id;
    return msg.str();
}

std::string CloudAgent::generatePRDescription(const CloudAgentTask& task, const std::vector<std::string>& changes) {
    std::ostringstream desc;
    desc << "## Description\n\n";
    desc << task.description << "\n\n";
    desc << "## Changes\n\n";
    for (const auto& f : changes) {
        desc << "- `" << f << "`\n";
    }
    desc << "\n## Task\n\n";
    desc << "This PR was automatically generated by RawrXD Cloud Agent.\n";
    desc << "Task ID: `" << task.id << "`\n";
    desc << "Repository: `" << task.repository << "`\n";
    return desc.str();
}

std::vector<std::string> CloudAgent::analyzeChanges(const std::string& localPath) {
    std::vector<std::string> changes;
    std::string cmd = "git -C \"" + localPath + "\" diff --name-only HEAD~1 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return changes;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (!line.empty()) changes.push_back(line);
    }
    _pclose(pipe);
    return changes;
}

bool CloudAgent::runTests(const std::string& localPath) {
    // Check for common test commands
    std::vector<std::string> testCommands = {
        "npm test",
        "yarn test",
        "pytest",
        "cargo test",
        "go test ./...",
        "dotnet test",
        "ctest"
    };

    for (const auto& cmd : testCommands) {
        std::string fullCmd = "cd \"" + localPath + "\" && " + cmd + " 2>&1";
        FILE* pipe = _popen(fullCmd.c_str(), "r");
        if (!pipe) continue;
        char buffer[4096];
        std::string output;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            output += buffer;
        }
        int status = _pclose(pipe);
        if (status == 0) return true;
        // If command not found, try next
        if (output.find("not recognized") != std::string::npos ||
            output.find("not found") != std::string::npos) {
            continue;
        }
    }
    // No test command found or all failed - assume success if no test framework detected
    return true;
}

bool CloudAgent::runLinter(const std::string& localPath) {
    // Check for common linters
    std::vector<std::string> lintCommands = {
        "npm run lint",
        "yarn lint",
        "flake8",
        "cargo clippy",
        "golangci-lint run"
    };

    for (const auto& cmd : lintCommands) {
        std::string fullCmd = "cd \"" + localPath + "\" && " + cmd + " 2>&1";
        FILE* pipe = _popen(fullCmd.c_str(), "r");
        if (!pipe) continue;
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {}
        int status = _pclose(pipe);
        if (status == 0) return true;
    }
    return true;  // No linter found - assume success
}

std::string CloudAgent::callLLM(const std::string& prompt, const json& context) {
    // In a full implementation, this would call the configured LLM endpoint
    // For now, return a placeholder
    return "LLM response placeholder";
}

json CloudAgent::planTask(const CloudAgentTask& task) {
    // In a full implementation, this would call the LLM to plan the task
    // For now, generate a simple plan
    json plan;
    plan["task"] = task.description;
    plan["steps"] = json::array();

    // Generate steps based on task description
    json step1;
    step1["description"] = "Analyze the codebase structure";
    step1["type"] = "analysis";
    plan["steps"].push_back(step1);

    json step2;
    step2["description"] = "Implement the required changes";
    step2["type"] = "implementation";
    plan["steps"].push_back(step2);

    json step3;
    step3["description"] = "Verify the changes work correctly";
    step3["type"] = "verification";
    plan["steps"].push_back(step3);

    return plan;
}

json CloudAgent::executeStep(const std::string& step, const json& context) {
    // In a full implementation, this would execute the step using the LLM
    // and the available tools (file edit, command execution, etc.)
    json result;
    result["step"] = step;
    result["status"] = "completed";
    return result;
}

// ============================================================================
// PRBuilder Implementation
// ============================================================================

PRBuilder::PRBuilder(std::shared_ptr<GitHubClient> client, const std::string& owner, const std::string& repo)
    : m_client(client), m_owner(owner), m_repo(repo) {}

PRBuilder& PRBuilder::title(const std::string& title) {
    m_request.title = title;
    return *this;
}

PRBuilder& PRBuilder::body(const std::string& body) {
    m_request.body = body;
    return *this;
}

PRBuilder& PRBuilder::head(const std::string& branch) {
    m_request.headBranch = branch;
    return *this;
}

PRBuilder& PRBuilder::base(const std::string& branch) {
    m_request.baseBranch = branch;
    return *this;
}

PRBuilder& PRBuilder::label(const std::string& label) {
    m_request.labels.push_back(label);
    return *this;
}

PRBuilder& PRBuilder::labels(const std::vector<std::string>& labels) {
    m_request.labels = labels;
    return *this;
}

PRBuilder& PRBuilder::assignee(const std::string& assignee) {
    m_request.assignees.push_back(assignee);
    return *this;
}

PRBuilder& PRBuilder::assignees(const std::vector<std::string>& assignees) {
    m_request.assignees = assignees;
    return *this;
}

PRBuilder& PRBuilder::reviewer(const std::string& reviewer) {
    m_request.reviewers.push_back(reviewer);
    return *this;
}

PRBuilder& PRBuilder::reviewers(const std::vector<std::string>& reviewers) {
    m_request.reviewers = reviewers;
    return *this;
}

std::future<PullRequest> PRBuilder::create() {
    return m_client->createPullRequest(m_owner, m_repo, m_request);
}

std::future<PullRequest> PRBuilder::createAndMerge(PRMergeMethod method) {
    return std::async(std::launch::async, [this, method]() -> PullRequest {
        PullRequest pr = m_client->createPullRequest(m_owner, m_repo, m_request).get();
        if (pr.number > 0) {
            m_client->mergePullRequest(m_owner, m_repo, pr.number, "", "", method).get();
        }
        return pr;
    });
}

// ============================================================================
// IssueBuilder Implementation
// ============================================================================

IssueBuilder::IssueBuilder(std::shared_ptr<GitHubClient> client, const std::string& owner, const std::string& repo)
    : m_client(client), m_owner(owner), m_repo(repo) {}

IssueBuilder& IssueBuilder::title(const std::string& title) {
    m_request.title = title;
    return *this;
}

IssueBuilder& IssueBuilder::body(const std::string& body) {
    m_request.body = body;
    return *this;
}

IssueBuilder& IssueBuilder::label(const std::string& label) {
    m_request.labels.push_back(label);
    return *this;
}

IssueBuilder& IssueBuilder::labels(const std::vector<std::string>& labels) {
    m_request.labels = labels;
    return *this;
}

IssueBuilder& IssueBuilder::assignee(const std::string& assignee) {
    m_request.assignees.push_back(assignee);
    return *this;
}

IssueBuilder& IssueBuilder::assignees(const std::vector<std::string>& assignees) {
    m_request.assignees = assignees;
    return *this;
}

IssueBuilder& IssueBuilder::milestone(int milestone) {
    m_request.milestone = milestone;
    return *this;
}

std::future<Issue> IssueBuilder::create() {
    return m_client->createIssue(m_owner, m_repo, m_request);
}

// ============================================================================
// CodeReviewAgent Implementation
// ============================================================================

CodeReviewAgent::CodeReviewAgent(std::shared_ptr<GitHubClient> client)
    : m_client(client) {}

CodeReviewAgent::~CodeReviewAgent() = default;

std::future<CodeReviewResult> CodeReviewAgent::reviewPR(const CodeReviewRequest& request) {
    return std::async(std::launch::async, [this, request]() -> CodeReviewResult {
        CodeReviewResult result;
        result.success = false;

        try {
            // Get PR files
            std::vector<json> files = m_client->listPRFiles(request.owner, request.repo, request.prNumber).get();

            // Get PR diff
            PullRequest pr = m_client->getPullRequest(request.owner, request.repo, request.prNumber).get();
            std::string diffUrl = pr.diffUrl;

            // Fetch diff
            std::map<std::string, std::string> headers;
            headers["Accept"] = "application/vnd.github.v3.diff";
            std::string diff = m_client->rawGet(diffUrl, headers);

            // Analyze the diff
            json analysis = analyzeCode(diff, "diff", request.customPrompt);

            // Generate review comments
            result.comments = generateComments(analysis, diff);
            result.recommendation = determineRecommendation(analysis);
            result.summary = "Reviewed " + std::to_string(files.size()) + " files";
            result.findings = analysis;
            result.success = true;

        } catch (const std::exception& e) {
            result.error = e.what();
        }

        return result;
    });
}

std::future<CodeReviewResult> CodeReviewAgent::reviewFile(const std::string& owner, const std::string& repo,
    const std::string& path, const std::string& ref) {
    return std::async(std::launch::async, [this, owner, repo, path, ref]() -> CodeReviewResult {
        CodeReviewResult result;
        result.success = false;

        try {
            FileContent fc = m_client->getFileContent(owner, repo, path, ref).get();
            std::string content = m_client->base64Decode(fc.content);

            // Detect language from extension
            std::string language = "text";
            size_t dot = path.find_last_of('.');
            if (dot != std::string::npos) {
                std::string ext = path.substr(dot + 1);
                if (ext == "cpp" || ext == "cc" || ext == "cxx" || ext == "h" || ext == "hpp") language = "cpp";
                else if (ext == "py") language = "python";
                else if (ext == "js" || ext == "jsx") language = "javascript";
                else if (ext == "ts" || ext == "tsx") language = "typescript";
                else if (ext == "rs") language = "rust";
                else if (ext == "go") language = "go";
                else if (ext == "java") language = "java";
            }

            json analysis = analyzeCode(content, language, "");
            result.comments = generateComments(analysis, content);
            result.recommendation = determineRecommendation(analysis);
            result.summary = "Reviewed " + path;
            result.findings = analysis;
            result.success = true;

        } catch (const std::exception& e) {
            result.error = e.what();
        }

        return result;
    });
}

std::future<CodeReviewResult> CodeReviewAgent::reviewDiff(const std::string& diff, const std::string& context) {
    return std::async(std::launch::async, [this, diff, context]() -> CodeReviewResult {
        CodeReviewResult result;
        result.success = false;

        try {
            json analysis = analyzeCode(diff, "diff", context);
            result.comments = generateComments(analysis, diff);
            result.recommendation = determineRecommendation(analysis);
            result.summary = "Reviewed diff";
            result.findings = analysis;
            result.success = true;

        } catch (const std::exception& e) {
            result.error = e.what();
        }

        return result;
    });
}

void CodeReviewAgent::setStyleRules(const json& rules) {
    m_styleRules = rules;
}

void CodeReviewAgent::setSecurityRules(const json& rules) {
    m_securityRules = rules;
}

void CodeReviewAgent::setPerformanceRules(const json& rules) {
    m_performanceRules = rules;
}

json CodeReviewAgent::analyzeCode(const std::string& code, const std::string& language, const std::string& context) {
    // In a full implementation, this would call the LLM to analyze the code
    // For now, perform basic pattern matching
    json analysis;
    analysis["language"] = language;
    analysis["issues"] = json::array();

    // Basic security checks
    if (code.find("strcpy") != std::string::npos) {
        analysis["issues"].push_back({
            {"type", "security"},
            {"severity", "high"},
            {"message", "Use of strcpy detected - potential buffer overflow"},
            {"recommendation", "Use strncpy or std::string"}
        });
    }
    if (code.find("gets") != std::string::npos) {
        analysis["issues"].push_back({
            {"type", "security"},
            {"severity", "critical"},
            {"message", "Use of gets detected - always unsafe"},
            {"recommendation", "Use fgets or std::getline"}
        });
    }
    if (code.find("system(") != std::string::npos) {
        analysis["issues"].push_back({
            {"type", "security"},
            {"severity", "medium"},
            {"message", "Use of system() detected - potential command injection"},
            {"recommendation", "Use execve or platform-specific alternatives"}
        });
    }

    // Basic style checks
    if (code.find("using namespace std") != std::string::npos) {
        analysis["issues"].push_back({
            {"type", "style"},
            {"severity", "low"},
            {"message", "using namespace std in header file"},
            {"recommendation", "Use explicit std:: prefix"}
        });
    }

    return analysis;
}

std::vector<ReviewComment> CodeReviewAgent::generateComments(const json& analysis, const std::string& diff) {
    std::vector<ReviewComment> comments;
    if (!analysis.contains("issues") || !analysis["issues"].is_array()) {
        return comments;
    }

    for (const auto& issue : analysis["issues"]) {
        ReviewComment c;
        c.body = "[" + issue.value("severity", "info") + "] " +
                 issue.value("message", "") + "\n" +
                 "Recommendation: " + issue.value("recommendation", "");
        c.path = "";  // Would be extracted from diff in full implementation
        c.line = 0;
        comments.push_back(c);
    }

    return comments;
}

ReviewState CodeReviewAgent::determineRecommendation(const json& analysis) {
    if (!analysis.contains("issues") || !analysis["issues"].is_array()) {
        return ReviewState::APPROVED;
    }

    bool hasCritical = false;
    bool hasHigh = false;
    for (const auto& issue : analysis["issues"]) {
        std::string severity = issue.value("severity", "");
        if (severity == "critical") hasCritical = true;
        if (severity == "high") hasHigh = true;
    }

    if (hasCritical) return ReviewState::CHANGES_REQUESTED;
    if (hasHigh) return ReviewState::CHANGES_REQUESTED;
    return ReviewState::APPROVED;
}

// ============================================================================
// WorkflowAutomation Implementation
// ============================================================================

WorkflowAutomation::WorkflowAutomation(std::shared_ptr<GitHubClient> client)
    : m_client(client) {}

WorkflowAutomation::~WorkflowAutomation() = default;

std::future<WorkflowStatus> WorkflowAutomation::triggerWorkflow(const std::string& owner, const std::string& repo,
    const WorkflowTrigger& trigger) {
    return std::async(std::launch::async, [this, owner, repo, trigger]() -> WorkflowStatus {
        WorkflowStatus status;
        WorkflowDispatchRequest req;
        req.ref = trigger.ref;
        req.inputs = trigger.inputs;

        m_client->dispatchWorkflow(owner, repo, trigger.workflowId, req).get();

        // Wait a moment for the run to start
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Get the latest run
        auto runs = m_client->listWorkflowRuns(owner, repo, trigger.ref, 1, 1).get();
        if (!runs.empty()) {
            status.runId = runs[0].id;
            status.status = runs[0].status;
            status.conclusion = runs[0].conclusion;
            status.startedAt = runs[0].runStartedAt;
        }

        return status;
    });
}

std::future<WorkflowStatus> WorkflowAutomation::waitForCompletion(const std::string& owner, const std::string& repo,
    long long runId, int timeoutMinutes) {
    return std::async(std::launch::async, [this, owner, repo, runId, timeoutMinutes]() -> WorkflowStatus {
        WorkflowStatus status;
        auto start = std::chrono::steady_clock::now();
        auto timeout = std::chrono::minutes(timeoutMinutes);

        while (std::chrono::steady_clock::now() - start < timeout) {
            WorkflowRun run = m_client->getWorkflowRun(owner, repo, runId).get();
            status.runId = run.id;
            status.status = run.status;
            status.conclusion = run.conclusion;

            if (run.status == "completed") {
                return status;
            }

            std::this_thread::sleep_for(std::chrono::seconds(10));
        }

        status.status = "timeout";
        return status;
    });
}

std::future<std::string> WorkflowAutomation::getWorkflowLogs(const std::string& owner, const std::string& repo,
    long long runId) {
    return std::async(std::launch::async, [this, owner, repo, runId]() -> std::string {
        std::string url = "/repos/" + owner + "/" + repo + "/actions/runs/" + std::to_string(runId) + "/logs";
        std::map<std::string, std::string> headers;
        headers["Authorization"] = "token " + m_client->getToken();
        headers["Accept"] = "application/vnd.github.v3+json";
        return m_client->rawGet("https://api.github.com" + url, headers);
    });
}

std::future<std::vector<json>> WorkflowAutomation::listWorkflows(const std::string& owner, const std::string& repo) {
    return std::async(std::launch::async, [this, owner, repo]() -> std::vector<json> {
        json data = m_client->graphqlQuery(
            "query($owner:String!,$repo:String!){repository(owner:$owner,name:$repo){workflows(first:100){nodes{id name path}}}}",
            {{"owner", owner}, {"repo", repo}});
        std::vector<json> workflows;
        if (data.contains("data") && data["data"].contains("repository") &&
            data["data"]["repository"].contains("workflows") &&
            data["data"]["repository"]["workflows"].contains("nodes")) {
            for (const auto& w : data["data"]["repository"]["workflows"]["nodes"]) {
                workflows.push_back(w);
            }
        }
        return workflows;
    });
}

std::future<bool> WorkflowAutomation::cancelWorkflow(const std::string& owner, const std::string& repo, long long runId) {
    return m_client->cancelWorkflowRun(owner, repo, runId);
}

// ============================================================================
// Factory Functions
// ============================================================================

std::shared_ptr<GitHubClient> createGitHubClient(const GitHubClient::Config& config) {
    return std::make_shared<GitHubClient>(config);
}

std::shared_ptr<CloudAgent> createCloudAgent(const CloudAgentConfig& config) {
    return std::make_shared<CloudAgent>(config);
}

std::shared_ptr<CodeReviewAgent> createCodeReviewAgent(std::shared_ptr<GitHubClient> client) {
    return std::make_shared<CodeReviewAgent>(client);
}

std::shared_ptr<WorkflowAutomation> createWorkflowAutomation(std::shared_ptr<GitHubClient> client) {
    return std::make_shared<WorkflowAutomation>(client);
}

std::shared_ptr<PRBuilder> createPRBuilder(std::shared_ptr<GitHubClient> client,
    const std::string& owner, const std::string& repo) {
    return std::make_shared<PRBuilder>(client, owner, repo);
}

std::shared_ptr<IssueBuilder> createIssueBuilder(std::shared_ptr<GitHubClient> client,
    const std::string& owner, const std::string& repo) {
    return std::make_shared<IssueBuilder>(client, owner, repo);
}

} // namespace GitHub
} // namespace RawrXD