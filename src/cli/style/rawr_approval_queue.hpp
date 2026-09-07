// rawr_approval_queue.hpp — user approval for destructive/network actions
#pragma once
#include <deque>
#include <string>

namespace rawr::style {

enum class ApprovalKind : int { Destructive = 1, Network = 2, GitPush = 3, Other = 0 };

struct ApprovalItem {
    std::string id;
    ApprovalKind kind = ApprovalKind::Other;
    std::string summary;
    bool approved = false;
    bool decided = false;
};

struct ApprovalQueue {
    std::deque<ApprovalItem> q;
    int seq = 0;

    std::string enqueue(ApprovalKind k, const std::string& summary) {
        ApprovalItem it{};
        it.id = "appr_" + std::to_string(++seq);
        it.kind = k;
        it.summary = summary;
        q.push_back(it);
        return it.id;
    }

    bool decide(const std::string& id, bool approve) {
        for (auto& it : q) {
            if (it.id == id) {
                it.approved = approve;
                it.decided = true;
                return true;
            }
        }
        return false;
    }

    bool pending() const {
        for (const auto& it : q)
            if (!it.decided) return true;
        return false;
    }

    ApprovalItem* frontPending() {
        for (auto& it : q)
            if (!it.decided) return &it;
        return nullptr;
    }
};

} // namespace rawr::style
