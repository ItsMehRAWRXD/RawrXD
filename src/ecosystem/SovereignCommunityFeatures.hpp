// Phase D.12 Batch 3/5: Community Features
// Forums, contributions, ratings, and reviews
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Ecosystem {

// ============================================================================
// Forum System
// ============================================================================

enum class ForumPostStatus {
    ACTIVE = 0,
    LOCKED = 1,
    ARCHIVED = 2,
    DELETED = 3
};

struct ForumPost {
    std::string id;
    std::string title;
    std::string content;
    std::string author_id;
    std::string author_name;
    std::string category;
    std::vector<std::string> tags;
    ForumPostStatus status;
    int view_count = 0;
    int reply_count = 0;
    int upvotes = 0;
    int downvotes = 0;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::chrono::steady_clock::time_point last_reply_at;
    std::string last_reply_by;
    bool is_pinned = false;
    bool is_announcement = false;
    std::map<std::string, std::string> metadata;
};

struct ForumReply {
    std::string id;
    std::string post_id;
    std::string parent_id;  // For nested replies
    std::string content;
    std::string author_id;
    std::string author_name;
    int upvotes = 0;
    int downvotes = 0;
    bool is_solution = false;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::vector<std::string> attachments;
};

class ForumSystem {
public:
    struct Config {
        std::string storage_path;
        bool enable_voting = true;
        bool enable_attachments = true;
        size_t max_attachment_size_mb = 10;
        int posts_per_page = 20;
        bool require_approval = false;
    };
    
    explicit ForumSystem(const Config& config);
    ~ForumSystem();
    
    bool Initialize();
    void Shutdown();
    
    // Post management
    std::string CreatePost(const ForumPost& post);
    bool UpdatePost(const std::string& post_id, const ForumPost& post);
    bool DeletePost(const std::string& post_id);
    ForumPost GetPost(const std::string& post_id) const;
    
    // Reply management
    std::string CreateReply(const ForumReply& reply);
    bool UpdateReply(const std::string& reply_id, const ForumReply& reply);
    bool DeleteReply(const std::string& reply_id);
    std::vector<ForumReply> GetReplies(const std::string& post_id) const;
    
    // Categories
    bool CreateCategory(const std::string& name, const std::string& description);
    bool DeleteCategory(const std::string& name);
    std::vector<std::string> GetCategories() const;
    std::vector<ForumPost> GetPostsByCategory(const std::string& category, int page = 0) const;
    
    // Search and filter
    std::vector<ForumPost> SearchPosts(const std::string& query) const;
    std::vector<ForumPost> GetPostsByTag(const std::string& tag) const;
    std::vector<ForumPost> GetPostsByAuthor(const std::string& author_id) const;
    std::vector<ForumPost> GetRecentPosts(int limit = 20) const;
    std::vector<ForumPost> GetPopularPosts(int limit = 20) const;
    std::vector<ForumPost> GetUnansweredPosts(int limit = 20) const;
    
    // Voting
    bool UpvotePost(const std::string& post_id, const std::string& user_id);
    bool DownvotePost(const std::string& post_id, const std::string& user_id);
    bool UpvoteReply(const std::string& reply_id, const std::string& user_id);
    bool DownvoteReply(const std::string& reply_id, const std::string& user_id);
    
    // Moderation
    bool PinPost(const std::string& post_id);
    bool UnpinPost(const std::string& post_id);
    bool LockPost(const std::string& post_id);
    bool UnlockPost(const std::string& post_id);
    bool MarkAsSolution(const std::string& reply_id);
    
    // Statistics
    struct ForumStats {
        int total_posts = 0;
        int total_replies = 0;
        int total_users = 0;
        int posts_today = 0;
        std::map<std::string, int> posts_by_category;
    };
    
    ForumStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, ForumPost> posts_;
    std::map<std::string, ForumReply> replies_;
    mutable std::mutex posts_mutex_;
    mutable std::mutex replies_mutex_;
};

// ============================================================================
// Contribution System
// ============================================================================

enum class ContributionType {
    CODE = 0,
    DOCUMENTATION = 1,
    TRANSLATION = 2,
    DESIGN = 3,
    TESTING = 4,
    BUG_REPORT = 5,
    FEATURE_REQUEST = 6
};

enum class ContributionStatus {
    SUBMITTED = 0,
    UNDER_REVIEW = 1,
    ACCEPTED = 2,
    REJECTED = 3,
    MERGED = 4,
    CLOSED = 5
};

struct Contribution {
    std::string id;
    std::string title;
    std::string description;
    ContributionType type;
    ContributionStatus status;
    std::string author_id;
    std::string author_name;
    std::string target_package_id;
    std::vector<std::string> files;
    std::string diff_url;
    std::vector<std::string> reviewers;
    std::map<std::string, std::string> review_comments;
    int points = 0;
    std::chrono::steady_clock::time_point submitted_at;
    std::chrono::steady_clock::time_point updated_at;
    std::chrono::steady_clock::time_point merged_at;
    std::string merged_by;
};

class ContributionSystem {
public:
    struct Config {
        std::string repository_url;
        std::string ci_webhook_url;
        bool require_cla = true;
        int min_reviewers = 1;
        bool auto_assign_reviewers = true;
    };
    
    explicit ContributionSystem(const Config& config);
    
    // Contribution lifecycle
    std::string SubmitContribution(const Contribution& contribution);
    bool UpdateContribution(const std::string& id, const Contribution& contribution);
    bool AssignReviewers(const std::string& id, const std::vector<std::string>& reviewers);
    bool AddReviewComment(const std::string& id, const std::string& reviewer, 
                          const std::string& comment);
    bool ApproveContribution(const std::string& id, const std::string& reviewer);
    bool RejectContribution(const std::string& id, const std::string& reviewer, 
                            const std::string& reason);
    bool MergeContribution(const std::string& id, const std::string& merger);
    
    // Queries
    Contribution GetContribution(const std::string& id) const;
    std::vector<Contribution> GetContributionsByAuthor(const std::string& author_id) const;
    std::vector<Contribution> GetContributionsByStatus(ContributionStatus status) const;
    std::vector<Contribution> GetPendingReview() const;
    std::vector<Contribution> GetContributionsForPackage(const std::string& package_id) const;
    
    // Points
    int CalculatePoints(const Contribution& contribution) const;
    bool AwardPoints(const std::string& contribution_id, int points);
    
private:
    Config config_;
    std::map<std::string, Contribution> contributions_;
    mutable std::mutex contributions_mutex_;
};

// ============================================================================
// User Reputation System
// ============================================================================

struct UserReputation {
    std::string user_id;
    int total_points = 0;
    int contribution_points = 0;
    int community_points = 0;
    int level = 1;
    std::string rank;
    std::vector<std::string> badges;
    std::map<std::string, int> category_points;
    std::chrono::steady_clock::time_point joined_at;
    std::chrono::steady_clock::time_point last_active;
};

class ReputationSystem {
public:
    struct Config {
        std::vector<std::pair<int, std::string>> rank_thresholds;
        std::map<std::string, int> badge_requirements;
        bool enable_leaderboard = true;
    };
    
    explicit ReputationSystem(const Config& config);
    
    // Points management
    bool AwardPoints(const std::string& user_id, int points, const std::string& category);
    bool DeductPoints(const std::string& user_id, int points, const std::string& reason);
    
    // Reputation queries
    UserReputation GetReputation(const std::string& user_id) const;
    int GetPoints(const std::string& user_id) const;
    std::string GetRank(const std::string& user_id) const;
    int GetLevel(const std::string& user_id) const;
    
    // Badges
    bool AwardBadge(const std::string& user_id, const std::string& badge);
    bool RevokeBadge(const std::string& user_id, const std::string& badge);
    std::vector<std::string> GetBadges(const std::string& user_id) const;
    bool HasBadge(const std::string& user_id, const std::string& badge) const;
    
    // Leaderboard
    std::vector<UserReputation> GetLeaderboard(int limit = 100) const;
    int GetUserRank(const std::string& user_id) const;
    
    // Statistics
    std::map<std::string, int> GetCategoryBreakdown(const std::string& user_id) const;
    
private:
    Config config_;
    std::map<std::string, UserReputation> reputations_;
    mutable std::mutex reputations_mutex_;
    
    void UpdateRank(UserReputation& reputation);
    void CheckBadges(UserReputation& reputation);
};

// ============================================================================
// Notification System
// ============================================================================

enum class NotificationType {
    POST_REPLY = 0,
    POST_MENTION = 1,
    CONTRIBUTION_UPDATE = 2,
    REVIEW_REQUEST = 3,
    BADGE_AWARDED = 4,
    POINTS_AWARDED = 5,
    PACKAGE_UPDATE = 6,
    SYSTEM = 7
};

struct Notification {
    std::string id;
    std::string user_id;
    NotificationType type;
    std::string title;
    std::string message;
    std::map<std::string, std::string> data;
    bool read = false;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point read_at;
};

class NotificationSystem {
public:
    struct Config {
        bool enable_email = true;
        bool enable_push = true;
        bool enable_in_app = true;
        int max_notifications_per_user = 1000;
        std::chrono::days retention_days{30};
    };
    
    explicit NotificationSystem(const Config& config);
    
    // Notification management
    std::string SendNotification(const Notification& notification);
    bool MarkAsRead(const std::string& notification_id);
    bool MarkAllAsRead(const std::string& user_id);
    bool DeleteNotification(const std::string& notification_id);
    
    // Queries
    std::vector<Notification> GetNotifications(const std::string& user_id) const;
    std::vector<Notification> GetUnreadNotifications(const std::string& user_id) const;
    int GetUnreadCount(const std::string& user_id) const;
    
    // Preferences
    bool SetNotificationPreference(const std::string& user_id, NotificationType type, 
                                   bool enabled);
    std::map<NotificationType, bool> GetNotificationPreferences(const std::string& user_id) const;
    
    // Broadcasting
    void BroadcastToAll(const Notification& notification);
    void BroadcastToCategory(const std::string& category, const Notification& notification);
    
private:
    Config config_;
    std::map<std::string, std::vector<Notification>> notifications_;
    mutable std::mutex notifications_mutex_;
};

// ============================================================================
// Community Runtime
// ============================================================================

class CommunityRuntime {
public:
    struct Config {
        ForumSystem::Config forum;
        ContributionSystem::Config contributions;
        ReputationSystem::Config reputation;
        NotificationSystem::Config notifications;
    };
    
    explicit CommunityRuntime(const Config& config);
    ~CommunityRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ForumSystem* GetForum();
    ContributionSystem* GetContributions();
    ReputationSystem* GetReputation();
    NotificationSystem* GetNotifications();
    
    // User profile
    struct UserProfile {
        std::string user_id;
        std::string display_name;
        std::string bio;
        std::string avatar_url;
        UserReputation reputation;
        int post_count = 0;
        int contribution_count = 0;
        std::vector<std::string> badges;
        std::chrono::steady_clock::time_point joined_at;
    };
    
    UserProfile GetUserProfile(const std::string& user_id) const;
    bool UpdateUserProfile(const std::string& user_id, const UserProfile& profile);
    
    // Activity feed
    std::vector<std::string> GetUserActivity(const std::string& user_id, int limit = 20) const;
    std::vector<std::string> GetGlobalActivity(int limit = 50) const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ForumSystem> forum_;
    std::unique_ptr<ContributionSystem> contributions_;
    std::unique_ptr<ReputationSystem> reputation_;
    std::unique_ptr<NotificationSystem> notifications_;
};

} // namespace Ecosystem
} // namespace Sovereign
