// Phase D.11 Batch 4/5: Interactive Tutorials
// Step-by-step guides with embedded code and validation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Documentation {

// ============================================================================
// Tutorial Types
// ============================================================================

enum class TutorialDifficulty {
    BEGINNER = 0,
    INTERMEDIATE = 1,
    ADVANCED = 2,
    EXPERT = 3
};

enum class TutorialStatus {
    NOT_STARTED = 0,
    IN_PROGRESS = 1,
    COMPLETED = 2,
    FAILED = 3
};

enum class StepType {
    TEXT = 0,
    CODE = 1,
    COMMAND = 2,
    QUIZ = 3,
    CHALLENGE = 4,
    VIDEO = 5,
    DIAGRAM = 6,
    INTERACTIVE = 7
};

struct TutorialStep {
    int step_number;
    std::string title;
    std::string description;
    StepType type;
    std::string content;
    std::string expected_output;
    std::string validation_script;
    std::vector<std::string> hints;
    std::chrono::seconds estimated_time{0};
    bool skippable = false;
    std::vector<std::string> prerequisites;
    std::map<std::string, std::string> metadata;
};

struct Tutorial {
    std::string id;
    std::string title;
    std::string description;
    TutorialDifficulty difficulty;
    std::vector<std::string> tags;
    std::vector<std::string> categories;
    std::vector<std::string> prerequisites;
    std::vector<TutorialStep> steps;
    std::map<std::string, std::string> metadata;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string author;
    int estimated_minutes = 30;
    int completion_count = 0;
    double avg_rating = 0.0;
};

struct TutorialProgress {
    std::string tutorial_id;
    std::string user_id;
    TutorialStatus status;
    int current_step = 0;
    std::vector<bool> completed_steps;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point completed_at;
    std::chrono::seconds time_spent{0};
    std::map<std::string, std::string> answers;
    std::map<std::string, int> attempt_counts;
};

// ============================================================================
// Tutorial Engine
// ============================================================================

class TutorialEngine {
public:
    struct Config {
        std::string tutorials_path;
        std::string progress_storage_path;
        bool enable_sandbox = true;
        int max_execution_time_seconds = 30;
        bool allow_code_execution = true;
    };
    
    explicit TutorialEngine(const Config& config);
    ~TutorialEngine();
    
    bool Initialize();
    void Shutdown();
    
    // Tutorial management
    bool LoadTutorial(const std::string& path);
    bool CreateTutorial(const Tutorial& tutorial);
    bool UpdateTutorial(const std::string& id, const Tutorial& tutorial);
    bool DeleteTutorial(const std::string& id);
    Tutorial GetTutorial(const std::string& id) const;
    std::vector<Tutorial> GetAllTutorials() const;
    
    // Search and filter
    std::vector<Tutorial> Search(const std::string& query) const;
    std::vector<Tutorial> GetByDifficulty(TutorialDifficulty difficulty) const;
    std::vector<Tutorial> GetByCategory(const std::string& category) const;
    std::vector<Tutorial> GetByTag(const std::string& tag) const;
    std::vector<Tutorial> GetRecommendedForUser(const std::string& user_id) const;
    
    // Progress tracking
    bool StartTutorial(const std::string& tutorial_id, const std::string& user_id);
    bool CompleteStep(const std::string& tutorial_id, const std::string& user_id, int step_number);
    bool FailStep(const std::string& tutorial_id, const std::string& user_id, int step_number);
    TutorialProgress GetProgress(const std::string& tutorial_id, const std::string& user_id) const;
    std::vector<TutorialProgress> GetUserProgress(const std::string& user_id) const;
    
    // Validation
    bool ValidateStep(const std::string& tutorial_id, int step_number, 
                      const std::string& user_input, std::string& feedback);
    bool ValidateCode(const std::string& code, const std::string& expected_output,
                      std::string& actual_output, std::string& error);
    bool ValidateCommand(const std::string& command, const std::string& expected_output,
                         std::string& actual_output);
    
private:
    Config config_;
    std::map<std::string, Tutorial> tutorials_;
    std::map<std::pair<std::string, std::string>, TutorialProgress> progress_;
    mutable std::mutex tutorials_mutex_;
    mutable std::mutex progress_mutex_;
    
    bool ExecuteInSandbox(const std::string& code, std::string& output, std::string& error);
};

// ============================================================================
// Code Playground
// ============================================================================

struct CodeSnippet {
    std::string id;
    std::string language;
    std::string code;
    std::string description;
    std::vector<std::string> dependencies;
    std::map<std::string, std::string> environment_vars;
    bool editable = true;
    bool runnable = true;
};

class CodePlayground {
public:
    struct Config {
        bool enable_execution = true;
        std::vector<std::string> supported_languages;
        int max_execution_time_ms = 5000;
        size_t max_memory_mb = 256;
        bool enable_network = false;
    };
    
    explicit CodePlayground(const Config& config);
    
    // Snippet management
    std::string CreateSnippet(const CodeSnippet& snippet);
    bool UpdateSnippet(const std::string& id, const CodeSnippet& snippet);
    CodeSnippet GetSnippet(const std::string& id) const;
    
    // Execution
    struct ExecutionResult {
        bool success;
        std::string output;
        std::string error;
        std::chrono::milliseconds execution_time{0};
        size_t memory_used = 0;
    };
    
    ExecutionResult Execute(const std::string& snippet_id);
    ExecutionResult ExecuteCode(const std::string& language, const std::string& code);
    
    // Validation
    bool ValidateSyntax(const std::string& language, const std::string& code, std::string& error);
    bool LintCode(const std::string& language, const std::string& code, 
                  std::vector<std::string>& warnings);
    
    // Templates
    std::vector<CodeSnippet> GetTemplates(const std::string& language) const;
    std::string GetTemplate(const std::string& language, const std::string& template_name) const;
    
private:
    Config config_;
    std::map<std::string, CodeSnippet> snippets_;
    mutable std::mutex snippets_mutex_;
    
    ExecutionResult ExecuteInContainer(const std::string& language, const std::string& code);
};

// ============================================================================
// Quiz System
// ============================================================================

enum class QuestionType {
    MULTIPLE_CHOICE = 0,
    TRUE_FALSE = 1,
    FILL_IN_BLANK = 2,
    MATCHING = 3,
    CODE_COMPLETION = 4,
    OPEN_ENDED = 5
};

struct QuizQuestion {
    std::string id;
    std::string question_text;
    QuestionType type;
    std::vector<std::string> options;
    std::vector<std::string> correct_answers;
    std::string explanation;
    int points = 1;
    std::vector<std::string> hints;
    std::chrono::seconds time_limit{0};
};

struct Quiz {
    std::string id;
    std::string title;
    std::string description;
    std::vector<QuizQuestion> questions;
    bool shuffle_questions = true;
    bool show_correct_answers = true;
    int passing_score = 70;
    std::chrono::minutes time_limit{30};
    int max_attempts = 3;
};

class QuizSystem {
public:
    // Quiz management
    bool CreateQuiz(const Quiz& quiz);
    bool UpdateQuiz(const std::string& id, const Quiz& quiz);
    bool DeleteQuiz(const std::string& id);
    Quiz GetQuiz(const std::string& id) const;
    std::vector<Quiz> GetAllQuizzes() const;
    
    // Taking quizzes
    struct QuizSession {
        std::string session_id;
        std::string quiz_id;
        std::string user_id;
        std::vector<int> question_order;
        std::map<std::string, std::string> answers;
        std::chrono::steady_clock::time_point started_at;
        std::chrono::steady_clock::time_point completed_at;
        bool completed = false;
    };
    
    QuizSession StartQuiz(const std::string& quiz_id, const std::string& user_id);
    bool SubmitAnswer(const std::string& session_id, const std::string& question_id,
                      const std::string& answer);
    struct QuizResult {
        int score = 0;
        int total_points = 0;
        int correct_answers = 0;
        int total_questions = 0;
        bool passed = false;
        std::map<std::string, bool> question_results;
        std::map<std::string, std::string> feedback;
    };
    
    QuizResult CompleteQuiz(const std::string& session_id);
    QuizResult GetResult(const std::string& session_id) const;
    
    // Analytics
    std::map<std::string, double> GetQuestionDifficulty() const;
    std::vector<std::string> GetMostMissedQuestions(const std::string& quiz_id) const;
    
private:
    std::map<std::string, Quiz> quizzes_;
    std::map<std::string, QuizSession> sessions_;
    mutable std::mutex quizzes_mutex_;
    mutable std::mutex sessions_mutex_;
};

// ============================================================================
// Challenge System
// ============================================================================

struct CodingChallenge {
    std::string id;
    std::string title;
    std::string description;
    std::string difficulty;
    std::vector<std::string> tags;
    std::string starter_code;
    std::vector<std::string> test_cases;
    std::vector<std::string> hidden_test_cases;
    std::map<std::string, std::string> constraints;
    std::chrono::seconds time_limit{60};
    int points = 100;
    std::string solution;
    std::vector<std::string> hints;
};

class ChallengeSystem {
public:
    // Challenge management
    bool CreateChallenge(const CodingChallenge& challenge);
    bool UpdateChallenge(const std::string& id, const CodingChallenge& challenge);
    CodingChallenge GetChallenge(const std::string& id) const;
    std::vector<CodingChallenge> GetChallengesByDifficulty(const std::string& difficulty) const;
    std::vector<CodingChallenge> GetChallengesByTag(const std::string& tag) const;
    
    // Submission
    struct Submission {
        std::string id;
        std::string challenge_id;
        std::string user_id;
        std::string code;
        std::chrono::steady_clock::time_point submitted_at;
        std::string status;  // pending, running, passed, failed
        int score = 0;
        std::vector<std::string> test_results;
        std::string error_message;
        std::chrono::milliseconds execution_time{0};
    };
    
    Submission SubmitSolution(const std::string& challenge_id, const std::string& user_id,
                                const std::string& code);
    Submission GetSubmission(const std::string& submission_id) const;
    std::vector<Submission> GetUserSubmissions(const std::string& user_id) const;
    
    // Evaluation
    bool EvaluateSubmission(Submission& submission);
    int CalculateScore(const Submission& submission, const CodingChallenge& challenge);
    
    // Leaderboard
    struct LeaderboardEntry {
        std::string user_id;
        int total_score = 0;
        int challenges_solved = 0;
        std::chrono::seconds total_time{0};
    };
    
    std::vector<LeaderboardEntry> GetLeaderboard(int limit = 100) const;
    LeaderboardEntry GetUserRank(const std::string& user_id) const;
    
private:
    std::map<std::string, CodingChallenge> challenges_;
    std::map<std::string, Submission> submissions_;
    mutable std::mutex challenges_mutex_;
    mutable std::mutex submissions_mutex_;
    
    bool RunTestCase(const std::string& code, const std::string& test_case,
                     std::string& output, std::string& error);
};

// ============================================================================
// Tutorial Analytics
// ============================================================================

struct TutorialMetrics {
    std::string tutorial_id;
    int total_starts = 0;
    int total_completions = 0;
    double completion_rate = 0.0;
    double avg_time_minutes = 0.0;
    double avg_rating = 0.0;
    std::map<int, double> step_completion_rates;
    std::map<int, int> step_drop_offs;
    std::vector<std::string> common_failures;
};

class TutorialAnalytics {
public:
    // Metrics collection
    void RecordTutorialStart(const std::string& tutorial_id, const std::string& user_id);
    void RecordTutorialComplete(const std::string& tutorial_id, const std::string& user_id);
    void RecordStepComplete(const std::string& tutorial_id, const std::string& user_id, 
                            int step_number);
    void RecordStepFail(const std::string& tutorial_id, const std::string& user_id,
                        int step_number, const std::string& reason);
    void RecordRating(const std::string& tutorial_id, const std::string& user_id, int rating);
    
    // Analysis
    TutorialMetrics GetMetrics(const std::string& tutorial_id) const;
    std::vector<Tutorial> GetMostPopularTutorials(int limit = 10) const;
    std::vector<Tutorial> GetMostDifficultTutorials(int limit = 10) const;
    std::vector<Tutorial> GetAbandonedTutorials(int limit = 10) const;
    
    // Insights
    std::vector<std::string> IdentifyBottlenecks(const std::string& tutorial_id) const;
    std::vector<std::string> SuggestImprovements(const std::string& tutorial_id) const;
    
    // Reporting
    void GenerateTutorialReport(const std::string& tutorial_id, const std::string& output_path);
    void GeneratePlatformReport(const std::string& output_path);
    
private:
    std::map<std::string, TutorialMetrics> metrics_;
    mutable std::mutex metrics_mutex_;
};

// ============================================================================
// Interactive Tutorial Runtime
// ============================================================================

class InteractiveTutorialRuntime {
public:
    struct Config {
        TutorialEngine::Config engine;
        CodePlayground::Config playground;
        QuizSystem::Config quiz;
        ChallengeSystem::Config challenge;
    };
    
    explicit InteractiveTutorialRuntime(const Config& config);
    ~InteractiveTutorialRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    TutorialEngine* GetEngine();
    CodePlayground* GetPlayground();
    QuizSystem* GetQuizSystem();
    ChallengeSystem* GetChallengeSystem();
    TutorialAnalytics* GetAnalytics();
    
    // Learning paths
    struct LearningPath {
        std::string id;
        std::string title;
        std::string description;
        std::vector<std::string> tutorial_ids;
        std::vector<std::string> quiz_ids;
        std::vector<std::string> challenge_ids;
        std::map<std::string, std::string> prerequisites;
    };
    
    bool CreateLearningPath(const LearningPath& path);
    bool UpdateLearningPath(const std::string& id, const LearningPath& path);
    LearningPath GetLearningPath(const std::string& id) const;
    std::vector<LearningPath> GetLearningPathsForUser(const std::string& user_id) const;
    
    // Progress tracking
    double CalculatePathProgress(const std::string& path_id, const std::string& user_id);
    std::string RecommendNextStep(const std::string& path_id, const std::string& user_id);
    
    // Certificates
    struct Certificate {
        std::string id;
        std::string user_id;
        std::string path_id;
        std::chrono::steady_clock::time_point issued_at;
        std::chrono::steady_clock::time_point expires_at;
        std::string verification_url;
    };
    
    Certificate IssueCertificate(const std::string& user_id, const std::string& path_id);
    bool VerifyCertificate(const std::string& certificate_id);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<TutorialEngine> engine_;
    std::unique_ptr<CodePlayground> playground_;
    std::unique_ptr<QuizSystem> quiz_system_;
    std::unique_ptr<ChallengeSystem> challenge_system_;
    std::unique_ptr<TutorialAnalytics> analytics_;
    
    std::map<std::string, LearningPath> learning_paths_;
    mutable std::mutex paths_mutex_;
};

} // namespace Documentation
} // namespace Sovereign
