<<<<<<< HEAD
#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

// C++20, no Qt. Token-bucket rate limiter per identifier (IP/user).

#include <string>
#include <map>
#include <chrono>
#include <mutex>

struct RateLimitInfo {
    int requestsPerSecond = 0;
    int tokens = 0;
    std::chrono::steady_clock::time_point lastRequestTime;
};

class RateLimiter
{
public:
    RateLimiter() = default;
    ~RateLimiter() = default;

    void setRateLimit(const std::string& identifier, int requestsPerSecond);
    bool isRequestAllowed(const std::string& identifier);

private:
    void refillTokens(const std::string& identifier, RateLimitInfo& info);

    std::mutex m_mutex;
    std::map<std::string, RateLimitInfo> m_rateLimits;
};

#endif // RATE_LIMITER_H
=======
#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <QObject>
#include <QMap>
#include <QDateTime>
#include <QString>

// Rate-limiter per IP / per user → token-bucket inside PerformanceOptimizer.
class RateLimiter : public QObject
{
    Q_OBJECT

public:
    explicit RateLimiter(QObject *parent = nullptr);
    ~RateLimiter();

    // Set rate limit (requests per second) for an IP or user
    void setRateLimit(const QString &identifier, int requestsPerSecond);

    // Check if a request is allowed for an IP or user
    bool isRequestAllowed(const QString &identifier);

private:
    struct RateLimitInfo {
        int requestsPerSecond;
        int tokens;
        QDateTime lastRequestTime;
    };

    QMap<QString, RateLimitInfo> m_rateLimits;
    
    // Refill tokens based on time elapsed
    void refillTokens(const QString &identifier, RateLimitInfo &info);
};

#endif // RATE_LIMITER_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
