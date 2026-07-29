<<<<<<< HEAD
#ifndef KV_CACHE_OPTIMIZER_H
#define KV_CACHE_OPTIMIZER_H

#include <vector>
#include <chrono>
#include <cstdio>

// KV-cache optimizer – dynamic sliding-window, cache eviction when context > 32 k.
class KVCacheOptimizer
{
public:
    explicit KVCacheOptimizer();
    ~KVCacheOptimizer();

    // Set cache size limit (in tokens)
    void setCacheSizeLimit(int limit);

    // Add tokens to cache
    void addTokens(const std::vector<int> &tokens);

    // Get cached tokens
    std::vector<int> getCachedTokens() const;

    // Get cache statistics
    int getCacheSize() const { return static_cast<int>(m_cachedTokens.size()); }
    int getCacheSizeLimit() const { return m_cacheSizeLimit; }

    // Set sliding window size
    void setSlidingWindowSize(int size);

    // Callback hooks (replacing Qt signals)
    void (*onCacheEvicted)(int tokensEvicted) = nullptr;
    void (*onCacheUpdated)(int totalTokens) = nullptr;

private:
    void evictIfNeeded();

    int m_cacheSizeLimit;
    int m_slidingWindowSize;
    std::vector<int> m_cachedTokens;
    std::chrono::steady_clock::time_point m_lastAccessTime;
    bool m_gpuCacheInitialized;
};

=======
#ifndef KV_CACHE_OPTIMIZER_H
#define KV_CACHE_OPTIMIZER_H

#include <QObject>
#include <QMap>
#include <QVariant>
#include <QDateTime>

// KV-cache optimizer – dynamic sliding-window, cache eviction when context > 32 k.
class KVCacheOptimizer : public QObject
{
    Q_OBJECT

public:
    explicit KVCacheOptimizer(QObject *parent = nullptr);
    ~KVCacheOptimizer();

    // Set cache size limit (in tokens)
    void setCacheSizeLimit(int limit);

    // Add tokens to cache
    void addTokens(const QList<int> &tokens);

    // Get cached tokens
    QList<int> getCachedTokens() const;

    // Evict tokens if cache is full
    void evictIfNeeded();

    // Set sliding window size
    void setSlidingWindowSize(int size);

private:
    int m_cacheSizeLimit;
    int m_slidingWindowSize;
    QList<int> m_cachedTokens;
    QDateTime m_lastAccessTime;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#endif // KV_CACHE_OPTIMIZER_H