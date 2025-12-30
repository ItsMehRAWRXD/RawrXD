#ifndef QT_ASYNC_FILE_OPERATIONS_HPP
#define QT_ASYNC_FILE_OPERATIONS_HPP

#include <QString>
#include <QByteArray>
#include <QObject>
#include <QMutex>
#include <memory>
#include "qt_async_callbacks.hpp"

// =============================================================================
// Qt Async File Operations - Pure MASM Thread Pool Wrapper
// =============================================================================
// Provides async file I/O operations backed by pure MASM thread pool
// Thread-safe, cross-platform (Windows/Linux/macOS), zero external dependencies
// =============================================================================

/**
 * @class QtAsyncFileOps
 * @brief Asynchronous file operations using pure MASM thread pool
 * 
 * Provides non-blocking file read/write operations with:
 * - Progress callbacks (periodic status updates)
 * - Cancellation support (graceful cancellation)
 * - Error handling (detailed error reporting)
 * - Multiple concurrent operations
 * - Configurable thread pool size
 * 
 * Usage:
 *   QtAsyncFileOps async_ops;
 *   async_ops.readFileAsync(
 *       "/path/to/file",
 *       [](const AsyncResult& result) {
 *           if (result.success) {
 *               qDebug() << "Read complete:" << result.bytes_processed << "bytes";
 *           }
 *       }
 *   );
 */
class QtAsyncFileOps : public QObject {
    Q_OBJECT
    
public:
    /**
     * Constructor
     * @param thread_count Number of worker threads (default: 4)
     * @param parent Qt parent object
     */
    explicit QtAsyncFileOps(int thread_count = 4, QObject* parent = nullptr);
    
    /**
     * Destructor - waits for pending operations
     */
    ~QtAsyncFileOps();
    
    // Disable copy operations
    QtAsyncFileOps(const QtAsyncFileOps&) = delete;
    QtAsyncFileOps& operator=(const QtAsyncFileOps&) = delete;
    
    // =========================================================================
    // Async File Read Operations
    // =========================================================================
    
    /**
     * Read entire file asynchronously
     * @param file_path Path to file to read
     * @param on_complete Callback invoked when read completes
     * @param on_progress Optional callback for progress updates
     * @param chunk_size Size of chunks to read (default: 64KB)
     * @return Work item ID (for cancellation)
     * 
     * Thread Safety: Safe to call from any thread
     */
    uint64_t readFileAsync(
        const QString& file_path,
        WorkCompleteCallback on_complete,
        ProgressCallback on_progress = nullptr,
        uint64_t chunk_size = 65536
    );
    
    /**
     * Read part of file asynchronously
     * @param file_path Path to file
     * @param offset Starting offset in file
     * @param size Number of bytes to read
     * @param on_complete Callback invoked on completion
     * @param on_progress Optional progress callback
     * @return Work item ID
     * 
     * Thread Safety: Safe to call from any thread
     */
    uint64_t readFilePartAsync(
        const QString& file_path,
        uint64_t offset,
        uint64_t size,
        WorkCompleteCallback on_complete,
        ProgressCallback on_progress = nullptr
    );
    
    // =========================================================================
    // Async File Write Operations
    // =========================================================================
    
    /**
     * Write data to file asynchronously
     * @param file_path Path to file to write
     * @param data Data to write
     * @param on_complete Callback on completion
     * @param on_progress Optional progress callback
     * @return Work item ID
     * 
     * Thread Safety: Safe to call from any thread
     */
    uint64_t writeFileAsync(
        const QString& file_path,
        const QByteArray& data,
        WorkCompleteCallback on_complete,
        ProgressCallback on_progress = nullptr
    );
    
    /**
     * Write data to file at specific offset asynchronously
     * @param file_path Path to file
     * @param offset Offset in file to write at
     * @param data Data to write
     * @param on_complete Callback on completion
     * @param on_progress Optional progress callback
     * @return Work item ID
     * 
     * Thread Safety: Safe to call from any thread
     */
    uint64_t writeFilePartAsync(
        const QString& file_path,
        uint64_t offset,
        const QByteArray& data,
        WorkCompleteCallback on_complete,
        ProgressCallback on_progress = nullptr
    );
    
    // =========================================================================
    // Async File Copy Operations
    // =========================================================================
    
    /**
     * Copy file asynchronously
     * @param source_path Source file path
     * @param dest_path Destination file path
     * @param on_complete Callback on completion
     * @param on_progress Optional progress callback (for large files)
     * @return Work item ID
     * 
     * Thread Safety: Safe to call from any thread
     */
    uint64_t copyFileAsync(
        const QString& source_path,
        const QString& dest_path,
        WorkCompleteCallback on_complete,
        ProgressCallback on_progress = nullptr
    );
    
    // =========================================================================
    // Operation Management
    // =========================================================================
    
    /**
     * Cancel an ongoing operation
     * @param work_id Work item ID returned from async operation
     * @return True if cancellation was initiated
     * 
     * Thread Safety: Safe to call from any thread
     * Note: Cancellation may not be immediate
     */
    bool cancelOperation(uint64_t work_id);
    
    /**
     * Wait for operation to complete
     * @param work_id Work item ID
     * @param timeout_ms Maximum time to wait in milliseconds (-1 = infinite)
     * @return Result of operation
     * 
     * Thread Safety: Safe to call from any thread
     */
    AsyncResult waitForOperation(uint64_t work_id, int timeout_ms = -1);
    
    /**
     * Get current status of operation
     * @param work_id Work item ID
     * @return Current async status
     * 
     * Thread Safety: Safe to call from any thread
     */
    AsyncStatus getOperationStatus(uint64_t work_id);
    
    /**
     * Get number of pending operations
     * @return Count of queued or running operations
     * 
     * Thread Safety: Safe to call from any thread
     */
    int getPendingOperationCount();
    
    // =========================================================================
    // Thread Pool Management
    // =========================================================================
    
    /**
     * Start the thread pool
     * @return True if successfully started
     * 
     * Thread Safety: Safe to call from any thread
     */
    bool startThreadPool();
    
    /**
     * Stop the thread pool and wait for pending operations
     * @param timeout_ms Maximum time to wait (default: 30000ms = 30 seconds)
     * @return True if shutdown completed before timeout
     * 
     * Thread Safety: Safe to call from any thread
     */
    bool stopThreadPool(int timeout_ms = 30000);
    
    /**
     * Check if thread pool is running
     * @return True if pool is active
     * 
     * Thread Safety: Safe to call from any thread
     */
    bool isThreadPoolRunning();
    
    /**
     * Get thread pool statistics
     * @param total_processed Output: total work items processed
     * @param total_errors Output: total errors occurred
     * 
     * Thread Safety: Safe to call from any thread
     */
    void getThreadPoolStats(uint64_t& total_processed, uint64_t& total_errors);
    
    // =========================================================================
    // Signals
    // =========================================================================
    
signals:
    /**
     * Emitted when async operation completes
     */
    void operationComplete(uint64_t work_id, const AsyncResult& result);
    
    /**
     * Emitted periodically during operation for progress updates
     */
    void operationProgress(uint64_t work_id, const AsyncProgress& progress);
    
    /**
     * Emitted when an error occurs
     */
    void operationError(uint64_t work_id, AsyncErrorCode code, const QString& message);
    
    /**
     * Emitted when operation is cancelled
     */
    void operationCancelled(uint64_t work_id);
    
protected slots:
    void onOperationComplete(uint64_t work_id, const AsyncResult& result);
    void onOperationProgress(uint64_t work_id, const AsyncProgress& progress);
    void onOperationError(uint64_t work_id, AsyncErrorCode code, const QString& message);
    
private:
    // Implementation details
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    
    mutable QMutex m_mutex;
    
    // MASM function declarations
    extern "C" {
        // Thread pool management
        void* wrapper_thread_pool_create(uint32_t thread_count);
        int wrapper_thread_pool_destroy(void* pool);
        
        // Work submission
        uint64_t wrapper_thread_pool_queue_work(
            void* pool,
            void* work_item
        );
        
        uint64_t wrapper_thread_pool_queue_file_read(
            void* pool,
            const char* file_path,
            uint8_t* buffer,
            uint64_t buffer_size,
            uint64_t offset
        );
        
        uint64_t wrapper_thread_pool_queue_file_write(
            void* pool,
            const char* file_path,
            const uint8_t* buffer,
            uint64_t buffer_size,
            uint64_t offset
        );
        
        // Operation management
        int wrapper_thread_pool_get_status(
            void* pool,
            uint64_t work_id
        );
        
        int wrapper_thread_pool_cancel_work(
            void* pool,
            uint64_t work_id
        );
        
        int wrapper_thread_pool_shutdown(void* pool);
    }
};

// =============================================================================
// Convenience Functions
// =============================================================================

/**
 * Global async file operations instance (singleton)
 * @return Reference to global QtAsyncFileOps instance
 */
QtAsyncFileOps& asyncFileOps();

/**
 * Read file asynchronously (convenience function)
 * @param file_path Path to file
 * @param on_complete Completion callback
 * @return Work ID for cancellation
 */
inline uint64_t qReadFileAsync(
    const QString& file_path,
    WorkCompleteCallback on_complete)
{
    return asyncFileOps().readFileAsync(file_path, on_complete);
}

/**
 * Write file asynchronously (convenience function)
 * @param file_path Path to file
 * @param data Data to write
 * @param on_complete Completion callback
 * @return Work ID for cancellation
 */
inline uint64_t qWriteFileAsync(
    const QString& file_path,
    const QByteArray& data,
    WorkCompleteCallback on_complete)
{
    return asyncFileOps().writeFileAsync(file_path, data, on_complete);
}

/**
 * Copy file asynchronously (convenience function)
 * @param source Source path
 * @param dest Destination path
 * @param on_complete Completion callback
 * @return Work ID for cancellation
 */
inline uint64_t qCopyFileAsync(
    const QString& source,
    const QString& dest,
    WorkCompleteCallback on_complete)
{
    return asyncFileOps().copyFileAsync(source, dest, on_complete);
}

#endif // QT_ASYNC_FILE_OPERATIONS_HPP
