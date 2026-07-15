// Chat Features TPS Benchmark
// Measures chat message processing throughput
// Tests: Message parsing, context management, response generation

#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdint>
#include <thread>
#include <numeric>
#include <algorithm>
#include <queue>
#include <mutex>
#include <random>
#include <sstream>

// Chat benchmark configuration
constexpr int NUM_CHAT_SESSIONS = 16;           // Concurrent chat sessions
constexpr int MESSAGES_PER_SESSION = 1000;        // Messages per session
constexpr int AVG_TOKENS_PER_MESSAGE = 50;      // Average tokens per message
constexpr int MAX_CONTEXT_LENGTH = 4096;          // Max context length
constexpr int WARMUP_MESSAGES = 100;              // Warmup messages

// Simulated chat message
struct ChatMessage {
    uint64_t id;
    std::string content;
    uint32_t token_count;
    uint64_t timestamp;
    bool is_user;
    
    ChatMessage(uint64_t i = 0, const std::string& c = "", uint32_t tc = 0, bool user = true)
        : id(i), content(c), token_count(tc), timestamp(0), is_user(user) {}
};

// Chat context (conversation history)
class ChatContext {
public:
    ChatContext(size_t max_length = MAX_CONTEXT_LENGTH) : max_length_(max_length) {}
    
    void AddMessage(const ChatMessage& msg) {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.push_back(msg);
        
        // Trim context if too long
        while (messages_.size() > max_length_) {
            messages_.erase(messages_.begin());
        }
    }
    
    size_t GetTokenCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t total = 0;
        for (const auto& msg : messages_) {
            total += msg.token_count;
        }
        return total;
    }
    
    size_t GetMessageCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return messages_.size();
    }
    
    std::vector<ChatMessage> GetMessages() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return messages_;
    }
    
private:
    mutable std::mutex mutex_;
    std::vector<ChatMessage> messages_;
    size_t max_length_;
};

// Simulated tokenizer
class Tokenizer {
public:
    uint32_t CountTokens(const std::string& text) {
        // Simple approximation: ~4 characters per token
        return static_cast<uint32_t>(text.length() / 4) + 1;
    }
    
    std::vector<uint32_t> Encode(const std::string& text) {
        uint32_t token_count = CountTokens(text);
        std::vector<uint32_t> tokens;
        tokens.reserve(token_count);
        
        for (uint32_t i = 0; i < token_count; ++i) {
            tokens.push_back(i % 32000);  // Simulate vocab
        }
        
        return tokens;
    }
    
    std::string Decode(const std::vector<uint32_t>& tokens) {
        // Simulate decoding
        std::string result;
        for (size_t i = 0; i < tokens.size(); ++i) {
            result += "word ";
        }
        return result;
    }
};

// Chat session simulating a user conversation
class ChatSession {
public:
    ChatSession(int id) : id_(id), messages_processed_(0), tokens_processed_(0) {}
    
    void ProcessMessage(const ChatMessage& message, Tokenizer& tokenizer) {
        auto start = std::chrono::high_resolution_clock::now();
        
        // 1. Tokenize input
        auto input_tokens = tokenizer.Encode(message.content);
        
        // 2. Add to context
        context_.AddMessage(message);
        
        // 3. Simulate inference (response generation)
        std::string response = GenerateResponse(input_tokens, tokenizer);
        
        // 4. Tokenize response
        auto response_tokens = tokenizer.Encode(response);
        
        // 5. Add response to context
        ChatMessage response_msg(message.id + 1, response, 
                                  static_cast<uint32_t>(response_tokens.size()), false);
        context_.AddMessage(response_msg);
        
        auto end = std::chrono::high_resolution_clock::now();
        
        // Update stats
        messages_processed_++;
        tokens_processed_ += input_tokens.size() + response_tokens.size();
        total_latency_ns_ += std::chrono::duration<double, std::nano>(end - start).count();
    }
    
    uint64_t GetMessagesProcessed() const { return messages_processed_; }
    uint64_t GetTokensProcessed() const { return tokens_processed_; }
    double GetAverageLatencyMs() const {
        return messages_processed_ > 0 ? (total_latency_ns_ / messages_processed_) / 1e6 : 0.0;
    }
    
private:
    std::string GenerateResponse(const std::vector<uint32_t>& input_tokens, Tokenizer& tokenizer) {
        // Simulate response generation
        // Response length proportional to input
        size_t response_length = input_tokens.size() * 2 + 10;
        
        std::ostringstream oss;
        oss << "Response to message with " << input_tokens.size() << " tokens. ";
        
        // Add filler to reach target length
        while (oss.str().length() < response_length * 4) {
            oss << "This is a simulated response. ";
        }
        
        return oss.str();
    }
    
    int id_;
    ChatContext context_;
    std::atomic<uint64_t> messages_processed_;
    std::atomic<uint64_t> tokens_processed_;
    std::atomic<double> total_latency_ns_;
};

// Chat server simulating multi-user chat
class ChatServer {
public:
    ChatServer(int num_sessions) {
        for (int i = 0; i < num_sessions; ++i) {
            sessions_.emplace_back(std::make_unique<ChatSession>(i));
        }
    }
    
    void RunBenchmark(int messages_per_session) {
        std::vector<std::thread> threads;
        
        // Launch threads for each session
        for (size_t i = 0; i < sessions_.size(); ++i) {
            threads.emplace_back(&ChatServer::SessionWorker, this, i, messages_per_session);
        }
        
        // Wait for completion
        for (auto& t : threads) {
            t.join();
        }
    }
    
    uint64_t GetTotalMessagesProcessed() const {
        uint64_t total = 0;
        for (const auto& session : sessions_) {
            total += session->GetMessagesProcessed();
        }
        return total;
    }
    
    uint64_t GetTotalTokensProcessed() const {
        uint64_t total = 0;
        for (const auto& session : sessions_) {
            total += session->GetTokensProcessed();
        }
        return total;
    }
    
    double GetAverageLatencyMs() const {
        double total = 0;
        size_t count = 0;
        for (const auto& session : sessions_) {
            total += session->GetAverageLatencyMs();
            count++;
        }
        return count > 0 ? total / count : 0.0;
    }
    
private:
    void SessionWorker(size_t session_id, int message_count) {
        Tokenizer tokenizer;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> token_dist(10, 100);
        
        for (int i = 0; i < message_count; ++i) {
            // Generate random message
            uint32_t tokens = token_dist(gen);
            std::string content = GenerateRandomMessage(tokens);
            
            ChatMessage msg(i, content, tokens, true);
            sessions_[session_id]->ProcessMessage(msg, tokenizer);
        }
    }
    
    std::string GenerateRandomMessage(uint32_t token_count) {
        std::ostringstream oss;
        for (uint32_t i = 0; i < token_count; ++i) {
            oss << "word" <> i << " ";
        }
        return oss.str();
    }
    
    std::vector<std::unique_ptr<ChatSession>> sessions_;
};

// Benchmark result
struct ChatBenchmarkResult {
    double duration_sec;
    uint64_t total_messages;
    uint64_t total_tokens;
    double messages_per_sec;
    double tokens_per_sec;
    double avg_latency_ms;
    double throughput_mbps;
    
    void Print() const {
        std::cout << "  Duration:            " << std::setw(15) << std::fixed << std::setprecision(2) 
                  << duration_sec << " s" << std::endl;
        std::cout << "  Total Messages:      " << std::setw(15) << total_messages << std::endl;
        std::cout << "  Total Tokens:        " << std::setw(15) << total_tokens << std::endl;
        std::cout << "  Messages/sec:        " << std::setw(15) << std::fixed << std::setprecision(2) 
                  << messages_per_sec << std::endl;
        std::cout << "  Tokens/sec (TPS):    " << std::setw(15) << std::fixed << std::setprecision(2) 
                  << tokens_per_sec << std::endl;
        std::cout << "  Avg Latency:         " << std::setw(15) << std::fixed << std::setprecision(3) 
                  << avg_latency_ms << " ms/msg" << std::endl;
        std::cout << "  Throughput:          " << std::setw(15) << std::fixed << std::setprecision(2) 
                  << throughput_mbps << " MB/s" << std::endl;
    }
};

// Run chat benchmark
ChatBenchmarkResult RunChatBenchmark(int num_sessions, int messages_per_session) {
    ChatServer server(num_sessions);
    
    auto start = std::chrono::high_resolution_clock::now();
    server.RunBenchmark(messages_per_session);
    auto end = std::chrono::high_resolution_clock::now();
    
    double duration_sec = std::chrono::duration<double>(end - start).count();
    uint64_t total_messages = server.GetTotalMessagesProcessed();
    uint64_t total_tokens = server.GetTotalTokensProcessed();
    
    ChatBenchmarkResult result;
    result.duration_sec = duration_sec;
    result.total_messages = total_messages;
    result.total_tokens = total_tokens;
    result.messages_per_sec = total_messages / duration_sec;
    result.tokens_per_sec = total_tokens / duration_sec;
    result.avg_latency_ms = server.GetAverageLatencyMs();
    result.throughput_mbps = (total_tokens * sizeof(float)) / (duration_sec * 1e6);
    
    return result;
}

// Print header
void PrintHeader() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "Chat Features TPS Benchmark" << std::endl;
    std::cout << "================================================================================" << std::endl;
    std::cout << "Tests: Message parsing, context management, response generation" << std::endl;
    std::cout << "Sessions: " << NUM_CHAT_SESSIONS << std::endl;
    std::cout << "Messages per session: " << MESSAGES_PER_SESSION << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    PrintHeader();
    
    // Warmup
    std::cout << "[1/3] Warmup (" << WARMUP_MESSAGES << " messages)..." << std::endl;
    auto warmup_result = RunChatBenchmark(2, WARMUP_MESSAGES / 2);
    std::cout << "  Warmup TPS: " << std::fixed << std::setprecision(2) << warmup_result.tokens_per_sec << std::endl;
    std::cout << std::endl;
    
    // Benchmark
    std::cout << "[2/3] Benchmarking (" << NUM_CHAT_SESSIONS << " sessions x " << MESSAGES_PER_SESSION << " messages)..." << std::endl;
    auto result = RunChatBenchmark(NUM_CHAT_SESSIONS, MESSAGES_PER_SESSION);
    std::cout << std::endl;
    
    // Results
    std::cout << "[3/3] Results:" << std::endl;
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    result.Print();
    std::cout << "--------------------------------------------------------------------------------" << std::endl;
    
    // Performance rating
    std::cout << std::endl;
    std::cout << "Chat Performance Rating:" << std::endl;
    if (result.tokens_per_sec > 100000) {
        std::cout << "  EXCELLENT: >100K TPS chat throughput" << std::endl;
    } else if (result.tokens_per_sec > 10000) {
        std::cout << "  VERY GOOD: >10K TPS chat throughput" << std::endl;
    } else if (result.tokens_per_sec > 1000) {
        std::cout << "  GOOD: >1K TPS chat throughput" << std::endl;
    } else if (result.tokens_per_sec > 100) {
        std::cout << "  MODERATE: >100 TPS chat throughput" << std::endl;
    } else {
        std::cout << "  NEEDS OPTIMIZATION" << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "Benchmark complete." << std::endl;
    
    return 0;
}
