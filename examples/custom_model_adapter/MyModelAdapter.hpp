// MyModelAdapter.hpp
// Example custom model adapter for RawrXD
// This demonstrates how to integrate a custom inference backend

#pragma once
#include <rawrxd/developer/PluginSDK.hpp>
#include <memory>
#include <vector>
#include <string>

// Forward declaration of your custom model implementation
class CustomModelImpl;

// Custom model backend implementation
class MyModelBackend : public RawrXD::Developer::IModelBackend {
public:
    MyModelBackend() = default;
    ~MyModelBackend() override {
        Shutdown();
    }

    bool Initialize(const std::unordered_map<std::string, std::string>& config) override {
        try {
            // Extract configuration
            model_path_ = config.at("model_path");
            device_ = config.count("device") ? config.at("device") : "cpu";
            threads_ = config.count("threads") ? std::stoi(config.at("threads")) : 4;
            
            // Initialize your custom model here
            // This is where you'd load weights, set up tensors, etc.
            impl_ = std::make_unique<CustomModelImpl>();
            
            if (!impl_->Load(model_path_, device_, threads_)) {
                return false;
            }
            
            is_initialized_ = true;
            return true;
        } catch (const std::exception& e) {
            last_error_ = e.what();
            return false;
        }
    }

    void Shutdown() override {
        if (impl_) {
            impl_->Unload();
            impl_.reset();
        }
        is_initialized_ = false;
    }

    std::string Generate(const std::string& prompt,
                         const std::unordered_map<std::string, std::string>& params) override {
        if (!is_initialized_ || !impl_) {
            return "{\"error\": \"Model not initialized\"}";
        }
        
        try {
            // Extract generation parameters
            int max_tokens = params.count("max_tokens") ? std::stoi(params.at("max_tokens")) : 256;
            float temperature = params.count("temperature") ? std::stof(params.at("temperature")) : 0.7f;
            float top_p = params.count("top_p") ? std::stof(params.at("top_p")) : 0.9f;
            int top_k = params.count("top_k") ? std::stoi(params.at("top_k")) : 40;
            
            // Run inference
            auto start = std::chrono::steady_clock::now();
            std::string generated_text = impl_->Generate(prompt, max_tokens, temperature, top_p, top_k);
            auto end = std::chrono::steady_clock::now();
            
            // Calculate metrics
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            int tokens_generated = CountTokens(generated_text);
            float tokens_per_second = tokens_generated * 1000.0f / duration.count();
            
            // Build response
            std::string response = "{";
            response += "\"text\": \"" + EscapeJson(generated_text) + "\",";
            response += "\"tokens_generated\": " + std::to_string(tokens_generated) + ",";
            response += "\"tokens_per_second\": " + std::to_string(tokens_per_second) + ",";
            response += "\"duration_ms\": " + std::to_string(duration.count());
            response += "}";
            
            return response;
        } catch (const std::exception& e) {
            return "{\"error\": \"" + std::string(e.what()) + "\"}";
        }
    }

    void GenerateStream(const std::string& prompt,
                         const std::unordered_map<std::string, std::string>& params,
                         std::function<void(const std::string&)> callback) override {
        if (!is_initialized_ || !impl_) {
            callback("{\"error\": \"Model not initialized\"}");
            return;
        }
        
        try {
            int max_tokens = params.count("max_tokens") ? std::stoi(params.at("max_tokens")) : 256;
            float temperature = params.count("temperature") ? std::stof(params.at("temperature")) : 0.7f;
            
            // Stream tokens one by one
            std::string current_text;
            for (int i = 0; i < max_tokens; ++i) {
                std::string token = impl_->GenerateToken(prompt + current_text, temperature);
                if (token.empty()) break;
                
                current_text += token;
                
                // Send token to callback
                std::string response = "{";
                response += "\"token\": \"" + EscapeJson(token) + "\",";
                response += "\"text\": \"" + EscapeJson(current_text) + "\"";
                response += "}";
                
                callback(response);
            }
        } catch (const std::exception& e) {
            callback("{\"error\": \"" + std::string(e.what()) + "\"}");
        }
    }

    void ClearContext() override {
        if (impl_) {
            impl_->ClearContext();
        }
    }

    std::unordered_map<std::string, std::string> GetStats() override {
        std::unordered_map<std::string, std::string> stats;
        
        if (impl_) {
            stats["model_path"] = model_path_;
            stats["device"] = device_;
            stats["threads"] = std::to_string(threads_);
            stats["is_initialized"] = is_initialized_ ? "true" : "false";
            
            auto model_stats = impl_->GetStats();
            stats["memory_used_mb"] = std::to_string(model_stats.memory_used_mb);
            stats["tokens_processed"] = std::to_string(model_stats.tokens_processed);
        }
        
        return stats;
    }

private:
    std::unique_ptr<CustomModelImpl> impl_;
    std::string model_path_;
    std::string device_;
    int threads_ = 4;
    bool is_initialized_ = false;
    std::string last_error_;

    int CountTokens(const std::string& text) {
        // Simple token counting - replace with actual tokenizer
        int count = 0;
        bool in_token = false;
        for (char c : text) {
            if (std::isspace(c)) {
                if (in_token) {
                    count++;
                    in_token = false;
                }
            } else {
                in_token = true;
            }
        }
        if (in_token) count++;
        return count;
    }

    std::string EscapeJson(const std::string& str) {
        std::string escaped;
        for (char c : str) {
            switch (c) {
                case '"': escaped += "\\\""; break;
                case '\\': escaped += "\\\\"; break;
                case '\b': escaped += "\\b"; break;
                case '\f': escaped += "\\f"; break;
                case '\n': escaped += "\\n"; break;
                case '\r': escaped += "\\r"; break;
                case '\t': escaped += "\\t"; break;
                default: escaped += c; break;
            }
        }
        return escaped;
    }
};

// Stub implementation - replace with your actual model implementation
class CustomModelImpl {
public:
    struct Stats {
        size_t memory_used_mb = 0;
        size_t tokens_processed = 0;
    };

    bool Load(const std::string& path, const std::string& device, int threads) {
        // TODO: Implement actual model loading
        // This is where you'd load weights, initialize tensors, etc.
        return true;
    }

    void Unload() {
        // TODO: Implement cleanup
    }

    std::string Generate(const std::string& prompt, int max_tokens, 
                         float temperature, float top_p, int top_k) {
        // TODO: Implement actual generation
        // This is a stub that returns placeholder text
        return "This is a placeholder response from the custom model adapter. "
               "Replace this with actual inference code.";
    }

    std::string GenerateToken(const std::string& context, float temperature) {
        // TODO: Implement token-by-token generation
        return "token";
    }

    void ClearContext() {
        // TODO: Implement context clearing
    }

    Stats GetStats() {
        Stats stats;
        stats.memory_used_mb = 1024;  // Placeholder
        stats.tokens_processed = 100; // Placeholder
        return stats;
    }
};

// Plugin wrapper that provides the model backend
class MyModelAdapterPlugin : public RawrXD::Developer::IPlugin {
public:
    bool Initialize(const RawrXD::Developer::PluginContext& context) override {
        context.log_callback("INFO", "MyModelAdapter initialized");
        return true;
    }

    void Shutdown() override {
        // Cleanup
    }

    RawrXD::Developer::PluginManifest GetManifest() const override {
        return {
            "com.example.mymodeladapter",
            "My Custom Model Adapter",
            "1.0.0",
            "Custom model backend adapter for RawrXD",
            "Example Author",
            "MIT",
            "https://example.com",
            "https://github.com/example/mymodeladapter",
            RawrXD::Developer::PLUGIN_API_VERSION,
            {"1.0.0"},
            {RawrXD::Developer::PluginCapability::MODEL_PROVIDER}
        };
    }

    std::string GetStatus() const override {
        return "Active - Custom model backend ready";
    }

    std::vector<RawrXD::Developer::ModelBackendDefinition> GetModelBackends() override {
        return {
            {
                "mycustom",
                "My Custom Model Backend",
                {"custom", "onnx", "gguf"},  // Supported formats
                true,   // Supports GPU
                true,   // Supports quantization
                true,   // Supports streaming
                [](const std::string& path) {
                    // Check if this backend can handle the model
                    return path.ends_with(".custom") || 
                           path.ends_with(".onnx") || 
                           path.ends_with(".gguf");
                },
                [](const std::string& path) {
                    // Create backend instance
                    return std::make_unique<MyModelBackend>();
                }
            }
        };
    }
};

// Export the plugin
RAWRXD_DEFINE_PLUGIN(MyModelAdapterPlugin)
