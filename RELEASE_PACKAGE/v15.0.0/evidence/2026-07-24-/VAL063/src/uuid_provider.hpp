#pragma once

#include "execution_types.hpp"
#include <optional>

namespace val063 {

// UUID v4 generation (random-based)
// Provides cryptographically secure random UUIDs for execution correlation
class UuidProvider {
public:
    UuidProvider();
    ~UuidProvider();

    UuidProvider(const UuidProvider&) = delete;
    UuidProvider& operator=(const UuidProvider&) = delete;

    // Generate new random UUID v4
    ExecutionId generate();

    // Parse UUID from string
    static std::optional<ExecutionId> parse(std::string_view str);

    // Convert UUID to standard string format
    static std::string to_string(const ExecutionId& id);

    // Validate UUID format
    static bool is_valid(std::string_view str);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Convenience functions
namespace uuid {
    // Generate new UUID
    ExecutionId generate();
    
    // Parse from string
    std::optional<ExecutionId> parse(std::string_view str);
    
    // Convert to string
    std::string to_string(const ExecutionId& id);
}

} // namespace val063
