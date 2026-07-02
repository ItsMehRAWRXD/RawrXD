// Stub json/json.h for RawrXD build
// Minimal implementation to satisfy AdapterRegistry compilation

#pragma once

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <memory>

namespace Json {

using UInt64 = unsigned long long;
using Int64 = long long;

// Forward declarations for compatibility
class Value;

// Global constants for Json::Value types (must be defined in header for inline)
namespace {
    // Anonymous namespace for internal linkage
    constexpr int _nullType = 0;
    constexpr int _intType = 1;
    constexpr int _uintType = 2;
    constexpr int _realType = 3;
    constexpr int _stringType = 4;
    constexpr int _booleanType = 5;
    constexpr int _arrayType = 6;
    constexpr int _objectType = 7;
}

class Value {
public:
    enum Type {
        nullType = _nullType,
        intType = _intType,
        uintType = _uintType,
        realType = _realType,
        stringType = _stringType,
        booleanType = _booleanType,
        arrayType = _arrayType,
        objectType = _objectType
    };

    // Static constants for compatibility - these reference the enum values
    static constexpr Type nullValue = nullType;
    static constexpr Type intValue = intType;
    static constexpr Type uintValue = uintType;
    static constexpr Type realValue = realType;
    static constexpr Type stringValue = stringType;
    static constexpr Type booleanValue = booleanType;
    static constexpr Type arrayValue = arrayType;
    static constexpr Type objectValue = objectType;

    Value() : type_(nullType) {}
    explicit Value(Type type) : type_(type) {}
    Value(const char* value) : type_(stringType), stringValue_(value ? value : "") {}
    Value(const std::string& value) : type_(stringType), stringValue_(value) {}
    Value(int value) : type_(intType), intValue_(value) {}
    Value(unsigned int value) : type_(uintType), uintValue_(value) {}
    Value(UInt64 value) : type_(uintType), uintValue_(static_cast<unsigned int>(value)) {}
    Value(double value) : type_(realType), realValue_(value) {}
    Value(bool value) : type_(booleanType), boolValue_(value) {}

    // Assignment operators
    Value& operator=(const Value& other) {
        if (this != &other) {
            type_ = other.type_;
            stringValue_ = other.stringValue_;
            intValue_ = other.intValue_;
            uintValue_ = other.uintValue_;
            realValue_ = other.realValue_;
            boolValue_ = other.boolValue_;
            arrayValue_ = other.arrayValue_;
            objectValue_ = other.objectValue_;
        }
        return *this;
    }

    // Subscript operators
    Value& operator[](const char* key) {
        if (type_ != objectType) {
            type_ = objectType;
            objectValue_.clear();
        }
        return objectValue_[key];
    }

    Value& operator[](const std::string& key) {
        return (*this)[key.c_str()];
    }

    Value& operator[](unsigned int index) {
        if (type_ != arrayType) {
            type_ = arrayType;
            arrayValue_.clear();
        }
        if (index >= arrayValue_.size()) {
            arrayValue_.resize(index + 1);
        }
        return arrayValue_[index];
    }

    // Append for arrays
    void append(const Value& value) {
        if (type_ != arrayType) {
            type_ = arrayType;
            arrayValue_.clear();
        }
        arrayValue_.push_back(value);
    }

    // Getters
    std::string asString() const {
        switch (type_) {
            case stringType: return stringValue_;
            case intType: return std::to_string(intValue_);
            case uintType: return std::to_string(uintValue_);
            case realType: return std::to_string(realValue_);
            case booleanType: return boolValue_ ? "true" : "false";
            default: return "";
        }
    }

    int asInt() const {
        switch (type_) {
            case intType: return intValue_;
            case uintType: return static_cast<int>(uintValue_);
            case realType: return static_cast<int>(realValue_);
            default: return 0;
        }
    }

    unsigned int asUInt() const {
        switch (type_) {
            case uintType: return uintValue_;
            case intType: return static_cast<unsigned int>(intValue_);
            default: return 0;
        }
    }

    UInt64 asUInt64() const {
        switch (type_) {
            case uintType: return uintValue_;
            case intType: return static_cast<UInt64>(intValue_);
            default: return 0;
        }
    }

    double asDouble() const {
        switch (type_) {
            case realType: return realValue_;
            case intType: return static_cast<double>(intValue_);
            case uintType: return static_cast<double>(uintValue_);
            default: return 0.0;
        }
    }

    // asFloat compatibility alias
    float asFloat() const {
        return static_cast<float>(asDouble());
    }

    bool asBool() const {
        return type_ == booleanType ? boolValue_ : false;
    }

    // Type checks
    bool isNull() const { return type_ == nullType; }
    bool isString() const { return type_ == stringType; }
    bool isInt() const { return type_ == intType; }
    bool isUInt() const { return type_ == uintType; }
    bool isDouble() const { return type_ == realType; }
    bool isBool() const { return type_ == booleanType; }
    bool isArray() const { return type_ == arrayType; }
    bool isObject() const { return type_ == objectType; }

    // Size
    size_t size() const {
        if (type_ == arrayType) return arrayValue_.size();
        if (type_ == objectType) return objectValue_.size();
        return 0;
    }

    // Iteration for arrays
    using iterator = std::vector<Value>::iterator;
    using const_iterator = std::vector<Value>::const_iterator;

    iterator begin() {
        static std::vector<Value> empty;
        return type_ == arrayType ? arrayValue_.begin() : empty.begin();
    }

    iterator end() {
        static std::vector<Value> empty;
        return type_ == arrayType ? arrayValue_.end() : empty.end();
    }

    const_iterator begin() const {
        static std::vector<Value> empty;
        return type_ == arrayType ? arrayValue_.begin() : empty.begin();
    }

    const_iterator end() const {
        static std::vector<Value> empty;
        return type_ == arrayType ? arrayValue_.end() : empty.end();
    }

    // Get with default value (JsonCpp compatibility)
    Value get(const char* key, const Value& defaultValue) const {
        if (type_ != objectType) return defaultValue;
        auto it = objectValue_.find(key);
        return (it != objectValue_.end()) ? it->second : defaultValue;
    }

    Value get(const std::string& key, const Value& defaultValue) const {
        return get(key.c_str(), defaultValue);
    }

private:
    Type type_;
    std::string stringValue_;
    int intValue_ = 0;
    unsigned int uintValue_ = 0;
    double realValue_ = 0.0;
    bool boolValue_ = false;
    std::vector<Value> arrayValue_;
    std::map<std::string, Value> objectValue_;
};

// Stream output
inline std::ostream& operator<<(std::ostream& os, const Value& value) {
    os << value.asString();
    return os;
}

// Reader class
class Reader {
public:
    bool parse(const std::string& document, Value& root) {
        (void)document;
        (void)root;
        return false;  // Stub: always fails
    }

    bool parse(const char* beginDoc, const char* endDoc, Value& root) {
        (void)beginDoc;
        (void)endDoc;
        (void)root;
        return false;
    }

    std::string getFormattedErrorMessages() const {
        return "JSON parsing not implemented in stub";
    }
};

// Writer classes
class FastWriter {
public:
    std::string write(const Value& root) {
        return root.asString();
    }
};

class StyledWriter {
public:
    std::string write(const Value& root) {
        return root.asString();
    }
};

// StreamWriterBuilder for JsonCpp compatibility
class StreamWriterBuilder {
public:
    // Settings (ignored in stub)
    void setIndent(const std::string& indent) { (void)indent; }
    
    // Build and write
    static std::string writeString(const StreamWriterBuilder& builder, const Value& root) {
        (void)builder;
        return root.asString();
    }
};

// CharReaderBuilder for JsonCpp compatibility
class CharReaderBuilder {
public:
    // Settings (ignored in stub)
    void setStrictMode(bool strict) { (void)strict; }
    
    // Build reader
    std::unique_ptr<Reader> newCharReader() const {
        return std::make_unique<Reader>();
    }
};

// parseFromStream for JsonCpp compatibility
inline bool parseFromStream(const CharReaderBuilder& builder, std::istream& sin, Value* root, std::string* errs) {
    (void)builder;
    (void)sin;
    (void)root;
    if (errs) *errs = "JSON parsing not implemented in stub";
    return false;
}

// writeString helper
inline std::string writeString(const StreamWriterBuilder& builder, const Value& root) {
    return StreamWriterBuilder::writeString(builder, root);
}

} // namespace Json