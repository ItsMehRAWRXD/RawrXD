//=============================================================================
// RawrXD DAP Transport
// Handles Content-Length framing for stdin/stdout
// Zero external dependencies
//=============================================================================
#pragma once

#include <cstdio>
#include <string>


namespace RawrXD {
namespace DAP {

//=============================================================================
// Minimal JSON Writer (Zero Dependency)
//=============================================================================

class JSONWriter {
public:
    JSONWriter(char* buffer, size_t size) : m_buf(buffer), m_size(size), m_pos(0) {}
    
    void BeginObject() { Append("{"); m_first = true; }
    void EndObject() { Append("}"); }
    void BeginArray() { Append("["); m_first = true; }
    void EndArray() { Append("]"); }
    
    void Key(const char* key) {
        if (!m_first) Append(",");
        m_first = false;
        String(key);
        Append(":");
    }
    
    void Null() { Append("null"); }
    void Bool(bool val) { Append(val ? "true" : "false"); }
    void Int(int val) { AppendInt(val); }
    void Int64(int64_t val) { AppendInt64(val); }
    void UInt64(uint64_t val) { AppendUInt64(val); }
    void String(const char* val) { AppendString(val); }
    void String(const char* val, size_t len) { AppendString(val, len); }
    
    const char* GetString() const { return m_buf; }
    size_t GetLength() const { return m_pos; }
    
private:
    char* m_buf;
    size_t m_size;
    size_t m_pos;
    bool m_first = true;
    
    void Append(const char* s) {
        size_t len = strlen(s);
        if (m_pos + len < m_size) {
            memcpy(m_buf + m_pos, s, len);
            m_pos += len;
            m_buf[m_pos] = 0;
        }
    }
    
    void AppendChar(char c) {
        if (m_pos + 1 < m_size) {
            m_buf[m_pos++] = c;
            m_buf[m_pos] = 0;
        }
    }
    
    void AppendInt(int val) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%d", val);
        Append(tmp);
    }
    
    void AppendInt64(int64_t val) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%lld", val);
        Append(tmp);
    }
    
    void AppendUInt64(uint64_t val) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%llu", val);
        Append(tmp);
    }
    
    void AppendString(const char* s) {
        AppendChar('"');
        while (*s) {
            char c = *s++;
            switch (c) {
                case '"': Append("\\\""); break;
                case '\\': Append("\\\\"); break;
                case '\b': Append("\\b"); break;
                case '\f': Append("\\f"); break;
                case '\n': Append("\\n"); break;
                case '\r': Append("\\r"); break;
                case '\t': Append("\\t"); break;
                default:
                    if (c < 0x20) {
                        char tmp[8];
                        snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                        Append(tmp);
                    } else {
                        AppendChar(c);
                    }
            }
        }
        AppendChar('"');
    }
    
    void AppendString(const char* s, size_t len) {
        AppendChar('"');
        for (size_t i = 0; i < len && s[i]; i++) {
            char c = s[i];
            switch (c) {
                case '"': Append("\\\""); break;
                case '\\': Append("\\\\"); break;
                case '\b': Append("\\b"); break;
                case '\f': Append("\\f"); break;
                case '\n': Append("\\n"); break;
                case '\r': Append("\\r"); break;
                case '\t': Append("\\t"); break;
                default:
                    if (c < 0x20) {
                        char tmp[8];
                        snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                        Append(tmp);
                    } else {
                        AppendChar(c);
                    }
            }
        }
        AppendChar('"');
    }
};

//=============================================================================
// Minimal JSON Parser (Zero Dependency)
//=============================================================================

class JSONParser {
public:
    JSONParser(const char* json) : m_json(json), m_pos(0) {}
    
    // Simple key lookup - finds "key": value and returns value as string
    bool GetString(const char* key, char* out, size_t outSize) {
        const char* found = FindKey(key);
        if (!found) return false;
        
        SkipWhitespace();
        if (m_json[m_pos] != '"') return false;
        m_pos++; // skip opening quote
        
        size_t i = 0;
        while (m_json[m_pos] && m_json[m_pos] != '"' && i < outSize - 1) {
            if (m_json[m_pos] == '\\' && m_json[m_pos + 1]) {
                m_pos++;
                char c = m_json[m_pos++];
                switch (c) {
                    case '"': out[i++] = '"'; break;
                    case '\\': out[i++] = '\\'; break;
                    case 'b': out[i++] = '\b'; break;
                    case 'f': out[i++] = '\f'; break;
                    case 'n': out[i++] = '\n'; break;
                    case 'r': out[i++] = '\r'; break;
                    case 't': out[i++] = '\t'; break;
                    default: out[i++] = c; break;
                }
            } else {
                out[i++] = m_json[m_pos++];
            }
        }
        out[i] = 0;
        if (m_json[m_pos] == '"') m_pos++;
        return true;
    }
    
    bool GetInt(const char* key, int& out) {
        const char* found = FindKey(key);
        if (!found) return false;
        
        SkipWhitespace();
        char* end;
        out = strtol(m_json + m_pos, &end, 10);
        if (end == m_json + m_pos) return false;
        m_pos = end - m_json;
        return true;
    }
    
    bool GetBool(const char* key, bool& out) {
        const char* found = FindKey(key);
        if (!found) return false;
        
        SkipWhitespace();
        if (strncmp(m_json + m_pos, "true", 4) == 0) {
            out = true;
            m_pos += 4;
            return true;
        }
        if (strncmp(m_json + m_pos, "false", 5) == 0) {
            out = false;
            m_pos += 5;
            return true;
        }
        return false;
    }
    
    const char* GetCommand() {
        return GetValue("command");
    }
    
    int GetSeq() {
        int seq = 0;
        GetInt("seq", seq);
        return seq;
    }
    
private:
    const char* m_json;
    size_t m_pos;
    
    void SkipWhitespace() {
        while (m_json[m_pos] && (m_json[m_pos] == ' ' || m_json[m_pos] == '\t' || 
                                  m_json[m_pos] == '\n' || m_json[m_pos] == '\r')) {
            m_pos++;
        }
    }
    
    const char* FindKey(const char* key) {
        size_t keyLen = strlen(key);
        const char* p = m_json;
        while (*p) {
            if (*p == '"') {
                p++;
                if (strncmp(p, key, keyLen) == 0 && p[keyLen] == '"') {
                    p += keyLen + 1;
                    SkipWhitespace();
                    if (*p == ':') {
                        p++;
                        m_pos = p - m_json;
                        return p;
                    }
                }
            }
            p++;
        }
        return nullptr;
    }
    
    const char* GetValue(const char* key) {
        static char buffer[256];
        if (GetString(key, buffer, sizeof(buffer))) {
            return buffer;
        }
        return nullptr;
    }
};

//=============================================================================
// DAP Transport
//=============================================================================

class DAPTransport {
public:
    DAPTransport() = default;
    
    // Read a complete DAP message from stdin
    // Returns true if message read successfully
    bool ReadMessage(char* buffer, size_t bufferSize, size_t& outLen) {
        char header[256];
        
        // Read header line
        if (!fgets(header, sizeof(header), stdin)) {
            return false;
        }
        
        // Parse Content-Length
        size_t contentLen = 0;
        if (sscanf(header, "Content-Length: %zu", &contentLen) != 1) {
            // Try to read another header line (might be blank line first)
            if (!fgets(header, sizeof(header), stdin)) return false;
            if (sscanf(header, "Content-Length: %zu", &contentLen) != 1) {
                return false;
            }
        }
        
        // Skip blank line
        if (!fgets(header, sizeof(header), stdin)) return false;
        
        // Read JSON payload
        if (contentLen >= bufferSize) {
            contentLen = bufferSize - 1;
        }
        
        size_t totalRead = 0;
        while (totalRead < contentLen) {
            size_t read = fread(buffer + totalRead, 1, contentLen - totalRead, stdin);
            if (read == 0) break;
            totalRead += read;
        }
        
        buffer[totalRead] = 0;
        outLen = totalRead;
        return totalRead > 0;
    }
    
    // Write a DAP message to stdout
    void WriteMessage(const char* json, size_t len) {
        printf("Content-Length: %zu\r\n\r\n", len);
        fwrite(json, 1, len, stdout);
        fflush(stdout);
    }
    
    void WriteMessage(const char* json) {
        WriteMessage(json, strlen(json));
    }
};

} // namespace DAP
} // namespace RawrXD
