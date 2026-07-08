#ifndef RAWRXD_CORE_GGUF_PARSER_H
#define RAWRXD_CORE_GGUF_PARSER_H
#include "core_export.h"
#include <memory>
namespace RawrXD { namespace Core {
class RAWRXD_CORE_EXPORT GGUFParser {
public:
    GGUFParser();
    ~GGUFParser();
    GGUFParser(const GGUFParser&) = delete;
    GGUFParser& operator=(const GGUFParser&) = delete;
    GGUFParser(GGUFParser&&) noexcept;
    GGUFParser& operator=(GGUFParser&&) noexcept;
    bool Parse(const char* path);
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};
}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_GGUF_PARSER_H
