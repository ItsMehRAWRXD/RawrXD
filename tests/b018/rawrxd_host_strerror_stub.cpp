// Minimal stub for rawrxd_host_strerror — avoids linking full rawrxd_host.cpp
// which pulls in C++20 headers incompatible with -std=c++17
#include "rawrxd_host.hpp"

extern "C" const char* rawrxd_host_strerror(int error_code)
{
    switch (error_code) {
        case RAWRXD_OK:                    return "OK";
        case RAWRXD_ERR_INVALID_PARAM:     return "Invalid parameter";
        case RAWRXD_ERR_OUT_OF_MEMORY:     return "Out of memory";
        case RAWRXD_ERR_MODEL_NOT_FOUND:   return "Model not found";
        case RAWRXD_ERR_ENGINE_INIT:       return "Engine initialization failed";
        case RAWRXD_ERR_INFERENCE:         return "Inference failed";
        case RAWRXD_ERR_NOT_IMPLEMENTED:   return "Not implemented";
        case RAWRXD_ERR_PIPE_IO:           return "Pipe I/O error";
        case RAWRXD_ERR_PROTOCOL:          return "Protocol error";
        default:                           return "Unknown error";
    }
}
