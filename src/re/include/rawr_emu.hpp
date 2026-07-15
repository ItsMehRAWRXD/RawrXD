/**
 * @file rawr_emu.hpp
 * @brief Multi-Architecture Emulator Interface
 * @description High-level C++ wrapper around Unicorn engine for emulating
 *              all supported architectures. No stubs - full implementation.
 * 
 * @version 1.0.0
 */

#pragma once

#include "rawr_arch.hpp"

// Conditionally include Unicorn
#ifdef HAS_UNICORN
#include <unicorn/unicorn.h>
#endif

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <map>

namespace RawrXD {
namespace RE {

/**
 * @brief Memory region permissions
 */
enum class MemPermission : uint32_t {
    NONE = 0,
    READ = UC_PROT_READ,
    WRITE = UC_PROT_WRITE,
    EXEC = UC_PROT_EXEC,
    READ_WRITE = UC_PROT_READ | UC_PROT_WRITE,
    READ_EXEC = UC_PROT_READ | UC_PROT_EXEC,
    ALL = UC_PROT_ALL
};

/**
 * @brief Hook types for emulation
 */
enum class HookType : uint32_t {
    CODE = UC_HOOK_CODE,           ///< Hook on every instruction
    BLOCK = UC_HOOK_BLOCK,         ///< Hook on basic block
    MEM_READ = UC_HOOK_MEM_READ,   ///< Hook on memory read
    MEM_WRITE = UC_HOOK_MEM_WRITE, ///< Hook on memory write
    MEM_FETCH = UC_HOOK_MEM_FETCH, ///< Hook on memory fetch
    MEM_ACCESS = UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, ///< Hook on any memory access
    INTR = UC_HOOK_INTR,           ///< Hook on interrupt
    INSN = UC_HOOK_INSN,           ///< Hook on specific instruction
    EDGE = UC_HOOK_EDGE            ///< Hook on edge generation
};

/**
 * @brief Emulation result
 */
struct EmuResult {
    bool success;
    uint64_t exitAddress;
    uint64_t instructionCount;
    std::string errorMessage;
    
    EmuResult() : success(false), exitAddress(0), instructionCount(0) {}
};

/**
 * @brief Register information
 */
struct RegInfo {
    std::string name;
    uint32_t id;
    uint32_t size;  ///< Register size in bits
};

/**
 * @brief Emulator configuration
 */
struct EmuConfig {
    Architecture arch;
    ArchFeature features;
    uint64_t stackAddress;
    size_t stackSize;
    bool enableHooks;
    bool traceInstructions;
    
    EmuConfig()
        : arch(Architecture::X86_64)
        , features(ArchFeature::NONE)
        , stackAddress(0x7FFF0000)
        , stackSize(0x10000)
        , enableHooks(true)
        , traceInstructions(false) {}
};

/**
 * @brief Multi-architecture emulator class
 * 
 * This class provides a unified interface for emulating all supported
 * architectures using the Unicorn engine.
 */
class Emulator {
public:
    /**
     * @brief Constructor
     * @param config Emulator configuration
     */
    explicit Emulator(const EmuConfig& config = EmuConfig());
    
    /**
     * @brief Destructor
     */
    ~Emulator();
    
    /**
     * @brief Initialize emulator
     * @return true if successful
     */
    bool Initialize();
    
    /**
     * @brief Map memory region
     * @param address Base address
     * @param size Region size
     * @param perms Permissions
     * @return true if successful
     */
    bool MapMemory(uint64_t address, size_t size, MemPermission perms);
    
    /**
     * @brief Unmap memory region
     * @param address Base address
     * @param size Region size
     * @return true if successful
     */
    bool UnmapMemory(uint64_t address, size_t size);
    
    /**
     * @brief Write memory
     * @param address Target address
     * @param data Data to write
     * @param size Size in bytes
     * @return true if successful
     */
    bool WriteMemory(uint64_t address, const void* data, size_t size);
    
    /**
     * @brief Read memory
     * @param address Source address
     * @param data Buffer to read into
     * @param size Size in bytes
     * @return true if successful
     */
    bool ReadMemory(uint64_t address, void* data, size_t size);
    
    /**
     * @brief Write register
     * @param regId Register ID
     * @param value Value to write
     * @return true if successful
     */
    bool WriteRegister(uint32_t regId, uint64_t value);
    
    /**
     * @brief Read register
     * @param regId Register ID
     * @param value Output value
     * @return true if successful
     */
    bool ReadRegister(uint32_t regId, uint64_t& value);
    
    /**
     * @brief Set instruction pointer
     * @param address New IP/PC value
     * @return true if successful
     */
    bool SetInstructionPointer(uint64_t address);
    
    /**
     * @brief Get instruction pointer
     * @param address Output IP/PC value
     * @return true if successful
     */
    bool GetInstructionPointer(uint64_t& address);
    
    /**
     * @brief Set stack pointer
     * @param address New SP value
     * @return true if successful
     */
    bool SetStackPointer(uint64_t address);
    
    /**
     * @brief Get stack pointer
     * @param address Output SP value
     * @return true if successful
     */
    bool GetStackPointer(uint64_t& address);
    
    /**
     * @brief Start emulation
     * @param begin Start address
     * @param until End address (0 = no limit)
     * @param timeout Timeout in microseconds (0 = no timeout)
     * @param count Max instructions (0 = unlimited)
     * @return Emulation result
     */
    EmuResult Emulate(uint64_t begin, uint64_t until = 0, 
                      uint64_t timeout = 0, size_t count = 0);
    
    /**
     * @brief Stop emulation
     */
    void Stop();
    
    /**
     * @brief Add code hook
     * @param callback Hook callback function
     * @param userData User data pointer
     * @return Hook handle
     */
#ifdef HAS_UNICORN
    uc_hook AddCodeHook(std::function<void(uint64_t, uint32_t)> callback, void* userData = nullptr);
#else
    void* AddCodeHook(std::function<void(uint64_t, uint32_t)> callback, void* userData = nullptr);
#endif
    
    /**
     * @brief Add memory hook
     * @param type Hook type (read/write/access)
     * @param callback Hook callback function
     * @param userData User data pointer
     * @return Hook handle
     */
#ifdef HAS_UNICORN
    uc_hook AddMemHook(HookType type, 
                       std::function<void(uint64_t, size_t, uint64_t)> callback,
                       void* userData = nullptr);
#else
    void* AddMemHook(HookType type,
                       std::function<void(uint64_t, size_t, uint64_t)> callback,
                       void* userData = nullptr);
#endif
    
    /**
     * @brief Remove hook
     * @param hh Hook handle
     * @return true if successful
     */
#ifdef HAS_UNICORN
    bool RemoveHook(uc_hook hh);
#else
    bool RemoveHook(void* hh);
#endif
    
    /**
     * @brief Check if emulator is valid/initialized
     * @return true if ready to use
     */
    bool IsValid() const { return m_handle != nullptr; }
    
    /**
     * @brief Get last error message
     * @return Error string
     */
    std::string GetLastError() const;
    
    /**
     * @brief Get current configuration
     * @return Configuration reference
     */
    const EmuConfig& GetConfig() const { return m_config; }
    
    /**
     * @brief Get register list for current architecture
     * @return Vector of register info
     */
    std::vector<RegInfo> GetRegisters() const;
    
    /**
     * @brief Get register ID by name
     * @param name Register name
     * @return Register ID or -1 if not found
     */
    int GetRegisterId(const std::string& name) const;

private:
#ifdef HAS_UNICORN
    uc_engine* m_handle;        ///< Unicorn handle
    uc_err m_lastError;         ///< Last error code
    std::map<uc_hook, std::function<void()>> m_hooks; ///< Hook callbacks
#else
    void* m_handle;             ///< Opaque handle (not used without Unicorn)
    int m_lastError;              ///< Last error code
    std::map<void*, std::function<void()>> m_hooks; ///< Hook callbacks
#endif
    EmuConfig m_config;         ///< Current configuration

    /**
     * @brief Setup stack
     * @return true if successful
     */
    bool SetupStack();

    /**
     * @brief Get register ID for stack pointer
     * @return Register ID
     */
    uint32_t GetStackPointerRegId() const;

    /**
     * @brief Get register ID for instruction pointer
     * @return Register ID
     */
    uint32_t GetInstructionPointerRegId() const;
};

/**
 * @brief Quick emulate function (stateless)
 * @param arch Architecture to emulate
 * @param code Machine code to emulate
 * @param codeSize Code size
 * @param baseAddress Base address
 * @param maxInstructions Max instructions to execute
 * @return Emulation result
 */
EmuResult QuickEmulate(
    Architecture arch,
    const uint8_t* code,
    size_t codeSize,
    uint64_t baseAddress = 0x1000,
    size_t maxInstructions = 1000
);

} // namespace RE
} // namespace RawrXD
