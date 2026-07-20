// HotPatcher.cpp
// Production live binary patching implementation

#include "HotPatcher.hpp"
#include <chrono>

namespace Sovereign {

PatchResult HotPatcher::Apply(const PatchRequest& request) {
    // Validate input
    if (request.address == 0) {
        return { false, request.address, "INVALID_ADDRESS" };
    }
    if (request.replacement.empty()) {
        return { false, request.address, "EMPTY_REPLACEMENT" };
    }
    if (!request.expected.empty() && request.expected.size() != request.replacement.size()) {
        return { false, request.address, "SIZE_MISMATCH" };
    }

    // Check if patch already exists at this address
    {
        std::lock_guard<std::mutex> lock(transactionLock);
        if (transactions.find(request.address) != transactions.end()) {
            return { false, request.address, "PATCH_ALREADY_EXISTS" };
        }
    }

    // Validate current bytes match expected (if provided)
    if (!request.expected.empty()) {
        if (!ValidateBytes(request.address, request.expected)) {
            return { false, request.address, "BYTE_VALIDATION_FAILED" };
        }
    }

    // Read original bytes for rollback
    std::vector<uint8_t> originalBytes(request.replacement.size());
    if (!ReadBytes(request.address, request.replacement.size(), originalBytes.data())) {
        return { false, request.address, "READ_ORIGINAL_FAILED" };
    }

    // Apply the patch
    DWORD oldProtection;
    if (!WriteBytes(request.address, request.replacement, oldProtection)) {
        return { false, request.address, "WRITE_FAILED" };
    }

    // Invalidate instruction cache (CRITICAL for CPU to see new instructions)
    InvalidateCache(request.address, request.replacement.size());

    // Store transaction for rollback
    {
        std::lock_guard<std::mutex> lock(transactionLock);
        PatchTransaction tx;
        tx.address = request.address;
        tx.original = std::move(originalBytes);
        tx.replacement = request.replacement;
        tx.oldProtection = oldProtection;
        tx.committed = true;
        tx.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        transactions[request.address] = std::move(tx);
    }

    return { true, request.address, "HOT_PATCH_APPLIED" };
}

PatchResult HotPatcher::Rollback(const PatchRequest& request) {
    std::lock_guard<std::mutex> lock(transactionLock);

    auto it = transactions.find(request.address);
    if (it == transactions.end()) {
        return { false, request.address, "NO_PATCH_TO_ROLLBACK" };
    }

    const auto& tx = it->second;

    // Restore original bytes
    DWORD tempProtection;
    if (!WriteBytes(request.address, tx.original, tempProtection)) {
        return { false, request.address, "ROLLBACK_WRITE_FAILED" };
    }

    // Invalidate cache
    InvalidateCache(request.address, tx.original.size());

    // Restore original protection
    RestoreProtection(request.address, tx.original.size(), tx.oldProtection);

    // Remove transaction
    transactions.erase(it);

    return { true, request.address, "HOT_PATCH_ROLLED_BACK" };
}

bool HotPatcher::HasPatchAt(uintptr_t address) const {
    std::lock_guard<std::mutex> lock(transactionLock);
    return transactions.find(address) != transactions.end();
}

const PatchTransaction* HotPatcher::GetTransaction(uintptr_t address) const {
    std::lock_guard<std::mutex> lock(transactionLock);
    auto it = transactions.find(address);
    if (it != transactions.end()) {
        return &it->second;
    }
    return nullptr;
}

size_t HotPatcher::RollbackAll() {
    // Create a copy of addresses first (under lock)
    std::vector<uintptr_t> addresses;
    {
        std::lock_guard<std::mutex> lock(transactionLock);
        addresses.reserve(transactions.size());
        for (const auto& pair : transactions) {
            addresses.push_back(pair.first);
        }
    }

    // Rollback each patch (without holding lock - Rollback acquires its own lock)
    size_t count = 0;
    for (uintptr_t addr : addresses) {
        PatchRequest req;
        req.address = addr;
        Rollback(req);
        count++;
    }

    return count;
}

size_t HotPatcher::GetActivePatchCount() const {
    std::lock_guard<std::mutex> lock(transactionLock);
    return transactions.size();
}

bool HotPatcher::ValidateBytes(uintptr_t address, const std::vector<uint8_t>& expected) {
    std::vector<uint8_t> actual(expected.size());
    if (!ReadBytes(address, expected.size(), actual.data())) {
        return false;
    }
    return (actual == expected);
}

bool HotPatcher::ReadBytes(uintptr_t address, size_t size, uint8_t* outBuffer) {
    SIZE_T bytesRead = 0;
    BOOL result = ReadProcessMemory(
        process,
        reinterpret_cast<LPCVOID>(address),
        outBuffer,
        size,
        &bytesRead
    );
    return (result && bytesRead == size);
}

bool HotPatcher::WriteBytes(uintptr_t address, const std::vector<uint8_t>& bytes, DWORD& oldProtection) {
    // Escalate protection to allow writing to executable pages
    DWORD newProtection = PAGE_EXECUTE_READWRITE;
    BOOL vpResult = VirtualProtectEx(
        process,
        reinterpret_cast<LPVOID>(address),
        bytes.size(),
        newProtection,
        &oldProtection
    );

    if (!vpResult) {
        return false;
    }

    // Write the patch bytes
    SIZE_T bytesWritten = 0;
    BOOL writeResult = WriteProcessMemory(
        process,
        reinterpret_cast<LPVOID>(address),
        bytes.data(),
        bytes.size(),
        &bytesWritten
    );

    if (!writeResult || bytesWritten != bytes.size()) {
        // Attempt to restore protection on failure
        DWORD temp;
        VirtualProtectEx(process, reinterpret_cast<LPVOID>(address), bytes.size(), oldProtection, &temp);
        return false;
    }

    return true;
}

bool HotPatcher::RestoreProtection(uintptr_t address, size_t size, DWORD protection) {
    DWORD temp;
    return VirtualProtectEx(
        process,
        reinterpret_cast<LPVOID>(address),
        size,
        protection,
        &temp
    );
}

void HotPatcher::InvalidateCache(uintptr_t address, size_t size) {
    FlushInstructionCache(process, reinterpret_cast<LPCVOID>(address), size);
}

} // namespace Sovereign
