// Model-free POSIX child-process acceptance for the production extension I/O helpers.
// This tests pipe transport, EOF, and process reaping, not the Win32 launcher.
#include "../~dev/rawrxd/src/core/extension_read_policy.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <algorithm>
#include <iostream>
#include <string>
using namespace rawrxd::extensions;
int main() {
    int fd[2];
    if (pipe(fd) != 0) return 2;
    const std::string payload = "MOCK_AGENT|request=B|result=ok";
    const pid_t child = fork();
    if (child < 0) { close(fd[0]); close(fd[1]); return 3; }
    if (child == 0) {
        close(fd[0]);
        const bool sent = writeExactly(payload.data(), payload.size(),
            [&](const char* p, std::size_t n) -> std::size_t {
                const auto k = write(fd[1], p, std::min<std::size_t>(n, 2));
                return k > 0 ? static_cast<std::size_t>(k) : 0;
            });
        close(fd[1]);
        _exit(sent ? 0 : 4);
    }
    close(fd[1]);
    std::string output(payload.size(), '\0');
    const bool got = readExactly(output.data(), output.size(),
        [&](char* p, std::size_t n) -> std::size_t {
            const auto k = read(fd[0], p, std::min<std::size_t>(n, 3));
            return k > 0 ? static_cast<std::size_t>(k) : 0;
        });
    char extra = 0;
    const bool eof = !readExactly(&extra, 1,
        [&](char* p, std::size_t n) -> std::size_t {
            const auto k = read(fd[0], p, n);
            return k > 0 ? static_cast<std::size_t>(k) : 0;
        });
    close(fd[0]);
    int status = 0;
    const bool reaped = waitpid(child, &status, 0) == child;
    const bool childOk = reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    std::cout << "SUBPROCESS_POLICY_GATE payload=" << (got && output == payload ? "PASS" : "FAIL")
              << " eof=" << (eof ? "PASS" : "FAIL")
              << " exit=" << (childOk ? "PASS" : "FAIL") << '\n';
    return got && output == payload && eof && childOk ? 0 : 1;
}
