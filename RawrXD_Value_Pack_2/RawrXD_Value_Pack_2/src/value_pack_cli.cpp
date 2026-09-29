#include "rawrxd/value/command_center.hpp"
#include "rawrxd/value/lifecycle_bus.hpp"
#ifdef _WIN32
#include "rawrxd/value/browser_authority.hpp"
#endif

#include <filesystem>
#include <iostream>
#include <string>

using namespace rawrxd::value;

static int coreSelfTest(const std::filesystem::path& outdir) {
    std::filesystem::create_directories(outdir);
    LifecycleBus bus((outdir / "lifecycle.tsv").string());
    CommandCenter cc(bus, (outdir / "command_center.tsv").string());

    std::size_t observed = 0;
    const auto sub = bus.subscribe([&](const LifecycleEvent&) { ++observed; });

    bool ok = true;
    ok &= cc.createTask("selftest-1", "Implement and validate value pack", "Deep2");
    ok &= cc.transition("selftest-1", TaskState::Running, "inference-start");
    ok &= cc.addChangedFile("selftest-1", "src/example.cpp");
    ok &= cc.transition("selftest-1", TaskState::Validating, "build-start");
    ok &= cc.setValidation("selftest-1", "PASS");
    ok &= cc.transition("selftest-1", TaskState::MergeReady, "merge-authorized");
    ok &= cc.setMerge("selftest-1", "PASS");
    ok &= cc.transition("selftest-1", TaskState::Pass, "complete");
    bus.unsubscribe(sub);

    const auto task = cc.get("selftest-1");
    ok &= task.has_value() && task->state == TaskState::Pass && task->changed_files.size() == 1;
    ok &= observed >= 6;
    ok &= std::filesystem::exists(outdir / "lifecycle.tsv");
    ok &= std::filesystem::exists(outdir / "command_center.tsv");

    std::cout << "GATE=RAWRXD_VALUE_PACK2_CORE_001\n";
    std::cout << "TASK_STATE=" << (task ? CommandCenter::toString(task->state) : "MISSING") << "\n";
    std::cout << "LIFECYCLE_EVENTS=" << observed << "\n";
    std::cout << "RECEIPT_EXISTS=" << (std::filesystem::exists(outdir / "command_center.tsv") ? 1 : 0) << "\n";
    std::cout << "VERDICT=" << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
}

#ifdef _WIN32
static int browserSelfTest(const std::filesystem::path& outdir, const std::string& url) {
    std::filesystem::create_directories(outdir);
    BrowserAuthority browser;
    bool ok = browser.launch(9222, true);
    if (!ok) {
        std::cout << "GATE=RAWRXD_BROWSER_AUTHORITY_001\nLAUNCH=FAIL\nVERDICT=FAIL\n";
        return 2;
    }
    auto nav = browser.navigate(url);
    auto title = browser.evaluate("document.title");
    auto shot = browser.screenshot((outdir / "browser.png").string());
    const auto network = browser.takeNetworkFailures();
    const auto console = browser.takeConsoleEvents();
    ok = nav.ok && title.ok && shot.ok;
    std::cout << "GATE=RAWRXD_BROWSER_AUTHORITY_001\n";
    std::cout << "LAUNCH=PASS\n";
    std::cout << "NAVIGATE=" << (nav.ok ? "PASS" : "FAIL") << "\n";
    std::cout << "TITLE_READ=" << (title.ok ? "PASS" : "FAIL") << "\n";
    std::cout << "SCREENSHOT=" << (shot.ok ? "PASS" : "FAIL") << "\n";
    std::cout << "CONSOLE_EVENTS=" << console.size() << "\n";
    std::cout << "NETWORK_FAILURES=" << network.size() << "\n";
    std::cout << "VERDICT=" << (ok ? "PASS" : "FAIL") << "\n";
    if (!ok) {
        if (!nav.ok) std::cerr << "navigate: " << nav.error << '\n';
        if (!title.ok) std::cerr << "title: " << title.error << '\n';
        if (!shot.ok) std::cerr << "screenshot: " << shot.error << '\n';
    }
    return ok ? 0 : 3;
}
#endif

int main(int argc, char** argv) {
    const std::filesystem::path outdir = argc >= 3 ? argv[2] : "rawrxd_value_receipts";
    if (argc < 2 || std::string(argv[1]) == "selftest") return coreSelfTest(outdir);
#ifdef _WIN32
    if (std::string(argv[1]) == "browser-selftest") {
        const std::string url = argc >= 4 ? argv[3] : "https://example.com";
        return browserSelfTest(outdir, url);
    }
#endif
    std::cerr << "usage: rawrxd-value-pack2 selftest [outdir]";
#ifdef _WIN32
    std::cerr << " | browser-selftest [outdir] [url]";
#endif
    std::cerr << '\n';
    return 64;
}
