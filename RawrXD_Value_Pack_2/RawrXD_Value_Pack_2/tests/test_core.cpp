#include "rawrxd/value/command_center.hpp"
#include "rawrxd/value/lifecycle_bus.hpp"

#include <cassert>
#include <filesystem>
#include <iostream>

int main() {
    using namespace rawrxd::value;
    const auto root = std::filesystem::temp_directory_path() / "rawrxd_value_pack2_test";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root, ec);

    LifecycleBus bus((root / "life.tsv").string());
    CommandCenter center(bus, (root / "tasks.tsv").string());
    std::size_t events = 0;
    auto sub = bus.subscribe([&](const LifecycleEvent&) { ++events; });

    assert(center.createTask("t1", "test", "local-model"));
    assert(!center.createTask("t1", "duplicate", "local-model"));
    assert(center.transition("t1", TaskState::Running));
    assert(center.addChangedFile("t1", "a.cpp"));
    assert(center.addChangedFile("t1", "a.cpp"));
    assert(center.transition("t1", TaskState::Validating));
    assert(center.setValidation("t1", "PASS"));
    assert(center.transition("t1", TaskState::MergeReady));
    assert(center.setMerge("t1", "PASS"));
    assert(center.transition("t1", TaskState::Pass));
    assert(!center.transition("t1", TaskState::Running));

    auto record = center.get("t1");
    assert(record.has_value());
    assert(record->state == TaskState::Pass);
    assert(record->changed_files.size() == 1);
    assert(events >= 6);
    assert(std::filesystem::file_size(root / "life.tsv") > 0);
    assert(std::filesystem::file_size(root / "tasks.tsv") > 0);
    bus.unsubscribe(sub);

    std::cout << "GATE=RAWRXD_VALUE_PACK2_TEST_001\nVERDICT=PASS\n";
    return 0;
}
