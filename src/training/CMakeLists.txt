# RawrXD Training Module CMakeLists.txt

cmake_minimum_required(VERSION 3.20)

# Training library
add_library(rawrxd_training STATIC
    fine_tuner.cpp
    lora_adapter.cpp
    checkpoint_manager.cpp
    data/dataset_loader.cpp
    data/data_collator.cpp
)

target_include_directories(rawrxd_training
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(rawrxd_training
    PUBLIC
        rawrxd_core
        nlohmann_json::nlohmann_json
)

# Training executables
add_executable(train_lora
    examples/train_lora_main.cpp
)

target_link_libraries(train_lora
    PRIVATE
        rawrxd_training
        rawrxd_core
)

add_executable(export_model
    examples/export_model_main.cpp
)

target_link_libraries(export_model
    PRIVATE
        rawrxd_training
        rawrxd_core
)

# Tests
if(BUILD_TESTING)
    add_executable(test_training
        tests/test_lora.cpp
        tests/test_dataset.cpp
        tests/test_checkpoint.cpp
    )

    target_link_libraries(test_training
        PRIVATE
            rawrxd_training
            GTest::gtest_main
    )

    add_test(NAME TrainingTests COMMAND test_training)
endif()

# Installation
install(TARGETS rawrxd_training
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/
    DESTINATION include/rawrxd/training
    FILES_MATCHING PATTERN "*.hpp"
)
