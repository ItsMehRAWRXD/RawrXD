cmake_minimum_required(VERSION 3.20)
project(RawrXDParityClosureTools LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(rawrxd_parity_tokenizer STATIC
    src/GgufParityTokenizer.cpp
)
target_include_directories(rawrxd_parity_tokenizer PUBLIC src)

add_executable(rawrxd_tokenizer_parity
    tools/tokenizer_parity_cert.cpp
)
target_link_libraries(rawrxd_tokenizer_parity PRIVATE rawrxd_parity_tokenizer)

add_executable(rawrxd_deep2_parity
    tools/deep2_parity_ladder.cpp
)

add_executable(rawrxd_token_sequence_parity
    tools/token_sequence_parity.cpp
)

if(MSVC)
    foreach(t
        rawrxd_parity_tokenizer
        rawrxd_tokenizer_parity
        rawrxd_deep2_parity
        rawrxd_token_sequence_parity)
        target_compile_options(${t} PRIVATE /W4 /EHsc)
    endforeach()
else()
    foreach(t
        rawrxd_parity_tokenizer
        rawrxd_tokenizer_parity
        rawrxd_deep2_parity
        rawrxd_token_sequence_parity)
        target_compile_options(${t} PRIVATE -Wall -Wextra -Wpedantic)
    endforeach()
endif()
