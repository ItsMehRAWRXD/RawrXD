# Certification Module - VAL-064 through VAL-067
set(CERTIFICATION_SOURCES
    CertificationTestSuite.cpp
)

add_library(certification_suite STATIC
    ${CERTIFICATION_SOURCES}
)

target_include_directories(certification_suite PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(certification_suite PUBLIC
    nlohmann_json::nlohmann_json
)
