cmake_minimum_required(VERSION 3.14)
project(openguard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Place compiled binaries directly in the build root (including multi-config generators)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}")
endforeach()

find_package(Threads REQUIRED)

add_executable(openguard
    src/main.cpp
    src/proxy.cpp
)

target_include_directories(openguard PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(openguard PRIVATE Threads::Threads)

if(MSVC)
    target_compile_options(openguard PRIVATE /W4 /permissive-)
else()
    target_compile_options(openguard PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()

add_test(NAME test_blocked_ssh
    COMMAND sh -c "echo '{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/home/user/.ssh/id_rsa\"}},\"id\":1}' | ./openguard -- cat | grep -q 'Access to sensitive credential path blocked'"
)

add_test(NAME test_allowed_path
    COMMAND sh -c "echo '{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/workspace/docs/readme.txt\"}},\"id\":2}' | ./openguard -- cat | grep -q '/workspace/docs/readme.txt'"
)


