cmake_minimum_required(VERSION 3.22.1)

project("maigshield" LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Hardening flags and compiler protections
add_compile_options(
    -std=c++20
    -fvisibility=hidden
    -fvisibility-inlines-hidden
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -Wformat
    -Wformat-security
    -Wall
    -Wextra
    -O2
)

# Stripping symbols & linker hardening
set(CMAKE_SHARED_LINKER_FLAGS
    "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,--gc-sections -Wl,-s"
)

add_library(
    maigshield
    SHARED
    jni_bridge.cpp
    integrity_scanner.cpp
    native_sensors.cpp
    token_packer.cpp
)

find_library(android-lib android)
find_library(log-lib log)

target_link_libraries(
    maigshield
    ${android-lib}
    ${log-lib}
)
