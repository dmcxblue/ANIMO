cmake_minimum_required(VERSION 3.16)
project(ANIMO LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Security hardening flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -fstack-protector-strong   # Stack buffer overflow protection
        -D_FORTIFY_SOURCE=2        # Buffer overflow checks in libc functions
        -fPIE                      # Position independent executable
    )
    add_link_options(
        -Wl,-z,relro               # Read-only relocations
        -Wl,-z,now                 # Immediate binding (full RELRO)
        -pie                       # Position independent executable
    )
endif()

# Find Qt6 globally (Test is optional at configure but required for the tests/ target)
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Sql Network WebEngineWidgets Test)

enable_testing()

# Subprojects
add_subdirectory(shared)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(tests)
