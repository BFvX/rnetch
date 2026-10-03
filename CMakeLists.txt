cmake_minimum_required(VERSION 3.18)
project(rnetch LANGUAGES NONE)

# Compatibility entry point. Cargo is the source of truth for the Rust core.
if(NOT WIN32)
    message(FATAL_ERROR "rnetch runtime requires Windows x64; use cargo test for portable modules")
endif()
find_program(POWERSHELL_EXECUTABLE NAMES pwsh powershell REQUIRED)
add_custom_target(rnetch ALL
    COMMAND "${POWERSHELL_EXECUTABLE}" -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_CURRENT_SOURCE_DIR}/scripts/build.ps1"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Building Rust rnetch (target/release/rnetch.exe)"
    VERBATIM
)

