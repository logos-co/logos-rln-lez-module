cmake_minimum_required(VERSION 3.14)
project(RlnLezModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found. LOGOS_MODULE_BUILDER_ROOT is not set.")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/metadata.json
               ${CMAKE_CURRENT_BINARY_DIR}/metadata.json COPYONLY)

logos_module(
    NAME rln_lez_module
    EXTERNAL_LIBS core_ffi
)

find_library(LIBLOGOS_RLN_MODULE_RUST
    NAMES librln_lez_module.a rln_lez_module
    PATHS
        ${CMAKE_CURRENT_SOURCE_DIR}/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/rust-lib/target/release
        ${CMAKE_CURRENT_SOURCE_DIR}/rust-lib/target/debug
    NO_DEFAULT_PATH
)

if(NOT LIBLOGOS_RLN_MODULE_RUST)
    message(FATAL_ERROR
        "Rust static library (librln_lez_module.a) not found in ${CMAKE_CURRENT_SOURCE_DIR}/lib. "
        "Ensure the preConfigure hook staged the buildRustPackage output."
    )
endif()

message(STATUS "Found rln_lez_module Rust static library: ${LIBLOGOS_RLN_MODULE_RUST}")

target_link_libraries(rln_lez_module_module_plugin PRIVATE
    ${LIBLOGOS_RLN_MODULE_RUST}
    logos-protocol::logos_protocol
)

if(APPLE)
    target_link_libraries(rln_lez_module_module_plugin PRIVATE
        "-framework CoreFoundation"
        "-framework Security"
    )
elseif(NOT WIN32)
    target_link_libraries(rln_lez_module_module_plugin PRIVATE pthread dl)
endif()
