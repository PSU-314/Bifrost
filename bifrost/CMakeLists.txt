cmake_minimum_required(VERSION 3.28)

project(bifrost VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Hardening)

include(GNUInstallDirs)

add_subdirectory(src)

option(BIFROST_BUILD_TESTS "Build the Bifrost test suite" OFF)
if (BIFROST_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

