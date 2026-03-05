cmake_minimum_required(VERSION 3.10)

# Project Name
project(bifrost VERSION 1.0 LANGUAGES CXX)

# 1. Generate compile_commands.json for LSP/IntelliSense
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 2. Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 3. Find Dependencies
# Finds OpenSSL on Arch Linux (provided by libssl-dev/openssl)
find_package(OpenSSL REQUIRED)

# 4. Gather Source Files
# This automatically picks up all .cpp files in the src directory
file(GLOB SOURCES "src/*.cpp")

# 5. Define the Executable
add_executable(${PROJECT_NAME} ${SOURCES})

# 6. Include Headers
# This tells the compiler to look in the include/ folder
target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# 7. Link Libraries
# Links the crypto and ssl libraries from OpenSSL
target_link_libraries(${PROJECT_NAME} PRIVATE 
    OpenSSL::Crypto
    OpenSSL::SSL
)
