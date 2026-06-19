cmake_minimum_required(VERSION 3.14)

project(bifrost VERSION 1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

file(GLOB SOURCES "src/*.cpp")
file(GLOB TEST_SOURCES "test/*.cpp")

add_executable(${PROJECT_NAME} ${SOURCES})

# add_executable(test ${TEST_SOURCES} src/KeyStore.cpp src/utility.cpp src/TypeDefs.cpp)

target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# target_include_directories(test PRIVATE 
#     ${CMAKE_CURRENT_SOURCE_DIR}/include
#     ${OPENSSL_INCLUDE_DIR}
# )

target_link_libraries(${PROJECT_NAME} PRIVATE 
    OpenSSL::Crypto
    OpenSSL::SSL
)

# target_link_libraries(test PRIVATE 
#     OpenSSL::Crypto
#     OpenSSL::SSL
# )
