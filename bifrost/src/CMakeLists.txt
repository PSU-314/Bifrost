# Explicit source listing - NO GLOBBING
set(BIFROST_LIB_SOURCES
    KDF.cpp
    KeyStore.cpp
    terminal-launch.cpp
    tls.cpp
    totp.cpp
    utility.cpp
)

# Core Library Target
add_library(bifrost_lib STATIC ${BIFROST_LIB_SOURCES})
add_library(bifrost::lib ALIAS bifrost_lib)

# Include directories
target_include_directories(bifrost_lib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Dependencies
target_link_libraries(bifrost_lib
    PUBLIC OpenSSL::Crypto Threads::Threads
    PRIVATE OpenSSL::SSL
)

# Apply Hardening and Warnings
set_project_warnings(bifrost_lib)
set_security_flags(bifrost_lib)

# ---------------------------------------------------------
# Executable Target
# ---------------------------------------------------------
add_executable(${PROJECT_NAME} bifrost.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE bifrost::lib)

# Apply Hardening and Warnings to binary
set_project_warnings(${PROJECT_NAME})
set_security_flags(${PROJECT_NAME})
if(ipo_supported)
    set_property(TARGET ${PROJECT_NAME} PROPERTY
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    set_property(TARGET ${PROJECT_NAME} PROPERTY
        INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
endif()

# ---------------------------------------------------------
# Installation Rules
# ---------------------------------------------------------
# 1. Install the binary
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
#     DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bifrost
#     FILES_MATCHING PATTERN "*.hpp"
# )

# 2. Configure and install the desktop file
# This injects the exact install prefix into the Exec line
configure_file(
    ${CMAKE_SOURCE_DIR}/bifrost-authentication.desktop.in
    ${CMAKE_CURRENT_BINARY_DIR}/bifrost-authentication.desktop
    @ONLY
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bifrost-authentication.desktop
    DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
)
