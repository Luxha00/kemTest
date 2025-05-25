cmake_minimum_required(VERSION 3.31)
project(kemTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Paths for liboqs installed via vcpkg
set(VCPKG_INSTALLED_DIR "C:/Users/lukah/vcpkg/installed/x64-windows")

# Find the library and headers
find_library(OQS_LIB
        NAMES oqs.lib
        PATHS "${VCPKG_INSTALLED_DIR}/lib"
        REQUIRED
)

find_path(OQS_INCLUDE_DIR
        NAMES oqs/oqs.h
        PATHS "${VCPKG_INSTALLED_DIR}/include"
        REQUIRED
)

# Add executable
add_executable(kem_test main.cpp)

# Link liboqs
target_include_directories(kem_test PRIVATE ${OQS_INCLUDE_DIR})
target_link_libraries(kem_test PRIVATE ${OQS_LIB})

# For Windows DLLs (copy oqs.dll to build directory)
add_custom_command(TARGET kem_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        "${VCPKG_INSTALLED_DIR}/bin/oqs.dll"
        $<TARGET_FILE_DIR:kem_test>
)