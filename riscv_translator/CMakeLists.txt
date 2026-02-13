cmake_minimum_required(VERSION 3.10)
project(RiscvToX86Translator)

set(CMAKE_CXX_STANDARD 17)

# 1. Point exactly to the config folder
set(capstone_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../capstone/install_dir/lib/cmake/capstone")

# 2. Find the package
find_package(capstone REQUIRED CONFIG)

# 3. Add your executable
add_executable(translator generate_c.cpp)

# 4. Link using the variables Capstone defines (fallback if target fails)
if(TARGET capstone::capstone)
    target_link_libraries(translator PRIVATE capstone::capstone)
else()
    # Manual link using the include and library variables from capstone-config.cmake
    target_include_directories(translator PRIVATE ${capstone_INCLUDE_DIR})
    target_link_libraries(translator PRIVATE "${capstone_LIB_DIR}/libcapstone.a")
endif()
