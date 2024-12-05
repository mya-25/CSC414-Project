cmake_minimum_required(VERSION 3.10)

# Project name and version
project(MyTestProject VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Ensure consistent runtime library setting across all configurations
if(MSVC)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MDd")  # For Debug mode, use dynamic runtime
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")  # For Release mode, use dynamic runtime
endif()

# Include Google Test (assuming googletest is in the same directory as this CMakeLists.txt)
add_subdirectory(googletest)

# Add your test source files
add_executable(MyTest test/test.cpp)

# Link Google Test and Google Mock (if you use it) to your test executable
target_link_libraries(MyTest gtest gtest_main)

# Optionally: Include directories if needed
# target_include_directories(MyTest PRIVATE src)

# Enable testing
enable_testing()
add_test(NAME MyTest COMMAND MyTest)

