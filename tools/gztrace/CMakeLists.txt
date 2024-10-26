# Minimum required version of CMake
cmake_minimum_required(VERSION 3.10)

# Project name
project(gztrace)

# Set the C standard
set(CMAKE_C_STANDARD 99)

# Include directory for header files
include_directories(${PROJECT_SOURCE_DIR}/include)

# Source files
set(SOURCE_FILES
        src/main.c
        src/param.c
        src/trace.c
        src/syscall.c
        src/record.c
)

# Add the executable target
add_executable(${PROJECT_NAME} ${SOURCE_FILES})
