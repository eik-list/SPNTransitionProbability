# ----------------------------------------------------------
# Common
# ----------------------------------------------------------

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

# ----------------------------------------------------------
# Project variables and paths
# ----------------------------------------------------------

# Project name
project(spn-transition-probability)

# Store variables
set(PROJECT_CHECK_RESULTS_DIR check)
set(PROJECT_SOURCE_DIR src)
set(PROJECT_TESTS_DIR tests)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(INCLUDE_DIRECTORIES include src)

# Add include paths
include_directories(${INCLUDE_DIRECTORIES})

# Stores all executables in src folder into variable SOURCES
file(GLOB_RECURSE SOURCES "${PROJECT_SOURCE_DIR}/*.cc")

# Stores all executables in src folder into variable TESTS
file(GLOB TESTS "${PROJECT_TESTS_DIR}/*.cc")

# Compile flags
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Wextra -pedantic -std=c++11 -mavx -march=native -O3")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -ggdb3 -DDEBUG -fsanitize=undefined,alignment,address -ftrapv -fno-omit-frame-pointer -fno-optimize-sibling-calls")
# -Wconversion -Wsign-conversion -Werror

set(CMAKE_BUILD_TYPE Release)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif(NOT CMAKE_BUILD_TYPE)

# Logging
message("Using build type ${CMAKE_BUILD_TYPE}")

# check for jsoncpp version
find_package(PkgConfig REQUIRED)

# ----------------------------------------------------------
# libraries
# ----------------------------------------------------------

# Include pthread
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Include GoogleTest
find_package(GTest REQUIRED)

# ----------------------------------------------------------
# Building apps
# ----------------------------------------------------------

add_executable(transition_matrix ${PROJECT_TESTS_DIR}/transition_matrix.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(transition_matrix PRIVATE -lntl)

add_executable(test_aes_column_transition_algorithm ${PROJECT_TESTS_DIR}/test_aes_column_transition_algorithm.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_aes_column_transition_algorithm PRIVATE -lntl)

add_executable(test_aes_row_and_column_transition_algorithm ${PROJECT_TESTS_DIR}/test_aes_row_and_column_transition_algorithm.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_aes_row_and_column_transition_algorithm PRIVATE -lntl)

add_executable(test_aes_byte_mixture_transition_algorithm ${PROJECT_TESTS_DIR}/test_aes_byte_mixture_transition_algorithm.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_aes_byte_mixture_transition_algorithm PRIVATE -lntl)

add_executable(test_aes_byte_transition_algorithm ${PROJECT_TESTS_DIR}/test_aes_byte_transition_algorithm.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_aes_byte_transition_algorithm PRIVATE -lntl)

add_executable(test_small_aes_byte_transition_algorithm ${PROJECT_TESTS_DIR}/test_small_aes_byte_transition_algorithm.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_small_aes_byte_transition_algorithm PRIVATE -lntl)

add_executable(test_many_aes_column_transitions ${PROJECT_TESTS_DIR}/test_many_aes_column_transitions.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_many_aes_column_transitions PRIVATE -lntl)

add_executable(test_many_small_aes_column_transitions ${PROJECT_TESTS_DIR}/test_many_small_aes_column_transitions.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_many_small_aes_column_transitions PRIVATE -lntl)

add_executable(test_all_aes_byte_transitions ${PROJECT_TESTS_DIR}/test_all_aes_byte_transitions.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_all_aes_byte_transitions PRIVATE -lntl)

add_executable(test_all_aes_column_transitions ${PROJECT_TESTS_DIR}/test_all_aes_column_transitions.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_all_aes_column_transitions PRIVATE -lntl)

add_executable(test_all_small_aes_byte_transitions ${PROJECT_TESTS_DIR}/test_all_small_aes_byte_transitions.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_all_small_aes_byte_transitions PRIVATE -lntl)

add_executable(test_all_small_aes_column_transitions ${PROJECT_TESTS_DIR}/test_all_small_aes_column_transitions.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_all_small_aes_column_transitions PRIVATE -lntl)

add_executable(test_byte_pattern_generator ${PROJECT_TESTS_DIR}/test_byte_pattern_generator.cc ${SOURCES} ${INCLUDE_DIRECTORIES})
target_link_libraries(test_byte_pattern_generator PRIVATE -lntl Threads::Threads gtest gtest_main)
