cmake_minimum_required(VERSION 3.18)
project(ids_pipeline)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# pybind11 — fetched automatically if not found locally
find_package(pybind11 QUIET)
if(NOT pybind11_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG        v2.12.0
  )
  FetchContent_MakeAvailable(pybind11)
endif()

pybind11_add_module(ids_pipeline ids_pipeline.cpp)

target_include_directories(ids_pipeline PRIVATE
  ${CMAKE_SOURCE_DIR}/../../include
)

# Compiler-specific optimisation flags — no generator expressions
if(MSVC)
  target_compile_options(ids_pipeline PRIVATE /O2 /arch:AVX2 /fp:fast)
  target_compile_definitions(ids_pipeline PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(ids_pipeline PRIVATE -O3 -march=native -ffast-math)
endif()
