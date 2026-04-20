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

# libbpf — optional, for eBPF support
find_package(bpf QUIET)
if(bpf_FOUND)
  message(STATUS "libbpf found: ${bpf_LIBRARIES}")
  add_compile_definitions(HAVE_LIBBPF)
else()
  message(STATUS "libbpf not found, eBPF support disabled")
endif()

# Compile BPF program if clang is available
find_program(CLANG clang)
if(CLANG)
  message(STATUS "clang found: ${CLANG}")
  add_custom_command(
    OUTPUT ids_ebpf.bpf.o
    COMMAND ${CLANG} -O2 -target bpf -c ${CMAKE_CURRENT_SOURCE_DIR}/ids_ebpf.bpf.c -o ${CMAKE_CURRENT_BINARY_DIR}/ids_ebpf.bpf.o
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ids_ebpf.bpf.c
    COMMENT "Compiling eBPF program"
  )
  add_custom_target(ebpf_program ALL DEPENDS ids_ebpf.bpf.o)
else()
  message(STATUS "clang not found, eBPF compilation disabled")
endif()

pybind11_add_module(ids_pipeline 
  ids_pipeline.cpp
  ids_ebpf.cpp
)

target_include_directories(ids_pipeline PRIVATE
  ${CMAKE_SOURCE_DIR}/../../include
)

# Link libbpf if available
if(bpf_FOUND)
  target_link_libraries(ids_pipeline PRIVATE ${bpf_LIBRARIES})
endif()

# Compiler-specific optimisation flags — no generator expressions
if(MSVC)
  target_compile_options(ids_pipeline PRIVATE /O2 /arch:AVX2 /fp:fast)
  target_compile_definitions(ids_pipeline PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
else()
  target_compile_options(ids_pipeline PRIVATE -O3 -march=native -ffast-math)
endif()
