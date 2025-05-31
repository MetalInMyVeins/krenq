cmake_minimum_required(VERSION 3.16.3)
project(krenq)
set(pn ${CMAKE_PROJECT_NAME})
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_LIBRARIES "${CMAKE_CXX_STANDARD_LIBRARIES} -static-libgcc -static-libstdc++")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(-std=c++20 -g0 -Wall -Wextra -Wpedantic -Werror -O3 -march=native -funroll-loops -finline-functions -fomit-frame-pointer -fno-rtti -falign-functions)

set(LIBRARY_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/lib)

add_library(lib${pn} SHARED
  ${CMAKE_SOURCE_DIR}/src/Core.cxx
  ${CMAKE_SOURCE_DIR}/src/krenq_status.cxx
  ${CMAKE_SOURCE_DIR}/src/privates1.cxx
  ${CMAKE_SOURCE_DIR}/src/save_key.cxx
  ${CMAKE_SOURCE_DIR}/src/sha-256.cxx
)

set_property(TARGET lib${pn} PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(lib${pn} PRIVATE ${CMAKE_SOURCE_DIR}/include)

set_target_properties(lib${pn} PROPERTIES
  OUTPUT_NAME ${pn}
)


