cmake_minimum_required(VERSION 3.24)

project(cabral
    VERSION 0.1.0
    DESCRIPTION "TCP/UDP port scanner"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(PROJECT_IS_TOP_LEVEL)
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
    if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    endif()
endif()

# GUI apenas no Linux; Windows recebe build degradado (docs/ARCHITECTURE.md).
if(UNIX AND NOT APPLE)
    set(CABRAL_GUI_DEFAULT ON)
else()
    set(CABRAL_GUI_DEFAULT OFF)
endif()

option(CABRAL_BUILD_GUI "Build the ImGui front-end" ${CABRAL_GUI_DEFAULT})
option(CABRAL_BUILD_TESTS "Build unit tests" ${PROJECT_IS_TOP_LEVEL})

add_library(cabral_warnings INTERFACE)
if(MSVC)
    target_compile_options(cabral_warnings INTERFACE /W4 /permissive- /Zc:__cplusplus)
    # Sem isso, o MSVC reporta __cplusplus == 199711L mesmo em /std:c++20.
    target_compile_definitions(cabral_warnings INTERFACE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(cabral_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_subdirectory(src)

if(CABRAL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
