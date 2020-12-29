#################
# prerequisites #
#################

cmake_minimum_required(VERSION 3.16)

project(cryptobox LANGUAGES CXX)

find_program(CONAN conan)
if (NOT CONAN)
    message(FATAL_ERROR
            "Cannot find conan. Is it installed?")
endif()

########################
# variable assignments #
########################

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_EXTENSIONS OFF)

set(ROOT_DIRECTORY ${CMAKE_SOURCE_DIR})

set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR})

set(COMPILE_OPTIONS
    -Werror
    $<$<CONFIG:DEBUG>:-g>
    $<$<CONFIG:DEBUG>:-ggdb>
    $<$<CONFIG:DEBUG>:-O0>)

set(COMPILE_WARNINGS
    -Wall
    -Wextra
    -Wpedantic
    -Wfloat-equal
    -Wctor-dtor-privacy
    -Winit-self
    -Wmissing-declarations
    -Wnoexcept
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Woverloaded-virtual
    -Wredundant-decls
    -Wshadow
    -Wsign-promo
    -Wswitch-default
    -Wundef)

##########################
# dependencies retrieval #
##########################

if (NOT EXISTS ${BUILD_DIRECTORY}/conanbuildinfo.cmake)
    execute_process(COMMAND
                    ${CONAN} install conan_dependencies.txt --build=missing --install-folder=${BUILD_DIRECTORY}
                    WORKING_DIRECTORY ${ROOT_DIRECTORY})
endif()

if (NOT EXISTS ${BUILD_DIRECTORY}/conanbuildinfo.cmake)
    message(FATAL_ERROR "Cannot find `conanbuildinfo.cmake` after installing dependencies. Did `conan install` work?")
endif()

include(${BUILD_DIRECTORY}/conanbuildinfo.cmake)

conan_basic_setup(TARGETS)

###########################
# subdirectories includes #
###########################

add_subdirectory(src)
