cmake_minimum_required(VERSION 3.10)

project(cryptobox LANGUAGES CXX)

if(NOT EXISTS "build/conanbuildinfo.cmake")
    execute_process(COMMAND
                    conan install . --build missing --install-folder "build"
                    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
endif()

include(build/conanbuildinfo.cmake)
conan_basic_setup()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-Wall)

add_executable(cryptobox-client
               src/detail/backend/openssl/OpenSsl.h
               src/detail/HexIterator.h
               src/All.h
               src/Buffer.h
               src/Buffer.cpp
               src/Client.cpp
               src/KeyHandle.h
               src/KeyHandle.cpp
               src/Message.h
               src/Message.cpp
               src/Operations.h
               src/Operations.cpp
               src/Signature.cpp
               src/Signature.h
               src/Types.h)

target_include_directories(cryptobox-client
                           PRIVATE
                           ${CMAKE_SOURCE_DIR}/src
                           ${CONAN_INCLUDE_DIRS_OPENSSL})

target_link_libraries(cryptobox-client
                      ${CONAN_LIBS_OPENSSL})
