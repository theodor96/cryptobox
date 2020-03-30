cmake_minimum_required(VERSION 3.10)

project(cryptobox LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-Wall)

add_executable(cryptobox-client
               src/cryptobox.cpp
               src/CryptoBoxService.h
               src/CryptoBoxService.cpp
        src/KeyHandle.cpp src/KeyHandle.h src/Message.cpp src/Message.h src/Signature.cpp src/Signature.h)

target_include_directories(cryptobox-client PRIVATE /Users/theodorserbana/Desktop/repos/openssl/include)

target_link_libraries(cryptobox-client /Users/theodorserbana/Desktop/repos/openssl/libcrypto.dylib)
