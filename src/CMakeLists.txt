#########################
# targets configuration #
#########################

set(PUBLIC_HEADER_LIST
    All.h
    Buffer.h
    KeyHandle.h
    Message.h
    Operations.h
    Signature.h
    Types.h)

add_library(cryptobox SHARED
            Buffer.cpp
            KeyHandle.cpp
            Message.cpp
            Operations.cpp
            Signature.cpp)

set_target_properties(cryptobox PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADER_LIST}")

target_link_libraries(cryptobox PRIVATE
                      CONAN_PKG::openssl)

install(TARGETS cryptobox
        PUBLIC_HEADER DESTINATION include
        LIBRARY DESTINATION lib)
