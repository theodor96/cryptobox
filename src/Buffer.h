#ifndef SRC_BUFFER_H
#define SRC_BUFFER_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <cstddef>
#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// fwd decl

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    class Buffer
    {
    public:
        /**
         * TODO: docs
         */
        static Buffer createFromText(const std::string& text);

        /**
         * TODO: docs
         */
        static Buffer createFromHex(const std::string& hex);

        /**
         * TODO: docs
         */
        static Buffer createFromRawBuffer(const unsigned char* rawBuffer, std::size_t rawBufferLength);

    private:
        Buffer(const unsigned char* rawBuffer, std::size_t rawBufferLength);
    };
}

#endif
