#ifndef SRC_BUFFER_H
#define SRC_BUFFER_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <cstddef>
#include <string>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// fwd decl

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    class Buffer
    {
    public:
        Buffer() = default;

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

        /**
         * TODO: docs
         */
        std::string toHex() const;

    private:
        using InternalBuffer = std::vector<unsigned char>;

        InternalBuffer r_buffer;

        Buffer(InternalBuffer r_buffer);
    };
}

#endif
