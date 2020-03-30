#ifndef SRC_HEXITERATOR_H
#define SRC_HEXITERATOR_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <cctype>
#include <iterator>
#include <string>
#include <stdexcept>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox::detail
{
    template <typename OutputItrT>
    class HexIterator : public std::iterator<std::output_iterator_tag, void, void, void, void>
    {
    public:
        explicit HexIterator(OutputItrT outItr);

        HexIterator& operator=(char hexDigit);

        HexIterator& operator*();

        const HexIterator& operator++() const;

    private:
        unsigned char r_byte;
        int r_digitCount;
        OutputItrT r_outItr;

        void reset();

        static unsigned int hexDigitToDecimalDigit(char hexDigit);
    };

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    template <typename OutputItrT>
    HexIterator<OutputItrT>::HexIterator(OutputItrT outItr)
    : r_byte{},
      r_digitCount{},
      r_outItr{outItr}
    {

    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    template <typename OutputItrT>
    HexIterator<OutputItrT>& HexIterator<OutputItrT>::operator=(char hexDigit)
    {
        if (0 > hexDigit)
        {
            throw std::invalid_argument{"Invalid hex digit " + std::string{1, hexDigit}};
        }

        r_byte <<= static_cast<unsigned char>(4);
        r_byte |= hexDigitToDecimalDigit(hexDigit);

        if (2 == ++r_digitCount)
        {
            *r_outItr++ = r_byte;
            reset();
        }

        return *this;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    template <typename OutputItrT>
    HexIterator<OutputItrT>& HexIterator<OutputItrT>::operator*()
    {
        return *this;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    template <typename OutputItrT>
    const HexIterator<OutputItrT>& HexIterator<OutputItrT>::operator++() const
    {
        return *this;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    template <typename OutputItrT>
    void HexIterator<OutputItrT>::reset()
    {
        r_byte = {};
        r_digitCount = {};
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    template <typename OutputItrT>
    unsigned int HexIterator<OutputItrT>::hexDigitToDecimalDigit(char hexDigit)
    {
        static const std::string hexCharacters{"0123456789abcdef"};

        auto result = hexCharacters.find(std::tolower(hexDigit));
        if (std::string::npos == result)
        {
            throw std::invalid_argument{"Invalid hex digit " + std::string{1, hexDigit}};
        }

        return result;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    template <typename OutputItrT>
    auto getHexIterator(OutputItrT outItr)
    {
        return HexIterator<OutputItrT>{outItr};
    }
}

#endif
