#include "Base64Wrapper.h"
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/trim.hpp>

std::string Base64Wrapper::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

std::string Base64Wrapper::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}

std::string Base64Wrapper::hex(const std::string& buffer)
{
    if (buffer.empty())
        return "";
    try
    {
        return boost::algorithm::hex(buffer);
    }
    catch (...)
    {
        return "";
    }
}

std::string Base64Wrapper::hex(const std::array<uint8_t, CLIENT_ID_SIZE> &buffer, const size_t size) {
    if (size == 0)
        return "";
    const std::string byteString(buffer.begin(), buffer.begin() + size);
    if (byteString.empty())
        return "";
    try
    {
        return boost::algorithm::hex(byteString);
    }
    catch (...)
    {
        return "";
    }
}

std::string Base64Wrapper::unhex(const std::string &hexString) {
    if (hexString.empty() || hexString.size() % 2 != 0) // need to be even for catching pairs
        return "";
    try
    {
        std::string result;
        boost::algorithm::unhex(hexString,std::back_inserter(result));
        return result;
    }
    catch (...)
    {
        return "";
    }
}

void Base64Wrapper::trim(std::string &stringToTrim) {
    boost::algorithm::trim(stringToTrim);
}