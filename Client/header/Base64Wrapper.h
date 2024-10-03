#ifndef CLIENT_BASE_64_WRAPPER_H
#define CLIENT_BASE_64_WRAPPER_H
#pragma once
#include <string>
#include <array>
#include "protocol.h"
#include <string>
#include <base64.h>


class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
    static std::string hex(const std::string& str);
    static std::string hex(const std::array<uint8_t, CLIENT_ID_SIZE> &buffer, size_t size);
    static std::string unhex(const std::string& hexString);

    static void trim(std::string& stringToTrim);
};

#endif //CLIENT_BASE_64_WRAPPER_H
