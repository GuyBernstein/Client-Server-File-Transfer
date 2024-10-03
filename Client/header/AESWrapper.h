#ifndef CLIENT_AES_WRAPPER_H
#define CLIENT_AES_WRAPPER_H
#pragma once
#include <string>

#include "protocol.h"
class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 16;
private:
	AESKey _key{};
public:
    AESWrapper() = default;
    AESWrapper(AESKey key) : _key(key){};

    virtual ~AESWrapper()                              = default;
    AESWrapper(const AESWrapper& other)                = delete;
    AESWrapper(AESWrapper&& other) noexcept            = delete;
    AESWrapper& operator=(const AESWrapper& other)     = delete;
    AESWrapper& operator=(AESWrapper&& other) noexcept = delete;

    AESKey getKey() const {return _key;};

    std::string encrypt(const std::string& plain) const;
    std::string encrypt(const uint8_t* plain, size_t length) const;
    std::string decrypt(const uint8_t* cipher, size_t length) const;
};

#endif //CLIENT_AES_WRAPPER_H
