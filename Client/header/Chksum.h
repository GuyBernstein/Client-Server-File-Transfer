//
// Created by גאי ברנשטיין on 29/09/2024.
//

#ifndef CLIENT_CHKSUM_H
#define CLIENT_CHKSUM_H

#define UNSIGNED(n) (n & 0xffffffff)

#include <iostream>
#include <fstream>
#include <ostream>
#include <cstdio>
#include <vector>
#include <iterator>
#include <filesystem>
#include <string>
#include <cstdint>
#include "protocol.h"


class Chksum {
public:
    static bool readFile(std::string &fName, std::string &fContent, CRC &crc, csize_t fileSize);
private:
    static CRC memcrc(const char * b, size_t n);
};

#endif //CLIENT_CHKSUM_H
