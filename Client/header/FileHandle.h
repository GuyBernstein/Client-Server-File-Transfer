//
// Created by גאי ברנשטיין on 20/09/2024.
//

#ifndef CLIENT_FILE_HANDLE_H
#define CLIENT_FILE_HANDLE_H
#pragma once
#include <iostream>
#include <fstream>
#include "protocol.h"
#include <boost/filesystem.hpp>  // for create_directories


class FileHandle
{
public:
    FileHandle();

    // Rule of five
    virtual ~FileHandle();
    FileHandle(const FileHandle& other)                = delete;
    FileHandle(FileHandle&& other) noexcept            = delete;
    FileHandle& operator=(const FileHandle& other)     = delete;
    FileHandle& operator=(FileHandle&& other) noexcept = delete;

    // file wrapper functions
    bool open(const std::string& filepath, bool write = false);
    void close();
    size_t size();

    bool readLine(std::string& line);
    bool readChunk(std::string &chunk, csize_t chunkSize, bool &eof);

    bool write(const std::string& data);
    bool write(const ClientName& clientName);

    bool writeLine(const std::string &line) ;
    bool writeLine(const ClientName& clientName);
    bool isOpen() const { return _isOpen; }
    bool isWriteMode() const { return _isWriteMode; }

private:
    std::ifstream _inStream;
    std::ofstream _outStream;
    bool _isOpen;
    bool _isWriteMode;
};

#endif //CLIENT_FILE_HANDLE_H
