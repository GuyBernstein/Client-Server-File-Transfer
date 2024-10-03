//
// Created by גאי ברנשטיין on 21/09/2024.
//

#ifndef CLIENT_CSOCKETHANDLER_H
#define CLIENT_CSOCKETHANDLER_H
#pragma once
#include <string>
#include <cstdint>
#include <ostream>
#include <vector>
#include "protocol.h"
#include <arpa/inet.h>  // for htonl
#include <boost/asio/ip/tcp.hpp>

using boost::asio::ip::tcp;
using boost::asio::io_context;

class CSocketHandler
{
public:
    CSocketHandler();

    // Rule of five
    virtual ~CSocketHandler();
    CSocketHandler(const CSocketHandler& other)                = delete;
    CSocketHandler(CSocketHandler&& other) noexcept            = delete;
    CSocketHandler& operator=(const CSocketHandler& other)     = delete;
    CSocketHandler& operator=(CSocketHandler&& other) noexcept = delete;

    // validators
    static bool isValidAddress(const std::string& address);
    static bool isValidPort(const std::string& port);

    // setter
    bool setSocketInfo(const std::string& address, const std::string& port);

    // communicator
    bool communicate(const std::vector<uint8_t> &toSend, std::vector<uint8_t> &response, csize_t receiveSize);


private:
    std::string    _address;
    std::string    _port;
    io_context*    _ioContext;
    tcp::resolver* _resolver;
    tcp::socket*   _socket;
    bool           _bigEndian;
    bool           _connected;  // indicates that socket has been open and connected.

    // private methods
    static void convertEndianess(uint8_t* buffer, size_t size) ;
    bool receiveData(std::vector<uint8_t> &buffer, csize_t bytesToReceive);
    bool sendData(const std::vector<uint8_t> &buffer);
    bool connect();
    void close();

};
#endif //CLIENT_CSOCKETHANDLER_H
