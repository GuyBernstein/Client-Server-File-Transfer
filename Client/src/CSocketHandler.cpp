//
// Created by גאי ברנשטיין on 21/09/2024.
//
#include "CSocketHandler.h"
#include <boost/asio.hpp>
#include <iostream>
using boost::asio::ip::tcp;
using boost::asio::io_context;

CSocketHandler::CSocketHandler() : _ioContext(nullptr), _resolver(nullptr), _socket(nullptr), _connected(false)
{
    union   // Test for endianness
    {
        uint32_t i;
        uint8_t c[sizeof(uint32_t)];
    }tester{ 1 };
    _bigEndian = (tester.c[0] == 0);
}

CSocketHandler::~CSocketHandler()
{
    close();
}

/**
 * Set the socket's address and port
 */
bool CSocketHandler::setSocketInfo(const std::string& address, const std::string& port)
{
    if (!isValidAddress(address) || !isValidPort(port))
    {
        return false;
    }
    _address = address;
    _port    = port;

    return true;
}

/**
 * Try parse IP Address. Return false if failed.
 * Handle special cases of "localhost", "LOCALHOST"
 */
bool CSocketHandler::isValidAddress(const std::string& address)
{
    if ((address == "localhost") || (address == "LOCALHOST"))
        return true;
    try
    {
        (void) boost::asio::ip::address_v4::from_string(address);
    }
    catch(...)
    {
        return false;
    }
    return true;
}

/**
 * Try to parse a port number from a string.
 * Return false if failed.
 */
bool CSocketHandler::isValidPort(const std::string& port)
{
    try
    {
        const int p = std::stoi(port);
        return (p > 0);  // port <= 0 is invalid..
    }
    catch(...)
    {
        return false;
    }
}

/**
 * Clear socket and connect to new socket.
 */
bool CSocketHandler::connect()
{
    if (!isValidAddress(_address) || !isValidPort(_port))
        return false;
    try
    {
        close();  // close and clear the current socket before new allocations.
        _ioContext = new io_context;
        _resolver  = new tcp::resolver(*_ioContext);
        _socket    = new tcp::socket(*_ioContext);

        boost::asio::connect(*_socket, _resolver->resolve(
                _address, _port, tcp::resolver::query::canonical_name));
        _socket->non_blocking(false);  // blocking socket..
        _connected = true;
    }
    catch(...)
    {
        _connected = false;
    }
    return _connected;
}

/**
 * Close current socket.
 */
void CSocketHandler::close()
{
    try
    {
        if (_socket != nullptr)
            _socket->close();
    }
    catch (...) {} // Do Nothing
    delete _ioContext;
    delete _resolver;
    delete _socket;
    _ioContext = nullptr;
    _resolver  = nullptr;
    _socket    = nullptr;
    _connected = false;
}

/**
 * Sending a request to the server and receiving a response with receiveSize size
 */
bool
CSocketHandler::communicate(const std::vector<uint8_t> &toSend, std::vector<uint8_t> &response, csize_t receiveSize) {
    if (!connect()) {
        return false;
    }
    if (!sendData(toSend)) {
        close();
        return false;
    }
    if (!receiveData(response, receiveSize)) {
        close();
        return false;
    }
    close();
    return true;
}

/**
 * receiving a response from the server, handling big data
 */
bool CSocketHandler::receiveData(std::vector<uint8_t> &buffer, csize_t bytesToReceive) {
    if (_socket == nullptr || !_connected  || bytesToReceive == 0)
        return false;

    buffer.clear();
    buffer.reserve(bytesToReceive);

    csize_t bytesReceived = 0;
    std::vector<uint8_t> tempBuffer(PACKET_SIZE, 0);

    while (bytesReceived < bytesToReceive)
    {
        boost::system::error_code errorCode;
        csize_t bytesRead = read(*_socket, boost::asio::buffer(tempBuffer, PACKET_SIZE),
                                 errorCode);

        if (errorCode || bytesRead == 0) {
            return false;
        }

        if (_bigEndian) {
            convertEndianess(tempBuffer.data(), bytesRead);
        }

        csize_t bytesToCopy = std::min(bytesRead, bytesToReceive - bytesReceived);
        buffer.insert(buffer.end(), tempBuffer.begin(), tempBuffer.begin() + bytesToCopy);


        bytesReceived += bytesToCopy;
    }

    return true;
}

/**
 * sending a request to the server, handling big data
 */
bool CSocketHandler::sendData(const std::vector<uint8_t> &buffer) {
    if (_socket == nullptr || !_connected || buffer.empty())
        return false;

    std::vector<uint8_t> tempBuffer(PACKET_SIZE);

    csize_t bytesSent = 0;
    while (bytesSent < buffer.size())
    {
        csize_t bytesToSend = std::min(PACKET_SIZE, static_cast<csize_t>(buffer.size() - bytesSent));
        std::copy(buffer.begin() + bytesSent, buffer.begin() + bytesSent + bytesToSend,
                  tempBuffer.begin());

        if (_bigEndian) {
            convertEndianess(tempBuffer.data(), bytesToSend);
        }

        boost::system::error_code errorCode;
        size_t bytesWritten = write(*_socket,boost::asio::buffer(tempBuffer, PACKET_SIZE),
                                    errorCode);

        if (errorCode || bytesWritten == 0) {
            return false;
        }

        bytesSent += bytesWritten;
    }

    return true;
}


/**
 * Handle Endianness.
 */
void CSocketHandler::convertEndianess(uint8_t* const buffer, size_t size)
{
    if (buffer == nullptr || size < sizeof(uint32_t))
        return;

    size_t numInts = size / sizeof(uint32_t);
    auto* intBuffer = reinterpret_cast<uint32_t*>(buffer);

    for (size_t i = 0; i < numInts; ++i)
    {
        intBuffer[i] = htonl(intBuffer[i]);
    }

}


