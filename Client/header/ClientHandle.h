//
// Created by גאי ברנשטיין on 20/09/2024.
//
#ifndef CLIENT_CLIENTHANDLE_H
#define CLIENT_CLIENTHANDLE_H
#pragma once
#include "ClientLogic.h"
#include <string>       // std::to_string


class ClientHandle {
public:
    ClientHandle() : _isRegistered(false), _currRetry(FIRST_TRY) {}

    // Rule of five
    virtual ~ClientHandle() = default;
    ClientHandle(const ClientHandle& other) = delete;
    ClientHandle(ClientHandle&& other) noexcept = delete;
    ClientHandle& operator=(const ClientHandle& other) = delete;
    ClientHandle& operator=(ClientHandle&& other) noexcept = delete;

    // protocol operations
    bool initializeAndConnect(bool &isReconnect);
    bool exchangeKeys();
    bool sendFile(bool &isInvalidCRC);
    bool sendValidCRC();
    bool sendInvalidCRC();
    bool sendAbort();

    // inline getters and setters
    bool hasRemainingAttempts() const { return _currRetry <= MAX_RETRIES; }
    std::string getErrorMessage() const { return _errMessage; }
    csize_t getAttemptNumber() const { return _currRetry; }
    void resetTries(){ _currRetry = FIRST_TRY;};


private:
    ClientLogic                    _clientLogic;
    bool                           _isRegistered; // to check if is registered to not exchange keys in that event
    csize_t                        _currRetry;
    std::string                    _errMessage;

    bool reportErrorAndDecrementRetries(const std::string& errorContext);

};
#endif //CLIENT_CLIENTHANDLE_H
