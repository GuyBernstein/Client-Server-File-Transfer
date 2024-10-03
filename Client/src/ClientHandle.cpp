//
// Created by גאי ברנשטיין on 20/09/2024.
//
#include "ClientHandle.h"
#include <iostream>

/**
 * Initialize client's keys & its connection with the server.
 */
bool ClientHandle::initializeAndConnect(bool &isReconnect) {
    // initializing the client, determining if client's need to register or reconnect.
    _clientLogic.initialize(isReconnect);

    // trying to register
    if (!_clientLogic.isRegistered() && !_clientLogic.registerClient())
        return reportErrorAndDecrementRetries("Registration failed");

    // trying to reconnect
    else if (_clientLogic.isRegistered() && !_clientLogic.reconnectClient())
        return reportErrorAndDecrementRetries("Reconnection failed");

    return true;
}

/**
 * Exchanging keys with the server.
 */
bool ClientHandle::exchangeKeys() {
    if(_clientLogic.sendPublicKey())
        return true;
    else
        return reportErrorAndDecrementRetries("Sending public key failed");
}

/**
 * Sending a file to the server
 */
bool ClientHandle::sendFile(bool &isInvalidCRC) {
    if(_clientLogic.sendEncryptedFileAndCorrespondedCRC(isInvalidCRC))
        return true;
    else
        return reportErrorAndDecrementRetries("Sending file failed");
}

/**
 * Sending a message indicating the server's crc is valid
 */
bool ClientHandle::sendValidCRC() {
    if(_clientLogic.sendCRCMessage(CRC_VALID))
        return true;
    else
        return reportErrorAndDecrementRetries("Sending Valid CRC failed");}


/**
 * Sending a message indicating the server's crc is invalid
 */
bool ClientHandle::sendInvalidCRC() {
    // Its isn't mentioned in the protocol,
    // but I assume that in this case the server would respond with code 1604 for a success
    if(_clientLogic.sendCRCMessage(CRC_INVALID_SENDING_AGAIN))
        return true;
    else
        return reportErrorAndDecrementRetries("Sending Invalid CRC failed");}


/**
 * Sending a message indicating the server's crc is invalid thus,
 * there is not further attempts to resend the file
 */
bool ClientHandle::sendAbort() {
    if(_clientLogic.sendCRCMessage(CRC_INVALID_FORTH_TIME_IM_DONE))
        return true;
    else
        return reportErrorAndDecrementRetries("Sending abort message failed");}


/**
 * Print error and decrement current retry of connecting with the server
 */
bool ClientHandle::reportErrorAndDecrementRetries(const std::string &errorContext) {
    std::string attemptNumber = "Attempt " + std::to_string(getAttemptNumber()) + ":\n";
    _currRetry++;
    _errMessage += attemptNumber + errorContext + ": " + _clientLogic.getLastError() + '\n';
    std::cout << "Server responded with an error" << std::endl;
    return false;
}


