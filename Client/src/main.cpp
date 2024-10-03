//
// Created by גאי ברנשטיין on 20/09/2024.
//

#include "ClientHandle.h"
#include <iostream>

int main(int argc, char* argv[])
{
    ClientHandle client;
    // variables to store each operation
    bool isConnected, isExchangeKeys, isReconnect;
    bool isSentFile, isSentValidCRC, isSentInvalidCRC;
    bool isSentLastCRC, isInvalidCRC = false, isAccept, isAbort = false;

    do {
        // try to connect to the server
        isConnected = client.initializeAndConnect(isReconnect);
    } while (!isConnected && client.hasRemainingAttempts());

    if (!isConnected) {
        std::cout << std::endl << "FATAL ERROR:" << std::endl;
        std::cout << "All connection attempts failed. Errors:" << std::endl;
        std::cout << client.getErrorMessage() << std::endl;
        return 1;
    }

    if(!isReconnect) {
        // do not allow if the client is already registered
        std::cout << "registration succeeded, the client is registered" << std::endl;

        client.resetTries();
        do {
            // try to send our public key,
            // and receive the server's encrypted key,
            // and decrypt it with our private key
            isExchangeKeys = client.exchangeKeys();
        } while (!isExchangeKeys && client.hasRemainingAttempts());

        if (!isExchangeKeys) {
            std::cout << std::endl << "FATAL ERROR:" << std::endl;
            std::cout << "All exchanging keys attempts failed. Errors:" << std::endl;
            std::cout << client.getErrorMessage() << std::endl;
            return 1;
        }

        std::cout << "exchange keys succeeded,"
                     " we send the client's key and received server's key" << std::endl;
    }
    else{
        std::cout << "reconnection succeeded, the client is reconnected" << std::endl;
    }

    client.resetTries();
    do{
        // try to send a file,
        // and to calculate our crc
        // and get calculated crc from the server
        isSentFile = client.sendFile(isInvalidCRC);
    } while (!isSentFile && client.hasRemainingAttempts());

    if (!isSentFile) {
        std::cout << std::endl << "FATAL ERROR:" << std::endl;
        std::cout << "All sending a file attempts failed. Errors:" << std::endl;
        std::cout << client.getErrorMessage() << std::endl;
        return 1;
    }

    if(!isInvalidCRC) {
        std::cout << "sending a file succeeded,"
                     " server received a valid file and responded with a valid CRC" << std::endl;

        client.resetTries();
        do {
            // try to send a message indicating that our crc and the server's crc are equal
            isSentValidCRC = client.sendValidCRC();
        } while (!isSentValidCRC && client.hasRemainingAttempts());

        if (!isSentValidCRC) {
            std::cout << std::endl << "FATAL ERROR:" << std::endl;
            std::cout << "All sending a valid crc attempts failed. Errors:" << std::endl;
            std::cout << client.getErrorMessage() << std::endl;
            return 1;
        }

        std::cout << "sending a valid crc succeeded,"
                     " server responded with a confirmation\n\nEnding with: Accept" << std::endl;
        return 0;
    }

    // resend a file up to 3 times
    for(int attempt = 0, isResentFile; attempt < MAX_RETRIES; attempt++, isAbort = false) {
        std::cout << "On the " << (attempt + 1) << " attempt:" << std::endl
                  << "Sending a file succeeded, "
                     "server received a valid file and responded with an invalid CRC." << std::endl;

        client.resetTries();
        do {
            // try to send a message indicating that our crc and the server's crc are not equal
            isSentInvalidCRC = client.sendInvalidCRC();
        } while (!isSentInvalidCRC && client.hasRemainingAttempts());

        if (!isSentInvalidCRC) {
            std::cout << std::endl << "FATAL ERROR:" << std::endl;
            std::cout << "All attempts for sending an invalid crc failed. Errors:" << std::endl;
            std::cout << client.getErrorMessage() << std::endl;
            return 1;
        }

        std::cout << "sending an invalid crc succeeded,"
                     " server responded with a confirmation" << std::endl;

        client.resetTries();
        do {
            // try to resend the file,
            // and to calculate our crc
            // and get calculated crc from the server
            isResentFile = client.sendFile(isAbort);
        } while (!isResentFile && client.hasRemainingAttempts());

        if (!isResentFile) {
            std::cout << std::endl << "FATAL ERROR:" << std::endl;
            std::cout << "All resending a file attempts failed. Errors:" << std::endl;
            std::cout << client.getErrorMessage() << std::endl;
            return 1;
        }

        if(!isAbort) {
            std::cout << "Resending a file succeeded,"
                         " server received a valid file and responded with a valid CRC" << std::endl;

            client.resetTries();
            do {
                // try to send a message indicating that our crc and the server's crc are equal
                isAccept = client.sendValidCRC();
            } while (!isAccept && client.hasRemainingAttempts());

            if (!isAccept) {
                std::cout << std::endl << "FATAL ERROR:" << std::endl;
                std::cout << "All sending a valid crc attempts failed. Errors:" << std::endl;
                std::cout << client.getErrorMessage() << std::endl;
                return 1;
            }

            std::cout << "sending a valid crc succeeded,"
                         " server responded with a confirmation\n\nEnding with: Accept" << std::endl;
            return 0;
        }
    }

    // finished resending a file three times
    // sending an abort message
    client.resetTries();
    do {
        // try to send a last message indicating that our crc and the server's crc are not equal
        isSentLastCRC = client.sendAbort();
    } while (isSentLastCRC && client.hasRemainingAttempts());

    if(!isSentLastCRC){
        std::cout << std::endl << "FATAL ERROR:" << std::endl;
        std::cout << "All attempts for sending an abort message failed. Errors:" << std::endl;
        std::cout << client.getErrorMessage() << std::endl;
        return 1;
    }

    std::cout << "sending an abort message succeeded,"
                 " server responded with a confirmation.\n\nEnding with: Abort" << std::endl;
    return 1;

}