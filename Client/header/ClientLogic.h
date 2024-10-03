//
// Created by גאי ברנשטיין on 20/09/2024.
//

#ifndef CLIENT_CLIENTLOGIC_H
#define CLIENT_CLIENTLOGIC_H

#include "protocol.h"
#include "FileHandle.h"
#include "CSocketHandler.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "Chksum.h"
#include "AESWrapper.h"
#include <sstream>
#include <string>
#include <vector>

constexpr auto KEY_INFO = "priv.key";   // Should be created near the exe file's location.
constexpr auto CLIENT_INFO = "me.info";   // Should be created near the exe file's location.
constexpr auto SERVER_INFO = "transfer.info";  // Should be located near the exe file.

class ClientLogic
{
public:

    struct SClient
    {
        Uuid                         id;
        ClientName                   userName = {};
        FileName                     fileName = {};
        DecryptedContentSize         fileSize;
        std::string                  privateKey = {};
        AESKey                       aesKey = {};
        bool                         _registered = false;
    };

    ClientLogic();

    // Rule of five
    virtual ~ClientLogic() = default;
    ClientLogic(const ClientLogic& other) = delete;
    ClientLogic(ClientLogic&& other) noexcept = delete;
    ClientLogic& operator=(const ClientLogic& other) = delete;
    ClientLogic& operator=(ClientLogic&& other) noexcept = delete;

    // protocol operations
    void initialize(bool &isReconnect);
    bool registerClient();
    bool sendPublicKey();
    bool reconnectClient();
    bool sendEncryptedFileAndCorrespondedCRC(bool &isInvalidCRC);
    bool sendCRCMessage(const ERequestCode code);

    // inline getters
    std::string getLastError() const { return _lastError.str(); }
    bool isRegistered() const{ return _self._registered;};

private:
    SClient                               _self;
    std::stringstream                     _lastError;
    std::unique_ptr<FileHandle>           _fileHandle;
    std::unique_ptr<CSocketHandler>       _socketHandler;
    RSAPrivateWrapper                     _rsaPrivateWrapper;

    // private methods
    bool parseInfo();
    void closeFile();
    void clearLastError();
    bool storeClientInfo();
    bool validateHeader(const SResponseHeader &header, EResponseCode expectedCode);
    bool isFileEmptyAndOpen(const std::string &filePath);
    void clientStop() const;
};

#endif //CLIENT_CLIENTLOGIC_H
