//
// Created by גאי ברנשטיין on 21/09/2024.
//

#ifndef CLIENT_PROTOCOL_H
#define CLIENT_PROTOCOL_H
#pragma once
#include <cstdint>
#include <string_view>
#include <array>
#include "RSAWrapper.h"

enum {
    DEF_VAL = 0,
    FIRST_TRY = 1,
    MAX_RETRIES = 3
};  // Default value

// Common types
typedef uint32_t csize_t;  // protocol's size type: Content's, payload's and message's size.
typedef uint8_t  version_t;
typedef uint16_t code_t;
typedef uint32_t EncryptedContentSize;
typedef uint32_t DecryptedContentSize;
typedef uint16_t currentMessageNum;
typedef uint16_t totalMessageCount;
typedef uint32_t CRC;

// Constants. All sizes are in BYTES.
constexpr csize_t    PACKET_SIZE             = 1024;   // Better be the same on the server side.
constexpr version_t  CLIENT_VERSION          = 3;
constexpr csize_t    CLIENT_ID_SIZE          = 16;
constexpr csize_t    CLIENT_ACTUALNAME_SIZE  = 100;
constexpr csize_t    CLIENT_NAME_SIZE        = 255;
constexpr csize_t    FILE_NAME_SIZE          = 255;
constexpr csize_t    RSA_KEY_SIZE            = RSAPublicWrapper::KEYSIZE; // 160
constexpr csize_t    DECRYPTED_AES_KEY_SIZE  = 128;
constexpr csize_t    AES_KEY_SIZE            = 16;
constexpr csize_t    PRIVATE_KEY_SIZE_BASE64 = 856; // the original size was 1024 then changed in CryptoPP and encoded
constexpr csize_t    CHUNK_SIZE              = 734;  // 1024 - sizeof(RequestSendFile) + messageContent

#define DEFINE_ARRAY(NAME, SIZE) \
typedef std::array<uint8_t, SIZE> NAME;

DEFINE_ARRAY(ClientName, CLIENT_NAME_SIZE)
DEFINE_ARRAY(PublicKey, RSA_KEY_SIZE)
DEFINE_ARRAY(Uuid, CLIENT_ID_SIZE)
DEFINE_ARRAY(FileName, FILE_NAME_SIZE)
DEFINE_ARRAY(DecryptedAESKey, DECRYPTED_AES_KEY_SIZE)
DEFINE_ARRAY(AESKey, AES_KEY_SIZE)
DEFINE_ARRAY(MessageContent, CHUNK_SIZE)


enum ERequestCode
{
    REGISTRATION   =                 825, // uuid ignored.
    SENDING_PUBLIC_KEY =             826,
    RECONNECTION =                   827,
    SENDING_FILE =                   828,
    CRC_VALID =                      900,
    CRC_INVALID_SENDING_AGAIN =      901,
    CRC_INVALID_FORTH_TIME_IM_DONE = 902
};

enum EResponseCode
{
    REGISTRATION_SUCCEEDED                      = 1600,
    REGISTRATION_FAILED                         = 1601,
    RECEIVED_PUBLIC_KEY_AND_SENDING_AES         = 1602,
    FILE_RECEIVED_PROPERLY_WITH_CRC             = 1603,
    APPROVED_GETTING_MESSAGE_THANKS             = 1604,
    APPROVED_REQUEST_TO_RECONNECT_SENDING_AES   = 1605, // table identical to code 1602
    REQUEST_FOR_RECONNECTION_DENIED             = 1606, // client's not registered, or invalid public key
    GENERIC_ERROR                               = 1607  // payload invalid. payloadSize = 0.
};

#pragma pack(push, 1)

struct SRequestHeader
{
    Uuid            clientId = {};
    const version_t version;
    const code_t    code;
    csize_t         payloadSize;


    SRequestHeader(const code_t reqCode, const csize_t payloadSize) :
                    version(CLIENT_VERSION), code(reqCode), payloadSize(payloadSize) {}
    SRequestHeader(const Uuid& id, const code_t reqCode) :
                    version(CLIENT_VERSION), code(reqCode), payloadSize(DEF_VAL){
        // store received client's ID
        std::copy_n(id.begin(),CLIENT_ID_SIZE, clientId.begin());
    };
    SRequestHeader(const Uuid& id, const code_t reqCode, const csize_t payloadSize) :
                    version(CLIENT_VERSION),code(reqCode), payloadSize(payloadSize) {
        // store received client's ID
        std::copy_n(id.begin(),CLIENT_ID_SIZE, clientId.begin());
    }
};



struct SResponseHeader
{
    version_t version;
    code_t    code;
    csize_t   payloadSize;
    SResponseHeader() : version(DEF_VAL), code(DEF_VAL), payloadSize(DEF_VAL) {}
};

struct SRequestConnection
{
    SRequestHeader header;
    ClientName clientName = {};

    // constructor for registration
    SRequestConnection(const ClientName& cName,ERequestCode code) :
                       header(code, CLIENT_NAME_SIZE) {
        std::copy_n(cName.begin(),CLIENT_NAME_SIZE, clientName.begin());
    }
    // constructor for reconnection
    SRequestConnection(const Uuid& id, const ClientName& cName, ERequestCode code) :
                       header(id, code, CLIENT_NAME_SIZE) {
        std::copy_n(cName.begin(),CLIENT_NAME_SIZE, clientName.begin());
    }
};

struct SResponseClientID
{
    SResponseHeader header;
    Uuid            payload = {};
};

struct SRequestSendPublicKey
{
    SRequestHeader header;
    struct
    {
        ClientName clientName = {};
        PublicKey  clientPublicKey = {};
    }payload;
    SRequestSendPublicKey(const Uuid& id, const ClientName& cName) :
                          header(id, SENDING_PUBLIC_KEY, CLIENT_NAME_SIZE + RSA_KEY_SIZE) {
        // store received client's name
        std::copy_n(cName.begin(),CLIENT_NAME_SIZE, payload.clientName.begin());
    }
};

struct SResponseAESKey
{
    SResponseHeader header;
    struct
    {
        Uuid   clientId = {};
        DecryptedAESKey serverAESKey = {};
    }payload;
};


struct SRequestSendFile
{
    SRequestHeader header;
    struct
    {
        EncryptedContentSize contentSize = DEF_VAL;
        DecryptedContentSize origFileSize = DEF_VAL;
        struct
        {
            currentMessageNum packetNumber = DEF_VAL;
            totalMessageCount totalPackets = DEF_VAL;
        }packets;
        FileName fileName = {};
        MessageContent  messageContent = {};
    }payload;
    SRequestSendFile(const Uuid &id, const FileName &fName, const DecryptedContentSize originalFileSize,
                     const EncryptedContentSize encryptedFileSize, const totalMessageCount totalPackets) :
                     header(id, SENDING_FILE){
        payload.origFileSize = originalFileSize;
        payload.contentSize = encryptedFileSize;
        payload.packets.packetNumber = FIRST_TRY;
        payload.packets.totalPackets = totalPackets;
        // store file name
        std::copy_n(fName.begin(),FILE_NAME_SIZE, payload.fileName.begin());
    }
    csize_t setPayloadSize(csize_t messageSize){
        csize_t size = 0;
        size += sizeof(payload.contentSize);
        size += sizeof(payload.origFileSize);
        size += sizeof(payload.packets);
        size += sizeof(payload.fileName);
        size += messageSize;
        return (header.payloadSize = size); // assign payload size and return it
    }
};

struct SResponseReceivedValidFileWithCRC
{
    SResponseHeader header;
    struct
    {
        Uuid   clientId = {};
        EncryptedContentSize contentSize = {};
        FileName fileName = {};
        CRC cksum = DEF_VAL;
    }payload;
};

struct SendMessage{
    SRequestHeader header;
    FileName fileName = {};
    SendMessage(const Uuid& id, const FileName& fName, const ERequestCode code) :
            header(id, code, FILE_NAME_SIZE) {
        // store file name
        std::copy_n(fName.begin(),FILE_NAME_SIZE, fileName.begin());
    }
};

#pragma pack(pop)
#endif //CLIENT_PROTOCOL_H
