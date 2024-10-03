//
// Created by גאי ברנשטיין on 20/09/2024.
//
#include "ClientLogic.h"

ClientLogic::ClientLogic() :
    _fileHandle(std::make_unique<FileHandle>()) , _socketHandler(std::make_unique<CSocketHandler>()),
    _rsaPrivateWrapper(RSAPrivateWrapper()) {}

/**
 * Parses each info file correspondingly to the protocol, and initialize the connection with the server
 */
void ClientLogic::initialize(bool &isReconnect) {
    // first, we check if there's me.info for connecting with the client.
    if (isFileEmptyAndOpen(CLIENT_INFO)) {
        _self._registered = true; // so we'll know which file to parse
        isReconnect = true; // for knowing which way to proceed after reconnection (no need for exchanging keys again)

        // lastly, we parse the me.info for reconnection
        if (!parseInfo())
            clientStop();
        return ; // successfully parsed info
    }

    // CLIENT_INFO doesn't exist.
    // first, we check for transfer.info in case the client isn't registered yet
    if (!isFileEmptyAndOpen(SERVER_INFO)) {
        clientStop();
    }

    // lastly, we parse the transfer.info for registration
    if (!parseInfo())
        clientStop();
}

/**
 * Register the client with the server
 */
bool ClientLogic::registerClient() {
    SRequestConnection request(_self.userName,REGISTRATION);
    SResponseClientID response;

    // Serialize the request
    std::vector<uint8_t> serializedRequest(
            reinterpret_cast<const uint8_t*>(&request),
            reinterpret_cast<const uint8_t*>(&request) + sizeof(request));

    // Prepare response vector
    std::vector<uint8_t> responseData;

    // Send request and receive response
    if (!_socketHandler->communicate(serializedRequest, responseData, sizeof(response)))
    {
        clearLastError();
        _lastError << "Failed communicating with server on " << _socketHandler;
        return false;
    }

    // Deserialize the response
    std::memcpy(&response, responseData.data(), sizeof(SResponseClientID));

    if(!validateHeader(response.header, REGISTRATION_SUCCEEDED))
        return false;

    // store received client's ID
    std::copy_n(response.payload.begin(),CLIENT_ID_SIZE, _self.id.begin());

    return true;
}

/**
 * Send the the public key to the server
 */
bool ClientLogic::sendPublicKey() {
    SRequestSendPublicKey request(_self.id, _self.userName);
    SResponseAESKey response;

    // create a public key
    std::string publicKey;
    try {
        publicKey = _rsaPrivateWrapper.getPublicKey();
    } catch (CryptoPP::Exception& e){
        clearLastError();
        _lastError << "Exception occurred while generating public key";
        return false;
    }

    if (publicKey.size() != RSA_KEY_SIZE) {
        clearLastError();
        _lastError << "Invalid public key length!";
        return false;
    }

    // store the private key in the request
    std::memcpy(&request.payload.clientPublicKey, publicKey.c_str(), sizeof(request.payload.clientPublicKey));

    // create a private key with base 64 encoded
    std::string privateKey;
    try {
        privateKey = _rsaPrivateWrapper.getPrivateKey();
    } catch (CryptoPP::Exception& e){
        clearLastError();
        _lastError << "Exception occurred while generating private key";
        return false;
    }
    _self.privateKey = Base64Wrapper::encode(privateKey);

    // Serialize the request
    std::vector<uint8_t> serializedRequest = std::vector<uint8_t>(
            reinterpret_cast<const uint8_t *>(&request),
            reinterpret_cast<const uint8_t *>(&request) + sizeof(request));

    // send request and receive response
    std::vector<uint8_t> responseData;

    if (!_socketHandler->communicate(serializedRequest, responseData, sizeof(response)))
    {
        clearLastError();
        _lastError << "Failed communicating with server on " << _socketHandler;
        return false;
    }

    // Deserialize the response
    std::memcpy(&response, responseData.data(), sizeof(SResponseAESKey));

    if(!validateHeader(response.header, RECEIVED_PUBLIC_KEY_AND_SENDING_AES))
        return false;

    try {
        // Generate decrypted key from response's aes key using rsa decryption with our private key
        std::string decryptedAESKey = _rsaPrivateWrapper.decrypt(
                reinterpret_cast<const char *>(response.payload.serverAESKey.data()),
                DECRYPTED_AES_KEY_SIZE);

        // Store it for encrypting a file later
        std::copy_n(decryptedAESKey.begin(),AES_KEY_SIZE, _self.aesKey.begin());
    } catch(std::length_error& e){
        clearLastError();
        _lastError << "AES key length error: " << e.what();
        return false;
    } catch(CryptoPP::Exception& e ){
        clearLastError();
        _lastError << "Exception occurred while decrypting key: " << e.what();
        return false;
    }

    // we store the username, UUID (that we have from the registration),
    // and the private key into the CLIENT_INFO and KEY_INFO files.
    return storeClientInfo();
}

/**
 * Reconnect to the server, we dont need to exchange keys this time
 */
bool ClientLogic::reconnectClient() {
    SRequestConnection request(_self.id, _self.userName, RECONNECTION);
    SResponseAESKey response;

    // Serialize the request
    std::vector<uint8_t> serializedRequest = std::vector<uint8_t>(
            reinterpret_cast<const uint8_t *>(&request),
            reinterpret_cast<const uint8_t *>(&request) + sizeof(request));

    // send request and receive response's header
    std::vector<uint8_t> responseData;
    if (!_socketHandler->communicate(serializedRequest, responseData, sizeof(response)))
    {
        clearLastError();
        _lastError << "Failed communicating with server on " << _socketHandler;
        return false;
    }

    // Deserialize the response
    std::memcpy(&response, responseData.data(), sizeof(SResponseAESKey));

    if(!validateHeader(response.header, APPROVED_REQUEST_TO_RECONNECT_SENDING_AES)) {
        return false;
    }

    if(response.payload.clientId != _self.id)
    {
        clearLastError();
        _lastError << "Received a response with client id not the same as it was when registered";
        return false;
    }
    try {
        // Generate a rsa key from the response's aes key using rsa decryption,
        // with the private key we have from the first run after we decode it from base 64
        RSAPrivateWrapper registeredRsaKey(Base64Wrapper::decode(_self.privateKey));

        // Decrypt the aes key
        std::string decryptedAESKey = registeredRsaKey.decrypt(
                reinterpret_cast<const char *>(response.payload.serverAESKey.data()),
                response.payload.serverAESKey.size());

        // Store it for encrypting a file later
        std::copy_n(decryptedAESKey.begin(),AES_KEY_SIZE, _self.aesKey.begin());
    } catch(std::length_error& e){
        clearLastError();
        _lastError << "AES key length error: " << e.what();
        return false;
    } catch(CryptoPP::Exception& e ){
        clearLastError();
        _lastError << "Exception occurred while decrypting key: " << e.what();
        return false;
    }
    return true;
}

/**
 * Send a file to the server, its encrypted with the aes key the server has sent to us.
 */
bool ClientLogic::sendEncryptedFileAndCorrespondedCRC(bool &isInvalidCRC) {
    // get the file name from our std::array into a std::string
    std::string fileName(_self.fileName.begin(), _self.fileName.end());

    // get the crc from the given code in unit 7, and the file content, match to our flow
    std::string messageContent;
    CRC crc;
    if(!Chksum::readFile(fileName, messageContent, crc, _self.fileSize))
    {
        clearLastError();
        _lastError << "Was unable to read from file: " << fileName;
        return false;
    }

    // Handle for large files
    if(messageContent.length() > std::numeric_limits<uint16_t>::max())
    {
        clearLastError();
        _lastError << "content of the file (" << fileName << ") is larger than ("
                   <<  std::numeric_limits<uint16_t>::max() << ")";
        return false;
    }

    // Generate an aes key and encrypt file's content
    AESWrapper aesKey = AESWrapper(_self.aesKey);
    messageContent = aesKey.encrypt(messageContent);

    // Calculate how many chunks fits in the total message content
    auto totalPackets = (totalMessageCount)((messageContent.length() + CHUNK_SIZE - 1) / CHUNK_SIZE);

    // initialize a request and a response
    SRequestSendFile request(_self.id, _self.fileName, (DecryptedContentSize)_self.fileSize,
                             (EncryptedContentSize)messageContent.length(), totalPackets);
    SResponseReceivedValidFileWithCRC response;


    
    // send request and receive response for each communication with the server,
    // validating received a message.
    csize_t serializedSize;
    std::vector<uint8_t> serializedRequest;
    std::vector<uint8_t> responseData;

    // iterate through each packet by sending it to the server.
    while(request.payload.packets.packetNumber <= request.payload.packets.totalPackets) {
        // Calculate the offset in the request for the current packet
        DecryptedContentSize offset = (request.payload.packets.packetNumber - 1) * CHUNK_SIZE;

        // get the sub message
        csize_t subMessageSize = std::min(request.payload.contentSize - offset, CHUNK_SIZE);
        std::string subMessage = messageContent.substr(offset, subMessageSize);

        // save the current encrypted chunk
        request.payload.messageContent.fill(0); // reset previous chunks
        std::copy_n(subMessage.begin(), subMessageSize, request.payload.messageContent.begin());
        csize_t payloadSize = request.setPayloadSize(subMessageSize);

        // Calculate the clean size of the current chunk
        serializedSize = sizeof(SRequestHeader) + payloadSize;

        // Serialize the current state of the request
        serializedRequest.assign(reinterpret_cast<const uint8_t *>(&request),
                                 reinterpret_cast<const uint8_t *>(&request) + serializedSize);

        // send a serialized request and received a thank-you message, until the last packet sent
        if (!_socketHandler->communicate(serializedRequest, responseData, sizeof(response))) {
            clearLastError();
            _lastError << "Failed communicating with server on " << _socketHandler;
            return false;
        }

        // Deserialize the response
        std::memcpy(&response, responseData.data(), sizeof(response));

        // Should be response of a received message
        if (request.payload.packets.packetNumber < request.payload.packets.totalPackets) {
            if (!validateHeader(response.header, APPROVED_GETTING_MESSAGE_THANKS)) {
                return false;
            }
        }
        else {
            // Handle the last packet received from the server
            if (!validateHeader(response.header, FILE_RECEIVED_PROPERLY_WITH_CRC)) {
                return false;
            }
        }

        if(response.payload.clientId != _self.id)
        {
            clearLastError();
            _lastError << "Received a response with client id not the same as it was when sent file";
            return false;
        }

        // Increment the packet number for the next iteration
        request.payload.packets.packetNumber++;
    }

    if(response.payload.contentSize != request.payload.contentSize)
    {
        clearLastError();
        _lastError << "Received a response with content size not the same as it was when sent file";
        return false;
    }

    if(response.payload.fileName != _self.fileName)
    {
        clearLastError();
        _lastError << "Received a response with file name"  << std::endl
                   <<"    Not the same as it was when sent file (" << fileName << ")";
        return false;
    }

    // now we only need to validate crc in the next protocol operations
    if(response.payload.cksum != crc)
        isInvalidCRC = true;

    return true;
}

/**
 * Send a message to the server, with its corresponding crc validation,
 * receiving a thank-you response in case of success
 */
bool ClientLogic::sendCRCMessage(const ERequestCode code) {
    SendMessage request(_self.id, _self.fileName, code);
    SResponseClientID response;

    // Serialize the request
    std::vector<uint8_t> serializedRequest =
            std::vector<uint8_t>(
                    reinterpret_cast<const uint8_t *>(&request),
                    reinterpret_cast<const uint8_t *>(&request) + sizeof(request));

    // send request and receive response's header
    std::vector<uint8_t> responseData;
    if (!_socketHandler->communicate(serializedRequest, responseData, sizeof(response)))
    {
        clearLastError();
        _lastError << "Failed communicating with server on " << _socketHandler;
        return false;
    }

    // Deserialize the response
    std::memcpy(&response, responseData.data(), sizeof(response));

    if(!validateHeader(response.header, APPROVED_GETTING_MESSAGE_THANKS)) {
        return false;
    }

    if(response.payload != _self.id)
    {
        clearLastError();
        _lastError << "Received a response with client id not the same as it was when registered";
        return false;
    }
    return true;
}

/**
 * Parse SERVER_INFO file for client name, server address & port and file name.
 * Parse CLIENT_INFO, in case it exists, for uuid and client name
 * Parse KEY_INFO, if it and CLIENT_INFO exists, for private key
 */
bool ClientLogic::parseInfo() {
    std::string address;
    std::string port;
    std::string line;
    if(!_self._registered) { // we are parsing transfer.info file
        // read- & parse-first line (address:port)
        if (!_fileHandle->readLine(line))
        {
            clearLastError();
            _lastError << "Couldn't read the first line from " << SERVER_INFO;
            return false;
        }

        Base64Wrapper::trim(line);
        const auto pos = line.find(':');
        if (pos == std::string::npos) {
            clearLastError();
            _lastError << SERVER_INFO <<" has invalid format! missing separator ':' in address:port";
            closeFile();
            return false;
        }
        address = line.substr(0, pos);
        port = line.substr(pos + 1);

        if (!_socketHandler->setSocketInfo(address, port))
        {
            clearLastError();
            _lastError << SERVER_INFO << " has invalid IP address or port!";
            closeFile();
            return false;
        }

        // read and parse the second line (userName)
        if (!_fileHandle->readLine(line)) {
            clearLastError();
            _lastError << "Couldn't read second line from " << SERVER_INFO;
            return false;
        }

        Base64Wrapper::trim(line);
        if (line.length() > CLIENT_ACTUALNAME_SIZE) {
            clearLastError();
            _lastError << "Invalid userName in " << SERVER_INFO << ". Must be 1-100 characters";
            closeFile();
            return false;
        }

        if (!std::all_of(line.begin(), line.end(),
                         [](unsigned char ch) {return std::isalnum(ch) || std::isspace(ch);})) {
            clearLastError();
            _lastError << "Invalid userName in " << SERVER_INFO
                       << " Username may only contain letters, numbers, and spaces!";
            closeFile();
            return false;
        }
        std::copy_n(line.begin(), line.length(), _self.userName.begin());

        // read and parse the third line (filepath)
        if (!_fileHandle->readLine(line)) {
            clearLastError();
            _lastError << "Couldn't read third line from " << SERVER_INFO;
            return false;
        }
        closeFile();

        // validate file name
        if (!isFileEmptyAndOpen(line))
            return false;

        if(line.length() > FILE_NAME_SIZE) {
            clearLastError();
            _lastError << "Invalid file name in " << SERVER_INFO << " File " << line
                       << " can't be more than " << FILE_NAME_SIZE;
            closeFile();
            return false;
        }
        _self.fileSize = _fileHandle->size(); // save the original file's size
        closeFile();

        std::copy_n(line.begin(),line.length(),_self.fileName.begin()); // save file name
        return true;
    }
    // is_registered is false

    // here we will parse the "me.info"
    // read- & parse-first line (userName)
    if (!_fileHandle->readLine(line))
    {
        clearLastError();
        _lastError << "Couldn't read first line from " << CLIENT_INFO;
        return false;
    }

    Base64Wrapper::trim(line);
    if (line.length() > CLIENT_ACTUALNAME_SIZE) {
        clearLastError();
        _lastError << "Invalid userName in " << CLIENT_INFO << ". Must be 1-100 characters";
        closeFile();
        return false;
    }

    if (!std::all_of(line.begin(), line.end(),
                     [](unsigned char ch) {return std::isalnum(ch) || std::isspace(ch);})) {
        clearLastError();
        _lastError << "Invalid userName in " << CLIENT_INFO
                   << " Username may only contain letters, numbers, and spaces!";
        return false;
    }
    std::copy_n(line.begin(), line.length(), _self.userName.begin());

    // read and parse the second line (uuid)
    if (!_fileHandle->readLine(line)) {
        clearLastError();
        _lastError << "Couldn't read second line from " << CLIENT_INFO;
        return false;
    }
    closeFile(); // finished reading from this file

    Base64Wrapper::trim(line);
    line = Base64Wrapper::unhex(line);
    if (line.length() != CLIENT_ID_SIZE) {
        clearLastError();
        _lastError << "Invalid uuid in " << CLIENT_INFO
                   << " uuid should be sized: " << CLIENT_ID_SIZE;
        return false;
    }
    std::copy_n(line.begin(), CLIENT_ID_SIZE, _self.id.begin());

    // read and parse (private key) but this time from the file "priv.key" as instructed in the protocol
    if(!isFileEmptyAndOpen(KEY_INFO))
        return false;

    bool isWholeFile;
    if (!_fileHandle->readChunk(line, PRIVATE_KEY_SIZE_BASE64, isWholeFile)) {
        clearLastError();
        _lastError << "Couldn't read private key from " << KEY_INFO;
        closeFile();
        return false;
    }
    closeFile(); // finished reading from this file

    if(!isWholeFile && line.length() != PRIVATE_KEY_SIZE_BASE64)
    {
        clearLastError();
        _lastError << "Private key in " << KEY_INFO << " is longer than " << PRIVATE_KEY_SIZE_BASE64 << " bits";
        return false;
    }
    _self.privateKey = line;

    // lastly, we parse socket info for reconnection
    if(!isFileEmptyAndOpen(SERVER_INFO))
        return false;

    // read- & parse-first line (address:port)
    if (!_fileHandle->readLine(line))
    {
        clearLastError();
        _lastError << "Couldn't read the first line from " << SERVER_INFO;
        return false;
    }

    Base64Wrapper::trim(line);
    const auto pos = line.find(':');
    if (pos == std::string::npos) {
        clearLastError();
        _lastError << SERVER_INFO <<" has invalid format! missing separator ':' in address:port";
        closeFile();
        return false;
    }
    address = line.substr(0, pos);
    port = line.substr(pos + 1);

    if (!_socketHandler->setSocketInfo(address, port))
    {
        clearLastError();
        _lastError << SERVER_INFO << " has invalid IP address or port!";
        return false;
    }

    // read username
    if (!_fileHandle->readLine(line))
    {
        clearLastError();
        _lastError << "Couldn't read the second line from " << SERVER_INFO;
        return false;
    }

    // skip handling,
    // we have already the username, now we just read the third line(file path)
    if (!_fileHandle->readLine(line)) {
        clearLastError();
        _lastError << "Couldn't read third line from " << SERVER_INFO;
        return false;
    }
    closeFile(); // finished reading from this file

    // try to open the file name
    if (!isFileEmptyAndOpen(line))
        return false;

    // check if the file path is valid
    if(line.length() > FILE_NAME_SIZE) {
        clearLastError();
        _lastError << "Invalid file name in " << SERVER_INFO << " File " << line
                   << " can't be more than " << FILE_NAME_SIZE;
        closeFile();
        return false;
    }

    // store and validate if the file is too large
    csize_t size;
    if((size = _fileHandle->size()) > std::numeric_limits<uint16_t>::max())
    {
        clearLastError();
        _lastError << "Encrypted content of the file (" << line << ")larger than ("
                   <<  std::numeric_limits<uint16_t>::max() << ")";
        return false;
    }
    _self.fileSize = size;
    closeFile();

    // save file name
    std::copy_n(line.begin(),line.length(),_self.fileName.begin());
    return true;
}


bool ClientLogic::validateHeader(const SResponseHeader &header, const EResponseCode expectedCode) {
    csize_t expectedSize = 0;

    switch (header.code)
    {
        case REGISTRATION_SUCCEEDED:
        {
            expectedSize = sizeof(SResponseClientID) - sizeof(SResponseHeader);
            break;
        }
        case REGISTRATION_FAILED:
        {
            clearLastError();
            _lastError << "Registration error response code (" << REGISTRATION_FAILED << ") received.";
            return false;
        }
        case RECEIVED_PUBLIC_KEY_AND_SENDING_AES:
        case APPROVED_REQUEST_TO_RECONNECT_SENDING_AES:
        {
            expectedSize = sizeof(SResponseAESKey) - sizeof(SResponseHeader);
            break;
        }
        case REQUEST_FOR_RECONNECTION_DENIED:
        {
            clearLastError();
            _lastError << "Reconnection error response code ("
                       << REQUEST_FOR_RECONNECTION_DENIED << ") received. client needs to register again";
            return false;
        }

        case FILE_RECEIVED_PROPERLY_WITH_CRC:
        {
            expectedSize = sizeof(SResponseReceivedValidFileWithCRC) - sizeof(SResponseHeader);
            break;
        }

        case APPROVED_GETTING_MESSAGE_THANKS:
        {
            expectedSize = sizeof(Uuid);
            break;
        }

        case GENERIC_ERROR:
        {
            clearLastError();
            _lastError << "Generic error response code (" << GENERIC_ERROR << ") received.";
            return false;
        }
    }

    if(header.code != expectedCode)
    {
        clearLastError();
        _lastError << "Unexpected response code (" << header.code << ") received. was expecting ("
                   << expectedCode << ") response code.";
        return false;
    }

    if (header.payloadSize != expectedSize)
    {
        clearLastError();
        _lastError << "Unexpected payload size " << header.payloadSize << ". Expected size was " << expectedSize;
        return false;
    }

    return true;
}


/**
 * Store username, uuid and private key in CLIENT_INFO
 * Store private key in KEY_INFO
 */
bool ClientLogic::storeClientInfo() {
    _fileHandle = std::make_unique<FileHandle>();
    if (!_fileHandle->open(CLIENT_INFO, true))
    {
        clearLastError();
        _lastError << "Couldn't open " << CLIENT_INFO;
        return false;
    }

    // Write userName
    if (!_fileHandle->writeLine(_self.userName))
    {
        clearLastError();
        _lastError << "Couldn't write userName to " << CLIENT_INFO;
        return false;
    }

    // Write UUID.
    std::string line(_self.id.begin(),_self.id.end());
    const auto hexifiedUuid = Base64Wrapper::hex(_self.id, sizeof(_self.id));
    if (!_fileHandle->writeLine(hexifiedUuid))
    {
        clearLastError();
        _lastError << "Couldn't write UUID to " << CLIENT_INFO;
        closeFile();
        return false;
    }

    // Write Base64 encoded private key
    if (!_fileHandle->write(_self.privateKey))
    {
        clearLastError();
        _lastError << "Couldn't write client's private key to " << CLIENT_INFO;
        closeFile();
        return false;
    }
    closeFile();

    // we finished writing userName, uuid and private key into "me.info" file,
    // and now writing the private key additionally into "priv.key" file
    _fileHandle = std::make_unique<FileHandle>();
    if (!_fileHandle->open(KEY_INFO, true))
    {
        clearLastError();
        _lastError << "Couldn't open " << KEY_INFO;
        return false;
    }

    if (!_fileHandle->write(_self.privateKey))
    {
        clearLastError();
        _lastError << "Couldn't write client's private key to " << KEY_INFO;
        closeFile();
        return false;
    }

    closeFile();
    return true;
}


void ClientLogic::closeFile() {
    if (_fileHandle) {
        _fileHandle->close();
        _fileHandle.reset();
    }
}

bool ClientLogic::isFileEmptyAndOpen(const std::string &filePath) {
    _fileHandle = std::make_unique<FileHandle>();
    if (!_fileHandle->open(filePath))
    {
        clearLastError();
        _lastError << "Couldn't open file: " << filePath;
        return false;
    }
    if(_fileHandle->size() == 0){
        clearLastError();
        _lastError << "The file is empty: " << filePath;
        closeFile();
        return false;
    }
    return true;
}

void ClientLogic::clearLastError() {
    const std::stringstream clean;
    _lastError.str("");
    _lastError.clear();
    _lastError.copyfmt(clean);
}

void ClientLogic::clientStop() const {
    std::cout << "Fatal Error from client side: " << getLastError() << std::endl;
    exit(1); // end program
}
