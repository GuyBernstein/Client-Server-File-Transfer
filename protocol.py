import struct

from enum import Enum

SERVER_VERSION = 3
DEF_VAL = 0  # Default value to initialize inner fields.
HEADER_SIZE = 7  # Header size without clientID. (version, code, payload size).
CLIENT_ID_SIZE = 16
MSG_ID_SIZE = 4
MSG_TYPE_MAX = 0xFF
MSG_ID_MAX = 0xFFFFFFFF
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160


# Request Code
class ERequestCode(Enum):
    REQUEST_REGISTRATION = 825  # uuid ignored.
    # REQUEST_USERS = 1001  # payload invalid. payloadSize = 0.
    # REQUEST_PUBLIC_KEY = 1002
    # REQUEST_SEND_MSG = 1003
    # REQUEST_PENDING_MSG = 1004  # payload invalid. payloadSize = 0.


# Responses Codes
class EResponseCode(Enum):
    RESPONSE_REGISTRATION = 2000
    RESPONSE_USERS = 2001
    RESPONSE_PUBLIC_KEY = 2002
    RESPONSE_MSG_SENT = 2003
    RESPONSE_PENDING_MSG = 2004
    RESPONSE_ERROR = 9000  # payload invalid. payloadSize = 0.


class RequestHeader:
    def __init__(self):
        self.clientID = b""
        self.version = DEF_VAL  # 1 byte
        self.code = DEF_VAL  # 2 bytes
        self.payloadSize = DEF_VAL  # 4 bytes
        self.SIZE = CLIENT_ID_SIZE + HEADER_SIZE

    def unpack(self, data):
        """ Little Endian unpack Request Header """
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            headerData = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + HEADER_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack("<BHL", headerData)
            return True
        except:
            self.__init__()  # reset values
            return False


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION  # 1 byte
        self.code = code  # 2 bytes
        self.payloadSize = DEF_VAL  # 4 bytes
        self.SIZE = HEADER_SIZE

    def pack(self):
        """ Little Endian pack Response Header """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.publicKey = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        if not self.header.unpack(data):
            return False
        try:
            # trim the byte array after the nul terminating character.
            nameData = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = str(struct.unpack(f"<{NAME_SIZE}s", nameData)[0].partition(b'\0')[0].decode('utf-8'))
            keyData = data[self.header.SIZE + NAME_SIZE:self.header.SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", keyData)[0]
            return True
        except:
            self.name = b""
            self.publicKey = b""
            return False


class RegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RESPONSE_REGISTRATION.value)
        self.clientID = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""
