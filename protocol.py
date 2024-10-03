import struct

from enum import Enum

SERVER_VERSION = 3
DEF_VAL = 0  # Default value to initialize inner fields.
HEADER_WITHOUT_CLIENT_ID = 7  # Header size without client ID.(version, code, payload size).
CLIENT_ID_SIZE = 16
HEADER_SIZE = CLIENT_ID_SIZE + HEADER_WITHOUT_CLIENT_ID
ACTUAL_NAME_SIZE = 100
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
PACKET_SIZE = 1024  # Default packet size.
MAX_QUEUED_CONN = 5  # Default maximum number of queued connections.
CONTENT_SIZE = 4
ORIG_FILE_SIZE = 4
PACKET_NUMBER_SIZE = 2
TOTAL_PACKETS_SIZE = 2
FILE_NAME_SIZE = 255
CHUNK_SIZE = 32
CRC_SIZE = 4


# Request Code
class ERequestCode(Enum):
    REGISTRATION = 825  # uuid ignored.
    SENDING_PUBLIC_KEY = 826
    RECONNECTION = 827
    SENDING_FILE = 828
    CRC_VALID = 900
    CRC_INVALID_SENDING_AGAIN = 901
    CRC_INVALID_FORTH_TIME_IM_DONE = 902


# Responses Codes
class EResponseCode(Enum):
    REGISTRATION_SUCCEEDED = 1600
    REGISTRATION_FAILED = 1601
    RECEIVED_PUBLIC_KEY_AND_SENDING_AES = 1602
    FILE_RECEIVED_PROPERLY_WITH_CRC = 1603
    APPROVED_GETTING_MESSAGE_THANKS = 1604
    APPROVED_REQUEST_TO_RECONNECT_SENDING_AES = 1605  # table identical to code 1602
    REQUEST_FOR_RECONNECTION_DENIED = 1606  # client is not registered, or invalid public key
    GENERIC_ERROR = 1607  # payload invalid. payloadSize = 0.


class RequestHeader:
    def __init__(self):
        self.client_id = b""
        self.version = DEF_VAL  # 1 byte
        self.code = DEF_VAL  # 2 bytes
        self.payload_size = DEF_VAL  # 4 bytes

    def unpack(self, data):
        """ Little Endian unpack Request Header """
        try:
            self.client_id = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            headerData = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + HEADER_WITHOUT_CLIENT_ID]
            self.version, self.code, self.payload_size = struct.unpack("<BHL", headerData)
            return True
        except:
            self.__init__()  # reset values
            return False

    def __eq__(self, other):
        if isinstance(other, RequestHeader):
            return (self.client_id == other.client_id and self.version == other.version and
                    self.code == other.code and self.payload_size == other.payload_size)
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        print("self.id: ", self.client_id)
        print("self.version: ", self.version)
        print("self.code: ", self.code)
        print("self.payload_size: ", self.payload_size)
        return ""


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION  # 1 byte
        self.code = code  # 2 bytes
        self.payload_size = DEF_VAL  # 4 bytes

    def pack(self):
        """ Little Endian pack Response Header """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payload_size)
        except:
            return b""


class ConnectionRequest:
    def __init__(self, request_header):
        self.header = request_header
        self.name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        try:
            name_data = data[HEADER_SIZE:HEADER_SIZE + NAME_SIZE]
            self.name = str(struct.unpack(
                f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.__init__(b"")
            return False


class ResponseClientID:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.REGISTRATION_SUCCEEDED.value)
        self.client_ID = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_ID)
            return data
        except:
            return b""


class SendingPublicKey:
    def __init__(self, request_header):
        self.header = request_header
        self.name = b""
        self.public_key = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        try:
            name_data = data[HEADER_SIZE:HEADER_SIZE + NAME_SIZE]
            self.name = str(struct.unpack(
                f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8'))

            key_data = data[HEADER_SIZE + NAME_SIZE:HEADER_SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.public_key = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", key_data)[0]
            return True
        except:
            self.__init__(b"")
            return False


class ResponseEncryptedAES:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.RECEIVED_PUBLIC_KEY_AND_SENDING_AES.value)
        self.client_ID = b""
        self.aes_key = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_ID)
            data += struct.pack(f"<{len(self.aes_key)}s", self.aes_key)
            return data
        except:
            return b""


class RequestSendingFile:
    class Packets:
        def __init__(self):
            self.packet_number = DEF_VAL
            self.total_packets = DEF_VAL

    def __init__(self):
        self.header = RequestHeader()
        self.content_size = b""
        self.orig_file_size = b""
        self.packets = RequestSendingFile.Packets()
        self.file_name = b""
        self.message_content = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        try:
            # we use offset to get past each field
            if not self.header.unpack(data):
                return False
            offset = HEADER_SIZE
            self.content_size = struct.unpack("<I", data[offset:offset + CONTENT_SIZE])[0]
            offset += CONTENT_SIZE

            self.orig_file_size = struct.unpack("<I", data[offset:offset + ORIG_FILE_SIZE])[0]
            offset += ORIG_FILE_SIZE

            self.packets.packet_number = struct.unpack("<H", data[offset:offset + PACKET_NUMBER_SIZE])[0]
            offset += PACKET_NUMBER_SIZE

            self.packets.total_packets = struct.unpack("<H", data[offset:offset + TOTAL_PACKETS_SIZE])[0]
            offset += TOTAL_PACKETS_SIZE

            file_name_data = data[offset:offset + FILE_NAME_SIZE]
            self.file_name = str(struct.unpack(
                f"<{FILE_NAME_SIZE}s", file_name_data)[0].partition(b'\0')[0].decode('utf-8'))
            offset += FILE_NAME_SIZE

            self.message_content = data[offset:HEADER_SIZE + self.header.payload_size]
            return True
        except:
            self.__init__()
            return False

    def __eq__(self, other):
        if isinstance(other, RequestSendingFile):
            return (self.header == other.header and self.content_size == other.content_size and
                    self.orig_file_size == other.orig_file_size and
                    self.packets.total_packets == other.packets.total_packets and
                    self.file_name == other.file_name)
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        print("request header:\n", self.header)
        print("self.content_size: ", self.content_size)
        print("self.orig_file_size: ", self.orig_file_size)
        print("self.packets.total_packets: ", self.packets.total_packets)
        print("self.packets.packet_number: ", self.packets.packet_number)
        print("self.file_name: ", self.file_name)
        print("self.message_content: ", self.message_content)
        return ""


class ReceivedValidFileWithCRC:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.FILE_RECEIVED_PROPERLY_WITH_CRC.value)
        self.client_ID = b""
        self.content_size = b""
        self.file_name = b""
        self.crc = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_ID)
            data += struct.pack("<L", self.content_size)
            data += struct.pack(f"<{FILE_NAME_SIZE}s", self.file_name)
            data += struct.pack("<L", self.crc)
            return data
        except:
            return b""

    def __str__(self):
        print("self.header.version: ", self.header.version)
        print("self.header.code: ", self.header.code)
        print("self.header.payload_size: ", self.header.payload_size)
        print("self.client_ID: ", self.client_ID)
        print("self.content_size: ", self.content_size)
        print("self.file_name: ", self.file_name)
        print("self.crc: ", self.crc)
        return ''


class RequestMessage:
    def __init__(self, request_header):
        self.header = request_header
        self.file_name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Registration data """
        try:
            file_name_data = data[HEADER_SIZE:HEADER_SIZE + FILE_NAME_SIZE]
            self.file_name = str(struct.unpack(
                f"<{FILE_NAME_SIZE}s", file_name_data)[0].partition(b'\0')[0].decode('utf-8'))
            return True
        except:
            self.__init__(b"")
            return False


class ResponseMessage:
    def __init__(self):
        self.header = ResponseHeader(EResponseCode.APPROVED_GETTING_MESSAGE_THANKS.value)
        self.client_ID = b""

    def pack(self):
        """ Little Endian pack Response Header and client ID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.client_ID)
            return data
        except:
            return b""
