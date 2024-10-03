import logging
import re
import selectors
import socket
import uuid
from functools import partial

import cksum
import client_model
import keys
import protocol
import utils


class Server:
    PACKET_SIZE = 1024  # Default packet size.
    MAX_QUEUED_CONN = 5  # Default maximum number of queued connections.
    IS_BLOCKED = False

    def __init__(self, host, port):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.request_handle = {
            # We are using partial() to make a new function where 'self' is already tied to each function
            protocol.ERequestCode.REGISTRATION.value: partial(self.handle_registration),
            protocol.ERequestCode.SENDING_PUBLIC_KEY.value: partial(self.handle_public_key_request),
            protocol.ERequestCode.RECONNECTION.value: partial(self.handle_reconnection),
            protocol.ERequestCode.SENDING_FILE.value: partial(self.handle_sending_file),
            protocol.ERequestCode.CRC_VALID.value: partial(self.handle_message),
            protocol.ERequestCode.CRC_INVALID_SENDING_AGAIN.value: partial(self.handle_message),
            protocol.ERequestCode.CRC_INVALID_FORTH_TIME_IM_DONE.value: partial(self.handle_message)
        }
        self.client_list = []
        self.client_aes_ciphers = {}

    def start(self):
        try:

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set SO_REUSEADDR option
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            server_socket.bind((self.host, self.port))
            server_socket.listen(self.MAX_QUEUED_CONN)
            server_socket.setblocking(Server.IS_BLOCKED)
            self.sel.register(server_socket, selectors.EVENT_READ, self.accept)
        except Exception as err:
            logging.exception(f"Server.start exception: {err}")
            # add handle like stopClinet()
            # return  # Exit the method if we cannot set up the socket
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as err:
                logging.exception(f"Server main loop exception: {err}")
                break

    def accept(self, sock, mask):
        conn, addr = sock.accept()
        logging.info(f"Accepted connection from {addr}")
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        data = conn.recv(self.PACKET_SIZE)
        success = False
        # Debug::
        logging.info(f"Received request: {data}")
        if data:
            request_header = protocol.RequestHeader()
            if not request_header.unpack(data):
                logging.error("Failed to parse request header!")
                logging.error(f"Sending a generic error code: "
                              f"{protocol.EResponseCode.GENERIC_ERROR.value}")
                response_header = protocol.ResponseHeader(protocol.EResponseCode.GENERIC_ERROR.value)
                self.write(conn, response_header.pack())
            else:
                if request_header.code in self.request_handle.keys():
                    # invoke corresponding handle.
                    success = self.request_handle[request_header.code](conn, data, request_header)
                if not success:
                    logging.error(f"Sending a generic error code: "
                                  f"{protocol.EResponseCode.GENERIC_ERROR.value}")
                    response_header = protocol.ResponseHeader(protocol.EResponseCode.GENERIC_ERROR.value)
                    self.write(conn, response_header.pack())

        logging.info(f"Closing connection to {conn}")
        self.sel.unregister(conn)
        conn.close()

    @staticmethod
    def write(conn, data):
        """ Send a response to client"""
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > Server.PACKET_SIZE:
                leftover = Server.PACKET_SIZE
            to_send = data[sent:sent + leftover]
            if len(to_send) < Server.PACKET_SIZE:
                to_send += bytearray(Server.PACKET_SIZE - len(to_send))
            try:
                conn.send(to_send)
                sent += len(to_send)
            except:
                logging.error("Failed to send response to " + conn)
                return False
        logging.info("Response sent successfully.")
        return True

    def handle_registration(self, conn, data, requestHeader):
        """ Register a new user. """
        request = protocol.ConnectionRequest(requestHeader)
        response = protocol.ResponseClientID()

        # Handle registration failure
        if not request.unpack(data):
            logging.error("Registration Request: Failed parsing request.")
            return False

        if not bool(re.match(r'^[a-zA-Z0-9 ]+$', request.name)):
            logging.error(f"Registration Request: Invalid requested username ({request.name})) "
                          f"must be of [a-zA-Z0-9 ] expression")
            return False
        if len(request.name) > protocol.ACTUAL_NAME_SIZE:
            logging.error(f"Registration Request: Invalid requested username ({request.name})) "
                          f"must be {protocol.ACTUAL_NAME_SIZE} chars at most")
            return False

        # Handle if failed registration:
        for client in self.client_list:
            if request.name == client.name:
                logging.error(f"Registration Request: Client is already registered")
                response.header.code = protocol.EResponseCode.REGISTRATION_FAILED.value
                return self.write(conn, response.pack())

        # Handle successful registration
        try:
            client = client_model.Client(uuid.uuid4().hex, request.name)
        except:
            logging.error(f"Registration Request: Error creating uuid for client's username: {request.name} ")
            return False
        self.client_list.append(client)  # save the client on the RAM
        logging.info(f"Successfully registered client {request.name}.")

        # Send successful response
        response.client_ID = client.id
        response.header.payload_size = protocol.CLIENT_ID_SIZE
        return self.write(conn, response.pack())

    def handle_public_key_request(self, conn, data, requestHeader):
        request = protocol.SendingPublicKey(requestHeader)
        response = protocol.ResponseEncryptedAES()

        # Handle sending public key failure:
        if not request.unpack(data):
            logging.error("Sending public key Request: Failed parsing request.")
            return False

        # Handle if not registered:
        is_registered = False
        this_client = None
        for client in self.client_list:
            if request.name == client.name:
                is_registered = True
                this_client = client  # found a matching client
                break

        if not is_registered:
            logging.error(f"Sending public key Request: Invalid requested username ({request.name})) "
                          "is not registered")
            return False

        if this_client.id != request.header.client_id:
            logging.error(f"Sending public key Request: Invalid requested id ({request.header.client_id})) "
                          f"is not registered to this username ({request.name})")
            return False

        # Save the public key
        this_client.public_key = request.public_key

        # Create an aes key and encrypt it to save
        aes_cipher = keys.AESCipher()
        encrypted_key = aes_cipher.encrypt_aes_with_rsa(request.public_key)
        if not encrypted_key:
            logging.error(f"Sending public key Request: Failed encrypting client's public key")
            return False
        self.client_aes_ciphers[this_client] = aes_cipher

        # Send successful response
        response.client_ID = this_client.id
        response.aes_key = encrypted_key

        response.header.code = protocol.EResponseCode.RECEIVED_PUBLIC_KEY_AND_SENDING_AES.value
        response.header.payload_size = protocol.CLIENT_ID_SIZE + len(encrypted_key)
        logging.info(f"Successfully received public key and sending aes.")
        return self.write(conn, response.pack())

    def handle_reconnection(self, conn, data, requestHeader):
        request = protocol.ConnectionRequest(requestHeader)
        response_success = protocol.ResponseEncryptedAES()
        response_fail = protocol.ResponseClientID()

        # Handle reconnection failure
        if not request.unpack(data):
            logging.error("Reconnection Request: Failed parsing request.")
            return False

        # Handle if not registered:
        is_registered = False
        this_client = None
        for client in self.client_list:
            if request.name == client.name:
                is_registered = True
                this_client = client  # found a matching client
                break

        # Handle Invalid username
        if not is_registered:
            logging.error(f"Reconnection Request: Invalid requested username ({request.name})) "
                          "is not registered")
            response_fail.header.code = protocol.EResponseCode.REQUEST_FOR_RECONNECTION_DENIED.value
            return self.write(conn, response_fail.pack())

        # Handle Invalid id
        if this_client.id != request.header.client_id:
            logging.error(f"Reconnection Request: Invalid requested id ({request.header.client_id})) "
                          f"is not registered to this username ({request.name})")
            response_fail.header.code = protocol.EResponseCode.REQUEST_FOR_RECONNECTION_DENIED.value
            return self.write(conn, response_fail.pack())

        # Handle missing public key
        if this_client.public_key is None:
            logging.error(f"Reconnection Request: Client's username ({request.name}) and id ({this_client.id}) "
                          "does not have a public key")
            response_fail.header.code = protocol.EResponseCode.REQUEST_FOR_RECONNECTION_DENIED.value
            return self.write(conn, response_fail.pack())

        # Create an aes key and encrypt it to save
        aes_cipher = keys.AESCipher()
        encrypted_key = aes_cipher.encrypt_aes_with_rsa(this_client.public_key)
        if not encrypted_key:
            logging.error(f"Reconnection Request: Failed encrypting client's public key")
            return False  # Send a generic response in this case

        self.client_aes_ciphers[this_client] = aes_cipher

        # Send successful response
        response_success.client_ID = this_client.id
        response_success.aes_key = encrypted_key
        response_success.header.code = protocol.EResponseCode.APPROVED_REQUEST_TO_RECONNECT_SENDING_AES.value
        response_success.header.payload_size = protocol.CLIENT_ID_SIZE + len(encrypted_key)
        logging.info(f"Successfully reconnected and sending aes.")
        return self.write(conn, response_success.pack())

    def handle_sending_file(self, conn, data, request_header):
        request = protocol.RequestSendingFile()
        sub_response = protocol.ResponseMessage()

        # Handle sending file failure:
        if not request.unpack(data):
            logging.error("Send File Request: on packet number 1: Failed parsing request's packet initially.")
            return False

        # Handle invalid packets
        if request.packets.packet_number > request.packets.total_packets:
            logging.error("Send File Request: on packet number 1: Packet number exceeded total packets.")
            return False

        # Handle if not connected:
        is_connected = False
        this_client = None
        for client in self.client_list:
            if request.header.client_id == client.id:
                is_connected = True
                this_client = client  # found a matching client
                break

        if not is_connected:
            logging.error(f"Send File Request: on packet number 1:"
                          f" Invalid requested id ({request.header.client_id})) "
                          f"is not registered")
            return False

        if not this_client.name or not this_client.public_key:
            logging.error(f"Send File Request: on packet number 1: "
                          f"Invalid client with id ({request.header.client_id})) "
                          f"does not have username or a public key")
            return False

        # Store the current packet of the encrypted file into this client
        this_client.file_content[request.file_name] += request.message_content

        if request.packets.packet_number < request.packets.total_packets:

            # Send successful sub file packet response
            logging.info("Successfully received file packet message. Sending thank you reply.")

            sub_response.client_ID = this_client.id
            sub_response.header.payload_size = protocol.CLIENT_ID_SIZE
            return self.write(conn,  sub_response.pack())


        # Handle the final chunk
        response = protocol.ReceivedValidFileWithCRC()

        # Decrypt message using our aes key that was saved for this client
        key = self.client_aes_ciphers[this_client].key
        decrypted_message = keys.decrypt_message(key, this_client.file_content[request.file_name])

        if not decrypted_message:
            logging.error(f"Send File Request: failed decrypting requested message content")
            return False  # Send a generic response in this case

        # Reset the file_content for this client, for future retries, to resend the file
        this_client.file_content[request.file_name] = b""

        # Write the valid file
        if not utils.write_decrypted_file(request.file_name, decrypted_message):
            return False


        # Handle a successful sending file with crc
        response.client_ID = request.header.client_id
        response.content_size = request.content_size

        # Pad the file_name with nulls for the size protocol.FILE_NAME_SIZE
        # response.filename = request.file_name.encode('utf-8').ljust(protocol.FILE_NAME_SIZE, b'\x00')
        # print("response.filename: ", response.filename)
        response.file_name = (lambda s, target_length: s.encode('utf-8').ljust(target_length,
                                                                               b'\x00'))(request.file_name,
                                                                                         protocol.FILE_NAME_SIZE)

        # Calculate crc from the valid file
        response.crc = cksum.readfile(request.file_name)
        response.header.payload_size = (protocol.CLIENT_ID_SIZE + protocol.CONTENT_SIZE +
                                        protocol.FILE_NAME_SIZE + protocol.CRC_SIZE)

        logging.info("Successfully file transferred completely. Sending calculated CRC.")
        return self.write(conn, response.pack())

    def handle_message(self, conn, data, request_header):
        request = protocol.RequestMessage(request_header)
        response = protocol.ResponseMessage()

        # Handle registration failure
        if not request.unpack(data):
            logging.error(f"Validate CRC Request with code {request_header.code}: Failed parsing request.")
            return False

        # Handle if not connected:
        is_connected = False
        this_client = None
        for client in self.client_list:
            if request.header.client_id == client.id:
                is_connected = True
                this_client = client  # found a matching client
                break

        # Handle generic errors
        if not is_connected:
            logging.error(f"Validate CRC Request with code {request_header.code}: "
                          f"Invalid requested id ({request.header.client_id}) "
                          f"is not connected")
            return False

        if not this_client.name or not this_client.public_key:
            logging.error(f"Validate CRC Request with code {request_header.code}: "
                          f"Invalid client with id ({request.header.client_id})) "
                          f"does not have username or a public key")
            return False

        if request.file_name not in this_client.file_content.keys():
            logging.error(f"Validate CRC Request with code {request_header.code}: "
                          f"Invalid requested id ({request.header.client_id}) "
                          f"didn't send file")
            return False

        # Send successful response
        logging.info("Successfully received crc message. Sending thank you reply.")

        response.client_ID = this_client.id
        response.header.payload_size = protocol.CLIENT_ID_SIZE
        return self.write(conn, response.pack())
