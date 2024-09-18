import selectors
import socket
import protocol
import logging


class Server:
    PACKET_SIZE = 1024  # Default packet size.
    IS_BLOCKED = False

    def __init__(self, host, port):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        # logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')

        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.requestHandle = {
            protocol.ERequestCode.REQUEST_REGISTRATION.value: self.handle_registration
            # protocol.ERequestCode.REQUEST_USERS.value: self.handleUsersListRequest,
            # protocol.ERequestCode.REQUEST_PUBLIC_KEY.value: self.handlePublicKeyRequest,
            # protocol.ERequestCode.REQUEST_SEND_MSG.value: self.handleMessageSendRequest,
            # protocol.ERequestCode.REQUEST_PENDING_MSG.value: self.handlePendingMessagesRequest
        }

    def start(self):
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((self.host, self.port))
            server_socket.listen()  # he did: sock.listen(Server.MAX_QUEUED_CONN)
            server_socket.setblocking(Server.IS_BLOCKED)
            self.sel.register(server_socket, selectors.EVENT_READ, self.accept)
        except Exception as err:
            logging.exception(f"Server.start exception: {err}")  # handle like stopClinet()
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as err:
                logging.exception(f"Server main loop exception: {err}")


    def accept(self, sock, mask):
        conn, addr = sock.accept()
        logging.info(f"Accepted connection from {addr}")
        conn.setblocking(False)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        data = conn.recv(self.PACKET_SIZE)
        # Debug::
        logging.info(f"Received message: {data.decode('utf-8')}")
        if data:
            requestHeader = protocol.RequestHeader()
            # success = False
            # if not requestHeader.unpack(data):
            #     logging.error("Failed to parse request header!")
            # else:
            #     if requestHeader.code in self.requestHandle.keys():
            #         success = self.requestHandle[requestHeader.code](conn, data)  # invoke corresponding handle.
            #     if not success:  # return generic error upon failure.
            #         pass
            #         # later needs to return an error if fails
            #         # responseHeader = protocol.ResponseHeader(protocol.EResponseCode.RESPONSE_ERROR.value)
            #         # self.write(conn, responseHeader.pack())
        else:
            logging.info(f"Closing connection to {conn}")
            self.sel.unregister(conn)
            conn.close()

    def handle_registration(self, conn, data):
        """ Register a new user. """
        request = protocol.RegistrationRequest()
        response = protocol.RegistrationResponse()
        if not request.unpack(data):
            logging.error("Registration Request: Failed parsing request.")
            return False
        # this is data base !@$!@$@#%@#%@#%!@%!@$!@$!@$!@#!@$!@$!@$
        # try:
        #     if not request.name.isalnum():
        #         logging.info(f"Registration Request: Invalid requested username ({request.name}))")
        #         return False
        #     if self.database.clientUs ernameExists(request.name):
        #         logging.info(f"Registration Request: Username ({request.name}) already exists.")
        #         return False
        # except:
        #     logging.error("Registration Request: Failed to connect to database.")
        #     return False

        # this is data base !@$!@$@#%@#%@#%!@%!@$!@$!@$!@#!@$!@$!@$
        # clnt = database.Client(uuid.uuid4().hex, request.name, request.publicKey, str(datetime.now()))
        # if not self.database.storeClient(clnt):
        #     logging.error(f"Registration Request: Failed to store client {request.name}.")
        #     return False

        logging.info(f"Successfully registered client {request.name}.")

        # this is data base !@$!@$@#%@#%@#%!@%!@$!@$!@$!@#!@$!@$!@$
        # response.clientID = clnt.ID

        response.header.payloadSize = protocol.CLIENT_ID_SIZE

        # return self.write(conn, response.pack())
        # ^^this was the command^^
        # -.- meanwhile i do this -.-
        # baabab
        print('gay')
        return True
