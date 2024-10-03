import protocol
from collections import defaultdict


class Client:
    """ Represents a client entry """
    def __init__(self, cid, client_name):
        self.id = bytes.fromhex(cid)  # Unique client ID, 16 bytes.
        self.name = client_name  # Client's name, null terminated ascii string, 100 bytes.
        self.public_key = None  # Client's public key, 160 bytes.
        self.file_content = defaultdict(bytearray)

    def validate(self):
        """ Validate Client attributes according to the requirements """
        if not self.id or len(self.id) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.name or len(self.name) >= protocol.NAME_SIZE:
            return False
        if not self.public_key or len(self.public_key) != protocol.PUBLIC_KEY_SIZE:
            return False
        return True


