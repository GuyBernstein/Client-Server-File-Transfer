from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


class AESCipher:

    def __init__(self):
        self.key = get_random_bytes(AES.block_size)

    def encrypt_aes_with_rsa(self, public_key):
        try:
            rsa_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            encrypted_key = cipher_rsa.encrypt(self.key)
            return encrypted_key
        except:
            return None


def decrypt_message(key, message):
    try:
        aes = AES.new(key, AES.MODE_CBC, iv=b'\0' * 16)
        return unpad(aes.decrypt(message), AES.block_size)
    except Exception as e:
        print(e)
        return None
