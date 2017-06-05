import os
from generate_keys import generate_keys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Hash import SHA256


def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out

    # Import private key object
    key = RSA.importKey(open('master_key.pem','r').read())
    # Create PKCS1 v1.5 OAEP cipher from private key
    RSA_cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    # Decrypt the AES key and iv
    AES_container = str(RSA_cipher.decrypt(f[0:512]), 'ascii')
    AES_key = AES_container[:32]
    AES_iv = AES_container[32:]
    # Create AES cipher with key and iv to decrypt file
    AES_cipher = AES.new(AES_key, AES.MODE_CBC, AES_iv)
    # Decrypt and unpad the file
    file = str(ANSI_X923_unpad(AES_cipher.decrypt(f[512:]), 16), "ascii")
    print(file)


def ANSI_X923_unpad(m, pad_length):
    # The last byte should represent the number of padding bytes added
    required_padding = m[-1]
    # Ensure that there are required_padding - 1 zero bytes
    if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
        return m[:-required_padding]
    else:
        # Raise an exception in the case of an invalid padding
        raise AssertionError("Padding was invalid")


if __name__ == "__main__":
    
    # If pem file has been deleted
    if not os.path.exists("master_key.pem"):
        # Generate new keys
        # Private key in master/ folder
        # Public key in pastebin.net/publickeys/ folder
        generate_keys()

    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("../pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
        
    f = open(os.path.join("../pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
