import os
from generate_keys import generate_keys
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    
    # Import private key object
    key = RSA.importKey(open('master_key.pem','r').read())
    # Create PKCS1 v1.5 OAEP cipher from private key
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    # Decrypt and decode the text
    decoded_text = str(cipher.decrypt(f), 'ascii')
    # Print decoded text
    print(decoded_text)


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
