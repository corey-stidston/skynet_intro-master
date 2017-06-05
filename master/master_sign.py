import os
from generate_keys import generate_keys
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

def sign_file(f):
    # Sign the file using PKCS1_v1_5

    # Import private key object
    key = RSA.importKey(open('master_key.pem','r').read())
    # Create the hash that will be signed and pre-pended to message
    hashed_f = SHA256.new(f)
    # Create signer using private key
    signer = PKCS1_v1_5.new(key)
    # Create signature
    signature = signer.sign(hashed_f)
    # Return signature appended with file
    return signature + f


if __name__ == "__main__":

    # If pem file has been deleted
    if not os.path.exists("master_key.pem"):
        # Generate new keys
        # Private key in master/ folder
        # Public key in pastebin.net/publickeys/ folder
        generate_keys()

    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("../pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)

    f = open(os.path.join("../pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("../pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
