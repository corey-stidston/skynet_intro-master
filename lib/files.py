import os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Hash import SHA256
from . import crypto_utils
import struct

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []
# Length of signature to split updates
SIGNATURE_LEN = 512
###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the master bot
    # I.e Use the master bots' public key to encrypt the data

    # Generate AES material and then AES key and iv
    AES_material = random.getrandbits(256)
    AES_material_h = SHA256.new(bytes(str(AES_material), "ascii")).hexdigest()
    AES_key = AES_material_h[0:32]
    AES_iv = AES_material_h[-16:]

    # Create AES container
    AES_container = b"".join([bytes(str(AES_key),"ascii"), bytes(str(AES_iv),"ascii")])

    # Use AES to encrypt file
    cipher = AES.new(AES_key, AES.MODE_CBC, AES_iv)

    # Pad the data with the correct blocksize for AES
    padded_data = crypto_utils.ANSI_X923_pad(data, 16)
    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)
    
    # Read masters' public key PEM file
    file = open(os.path.join("pastebot.net/publickeys", "master_pubkey.pem"), "r")
    # Import masters' public key
    pubkey = RSA.importKey(file.read())
    file.close()
    # Create new OAEP cipher with masters' public key and SHA256 Hashing algorithm
    cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA256)

    # Encrypt AES key and iv with OAEP cipher
    AES_container_e = cipher.encrypt(AES_container)

    return AES_container_e + encrypted_data

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Open master public key
    file = open(os.path.join("pastebot.net/publickeys", "master_pubkey.pem"), "r")
    # Verify the file was sent by the bot master
    key = RSA.importKey(file.read())
    file.close()
    # Seperate signature
    signature = f[:SIGNATURE_LEN]
    # Seperate hashed file
    hashed_f = SHA256.new(f[SIGNATURE_LEN:])
    # Create new PKSC1_v1_5 Signature Scheme object
    verifier = PKCS1_v1_5.new(key)
    # Return result of verification
    return verifier.verify(hashed_f,signature)

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)

    sconn.send(bytes(fn,"ascii"))
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
