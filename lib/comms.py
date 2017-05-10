import struct
import time
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from . import crypto_utils
from dh import create_dh_key, calculate_dh_secret
import sys

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.shared_hash = None
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 

        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_hash))
            #print("Shared hash length: {}".format(len(self.shared_hash)))

            # Create initialisation vector from the last 16 characters of the shared hash
            initialisation_vector = self.shared_hash[-16:]
            # Create new AES instance, using first 32 characters of the shared hash
            self.cipher = AES.new(self.shared_hash[:16], AES.MODE_CBC, initialisation_vector)
            

    def send(self, data):
        if self.cipher:
            # Append the timestamp to the packet as an integer
            container = b"".join([data, struct.pack(">i", int(time.time()))])
            # Calculate the Hash
            hmac = HMAC.new(self.shared_hash.encode(), container, SHA256).digest()
            # Append the the HMAC to the container
            outer_container = b"".join([container, hmac])
            # Pad the message with the correct blocksize for AES
            padded_message = crypto_utils.ANSI_X923_pad(outer_container, self.cipher.block_size)
            # Encrypt entire message
            encrypted_data = self.cipher.encrypt(padded_message)

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            # Decrypt the message into an unpadded form
            decrypted_message = self.cipher.decrypt(encrypted_data)
            # Unpad the message
            outer_container = crypto_utils.ANSI_X923_unpad(decrypted_message, self.cipher.block_size)
            # Extract the hmac
            hmac = outer_container[-SHA256.digest_size:]
            # Deconstruct the packet
            container = outer_container[:-SHA256.digest_size]
            # Calculate hmac
            calculated_hmac = HMAC.new(self.shared_hash.encode(), container, SHA256).digest()
            if calculated_hmac != hmac:
                print("****WARNING: MESSAGE INTEGRITY ATTACK DETECTED****")
                # Do something about integrity attack
                # ignore message etc
                # close connection etc..
            #else:
                #print("HMACS ARE EQUAL")

            # Extract the timestamp
            timestamp = struct.unpack(">i", container[-4:])[0]
            
            # Ensure the timestamp is within a reasaonable time period (10 seconds)
            if(time.time() - timestamp > 10):
                print("****WARNING: REPLAY ATTACK DETECTED****")
                # Do something about replay attack
                # ignore message
                # close connection etc..

            # Extract the data
            data = container[:-4]

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data
        return data

    def close(self):
        self.conn.close()
