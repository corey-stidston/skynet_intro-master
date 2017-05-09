import struct
import time
from Crypto.Cipher import XOR
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from . import crypto_utils
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            #print("Shared hash: {}".format(shared_hash))
            
            # my code
            initialisation_vector = shared_hash[-16:]
            self.cipher = AES.new(shared_hash[:32], AES.MODE_CBC, initialisation_vector)

            # other method - Counter Mode
            #ctr = Counter.new(128, initial_value="Randomint")
            #self.cipher = AES.new(shared_hash[:32], AES.MODE_CTR, ctr) # cipher block chaining
            

        # Default XOR algorithm can only take a key of length 32
        # self.cipher = XOR.new(shared_hash[:4]) #<----------CHANGE / REMOVE THIS

    def send(self, data):
        if self.cipher:
            container = b"".join([data, struct.pack(">i", int(time.time()))])

            padded_message = crypto_utils.ANSI_X923_pad(container, self.cipher.block_size) #self.cipher.block_size
            
            #encrypt entire message
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

            #decrypt the message into unpadded form
            unpadded_message = self.cipher.decrypt(encrypted_data)
            #unpad the message
            container = crypto_utils.ANSI_X923_unpad(unpadded_message, self.cipher.block_size)
            packet_time = struct.unpack(">i", container[-4:])[0]
            
            if(time.time() - packet_time > 10):
                print("\nWARNING: REPLAY ATTACK DETECTED")
                

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
