import os
from Crypto import Random
from Crypto.PublicKey import RSA

def generate_keys():
	random_generator = Random.new().read

	# Generate RSA key object
	key = RSA.generate(4096, random_generator)

	# Create private key PEM
	f = open('master_key.pem','w')
	f.write(key.exportKey('PEM').decode('ascii'))
	f.close()

	# Create public key in pastebin.net/publickeys/
	f = open(os.path.join("../pastebot.net/publickeys",'master_pubkey.pem'),'w')
	f.write(key.publickey().exportKey('PEM').decode('ascii'))
	return