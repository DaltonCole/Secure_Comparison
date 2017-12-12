import socket
from phe import paillier
import pickle
from helper_client import *
from sys import getsizeof, argv
import time

if len(argv) != 2:
	print("Usage: python3 {} (port number)".format(argv[0]))
	quit()

### Initalize Connection Process ###
# create a socket object
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = 'localhost'

port = int(argv[1])

# connection to hostname on the port.
server.connect((host, port))
#####################################

### Send Config Paramaters ###
# Send Public Key
public_key, private_key = paillier.generate_paillier_keypair()#n_length=33)
public_key.max_int = public_key.n - 1
send(server, public_key)
# Send Field Size
N = 3000000019 # 3 billion
send(server, N)
##############################

### Start Menu ###
while True:
	option = print_menu()

	if '1' in option:
		send(server, '1')
		print("Secure multiplication selected, please enter v: ", end='')
		# Get user input
		v = public_key.encrypt(int(input()))
		# Send v to server
		send(server, v)
		print("Sent v to server")
		secure_multiplication_client(server, public_key, private_key, N)

		# Confirmation for convenience of user
		print("u * v = {}".format(private_key.decrypt(receive(server)) % N))
	elif '2' in option:
		send(server, '2')
		print("Secure minimum selected, please enter v: ", end='')
		enc_v = public_key.encrypt(int(input()))
		send(server, enc_v)
		secure_bit_decomposition_client(server, private_key)
		secure_bit_decomposition_client(server, private_key)
		secure_minimum_client(server, public_key, private_key, N)
		print("Min(u, v) = {}".format(private_key.decrypt(receive(server)) % N))
	elif '3' in option:
		send(server, '3')
		print("Secure squared euclidean distance selected, please enter v: ", end='')
		v = get_vector_input_client(public_key)
		send(server, v)
		secure_squared_euclidean_distance_client(server, public_key, private_key, N, len(v))
		print("SSED(u, v) = {}".format(private_key.decrypt(receive(server)) % N))

	elif '4' in option:
		send(server, '4')
		print("Secure bit decomposition selected, please enter x: ", end='')
		x = int(input())
		print("Enter a bitlength m (or default to len(x)): ", end='')
		m = input().strip()
		m = int(m) if m else (x.bit_length() + 1)
		enc_x = public_key.encrypt(x)

		send(server, enc_x)
		send(server, m)
		secure_bit_decomposition_client(server, private_key)
		x_decomp = receive(server)
		print("Received [x] from server.")
		x_decomp_decrypt = [private_key.decrypt(x_i) for x_i in x_decomp]
		print("Decrypted; x-decomp:", x_decomp_decrypt)

	elif '5' in option:
		send(server, '5')
		print("Secure Bit-OR selected, please enter o2 [0,1]: ", end='')
		# Get user input
		o2 = public_key.encrypt(bool(int(input())))
		# Send o2 to server
		send(server, o2)
		print("Sent o2 to server")
		secure_multiplication_client(server, public_key, private_key, N)
		print("OR(o1, o2) = {}".format(private_key.decrypt(receive(server)) % N))
	
	elif '9' in option:
		send(server, '9')
		break
	print()

"""
msg = pickle.loads(s.recv(4096))
print(private_key.decrypt(msg))
"""

server.close()
