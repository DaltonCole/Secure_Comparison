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
		v = int(input())
		# Send v to server
		send(server, v)
		print("Sent v to server")
		secure_multiplication_client(server, public_key, private_key, N)

		# Confirmation for convenience of user
		print("u * v = {}".format(private_key.decrypt(receive(server)) % N))
	elif '2' in option:
		send(server, '2')
		print("Secure minimum selected, please enter v: ", end='')
		v_decomp = binary_decomposition_client(public_key, int(input()))
		send(server, v_decomp)
		secure_minimum_client(server, public_key, private_key, N)
		print("Min(u, v) = {}".format(private_key.decrypt(receive(server)) % N))
	elif '3' in option:
		send(server, '3')
		print("Secure squared euclidean distance selected, please enter v: ", end='')
		v = get_vector_input_client(public_key)
		send(server, v)
		secure_squared_euclidean_distance_client(server, public_key, private_key, N, len(v))
		print("SSED(u, v) = {}".format(private_key.decrypt(receive(server)) % N))

	elif '9' in option:
		send(server, '9')
		break
	elif '6' in option:
		send(server, '6')
		print("Secure Bit-OR selected, please enter o2 [0,1]: ", end='')
		# Get user input
		o2 = public_key.encrypt(int(input()))
		# Send o2 to server
		send(server, o2)
		secure_bitor_client(server, public_key, private_key, N)
		print("Sent o2 to server")
		print("OR(o1, o2) = {}".format(private_key.decrypt(receive(server)) % N))

	print()

"""
msg = pickle.loads(s.recv(4096))
print(private_key.decrypt(msg))
"""

server.close()
