import socket
from phe import paillier
import pickle
from helper_client import *
from sys import getsizeof
import time


### Initalize Connection Process ###
# create a socket object
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 9999

# connection to hostname on the port.
server.connect((host, port))  
#####################################

### Send Config Paramaters ###
# Send Public Key
public_key, private_key = paillier.generate_paillier_keypair()
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
		secure_multiplication_client(server, public_key, private_key, N)

		# Confirmation for convenience of user
		print("u * v = {}".format(private_key.decrypt(receive(server)) % N))
	elif '2' in option:
		send(server, '2')
		secure_minimum_client(server, public_key, private_key, N)
		print("Min(u, v) = {}".format(private_key.decrypt(receive(server)) % N))
	elif '9' in option:
		send(server, '9')
		break

"""
msg = pickle.loads(s.recv(4096))
print(private_key.decrypt(msg))
"""                             

server.close()
