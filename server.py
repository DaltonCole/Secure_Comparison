import socket
from phe import paillier
from helper_server import *
import pickle
from sys import getsizeof, argv

if len(argv) != 2:
	print("Usage: python3 {} (port number)".format(argv[0]))
	quit()

# create a socket object
serversocket = socket.socket(
	        socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = 'localhost'


# Try to make it so socket closes quickly
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
port = int(argv[1])

# bind to the port
serversocket.bind((host, port))

# queue up to 10 requests
serversocket.listen(10)

# establish a connection
client, addr = serversocket.accept()

print("Got a connection!")

### Recieve Config Parameters ###
# Key
public_key = receive(client)
print("Got public key")
# Field Size
N = receive(client)
print("N: {}".format(N))
##########################

while True:
	# Recieve menu option
	option = receive(client)

	if '1' in option:
		print("Secure multiplication selected, please enter u: ", end='')
		# Get u from user
		u = public_key.encrypt(int(input()))
		# Recieve v from client
		v = receive(client)
		print("received V")
		u_times_v = secure_multiplication_server(client, public_key, N, u, v)

		# For Confirmation
		print("Finished secure multiplication, sending to client for your confirmation...")
		send(client, u_times_v)
	elif '2' in option:
		print("Secure minimum selected, please enter u: ", end='')
		u_decomp = binary_decomposition_server(public_key, int(input()))
		v_decomp = receive(client)
		minimum = secure_minimum_server(client, public_key, N, u_decomp, v_decomp)
		print("Finished secure minimum, sending to client for your confirmation...")
		send(client, minimum)
	elif '3' in option:
		print("Secure squared euclidean distance selected, please enter u: ", end='')
		u = get_vector_input_server(public_key)
		v = receive(client)
		ssed = secure_squared_euclidean_distance_server(client, public_key, N, u, v)
		print("Finished secure squared euclidean distance, sending to client for your confirmation...")
		send(client, ssed)

	elif '4' in option:
		print("Secure bit decomposition selected.")
		enc_x = receive(client)
		m = receive(client)
		print("Received E(x) and m; running secure bit decomposition.")
		x_decomp = secure_bit_decomposition_server(server, public_key, enc_x, m)
		print("Finished secure bit decomposition, sending to client")
		send(client, x_decomp)

	elif '9' in option:
		break

print("Closing connection")
client.close()
serversocket.close()


"""
   msg = 'Thank you for connecting'+ "\r\n"

   public_key = pickle.loads(clientsocket.recv(4096))
   clientsocket.send(pickle.dumps(public_key.encrypt(10)))

#clientsocket.send(msg.encode('ascii'))
clientsocket.close()
"""
