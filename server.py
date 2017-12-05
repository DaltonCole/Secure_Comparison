import socket   
from phe import paillier 
from helper_server import * 
import pickle
from sys import getsizeof


# create a socket object
serversocket = socket.socket(
	        socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 9999                                           

# bind to the port
serversocket.bind((host, port))                                  

# queue up to 10 requests
serversocket.listen(10)  

# Try to make it so socket closes quickly
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# establish a connection
client, addr = serversocket.accept()      

print("Got a connection!")

### Recieve Config Parameters ###
# Key
public_key = receive(client)
print("Got puclic key")
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
		u_times_v = secure_multiplication_server(client, public_key, N, u, v)

		# For Confirmation
		print("Finished secure multiplication, sending to client for your confirmation...")
		send(client, u_times_v)
	elif '2' in option:
		minimum = secure_minimum_server(client, public_key, N)
		print("Finished secure minimum, sending to client for your confirmation...")
		send(client, minimum)
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