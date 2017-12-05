import socket
from phe import paillier
import pickle
from random import randrange, choice
from sys import getsizeof
from time import sleep

def receive(socket):
	buffer_size = pickle.loads(socket.recv(128))
	r = socket.recv(buffer_size)
	return pickle.loads(r)

def send(socket, data):
	# Send buffer size
	socket.send(pickle.dumps(getsizeof(pickle.dumps(data))))
	sleep(0.4)
	socket.send(pickle.dumps(data))
	sleep(0.4)

def secure_multiplication_server(client, public_key, N, u, v):
	# Pick two random numbers
	ra = randrange(0, N)
	rb = randrange(0, N)

	a_prime = u + public_key.encrypt(ra)
	b_prime = v + public_key.encrypt(rb)

	# Send a' and b' to client
	send(client, a_prime)
	send(client, b_prime)

	# Recieve E(h) from client
	h_prime = receive(client)

	s = h_prime + (u * (N - rb))
	s_prime = s + (v * (N - ra))

	u_times_v = s_prime + (public_key.encrypt(ra * rb) * (N - 1))
	
	return u_times_v


def secure_minimum_server(client, public_key, N):
	print("Secure minimum selected, please enter u: ", end='')
	u = public_key.encrypt(int(input()))

	# Recieve v from client
	v = receive(client)
	v_decomp = receive(client)

	send(client, u)
	u_decomp = receive(client)

	# Randomly choose functionality F
	F = choice(['u > v', 'u < v'])

	for u_i, v_i in zip(v_decomp, u_decomp):
		u_times_v = secure_multiplication_server(client, public_key, N, u_i, v_i)

