import socket
from phe import paillier
import pickle
from random import randrange, choice, shuffle
from sys import getsizeof
from time import sleep

def receive(socket):
	buffer_size = pickle.loads(socket.recv(128))
	r = socket.recv(buffer_size)
	return pickle.loads(r)

def send(socket, data):
	# Send buffer size
	socket.send(pickle.dumps(getsizeof(pickle.dumps(data))))
	sleep(0.1)
	socket.send(pickle.dumps(data))
	sleep(0.1)

def permute(l):
	other = [x for x in range(0, len(l))]
	shuffle(other)

	return [l[x] for x in other], other

def un_permute(l, other):
	a = [0] * len(l)

	for x, y in zip(l, other):
		a[y] = x

	return a


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

def binary_decomposition_server(public_key, num):
	bd = [int(x) for x in "{0:b}".format(num)]
	bd = ([0] * (32 - len(bd))) + bd

	return [public_key.encrypt(x) for x in bd]

def secure_minimum_server(client, public_key, N, u_decomp, v_decomp):
	# Randomly choose functionality F
	F = choice(['u > v', 'u < v'])

	# Initalize
	H_i = public_key.encrypt(0)
	L = []
	Gamma = []
	r = []

	# For each bit
	for u_i, v_i in zip(u_decomp, v_decomp):
		u_times_v = secure_multiplication_server(client, public_key, N, u_i, v_i)

		r.append(randrange(0, N))
		if F == 'u > v':
			W_i = u_i + (u_times_v * (N - 1))
			Gamma.append((v_i - u_i) + public_key.encrypt(r[-1]))
		else:
			W_i = v_i + (u_times_v * (N - 1))
			Gamma.append((u_i - v_i) + public_key.encrypt(r[-1]))

		# XOR
		G_i = u_i + v_i + (u_times_v * (N - 2))

		H_i = (H_i * randrange(0, N)) + G_i

		Phi_i = public_key.encrypt(-1) + H_i

		L.append(W_i + (Phi_i * randrange(0, N)))

	Gamma_prime, gamma_permute_key = permute(Gamma)
	L_prime, _ = permute(L)

	send(client, Gamma_prime)
	send(client, L_prime)

	# Recieve M' and E(alpha)
	M_prime = receive(client)
	alpha = receive(client)

	# De-permute M
	M = un_permute(M_prime, gamma_permute_key) 

	minimum = []
	for i in range(32):
		lambda_i = M[i] + (alpha * (N - r[i]))

		if F == 'u > v':
			minimum.append(u_decomp[i] + lambda_i)
		else:
			minimum.append(v_decomp[i] + lambda_i)

	total_minimum = public_key.encrypt(0)
	for i in range(32):
		total_minimum += (minimum[31 - i] * (2 ** i))

	return total_minimum

def get_vector_input_server(public_key):
	print("\nEnter comma delimited vector: ")
	v = input().split(',')
	return [public_key.encrypt(int(x)) for x in v]

def secure_squared_euclidean_distance_server(client, public_key, N, u, v):
	u_minus_v = [(a - b) for a, b in zip(u, v)]

	squared = [secure_multiplication_server(client, public_key, N, x, x) for x in u_minus_v]

	summed = public_key.encrypt(0)

	for i in squared:
		summed += i

	return summed