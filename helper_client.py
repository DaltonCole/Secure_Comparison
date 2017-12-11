
from helper_helper import send, receive, get_vector_input

get_vector_input_client = get_vector_input

def bit_decomposition(num, public_key, private_key):
	num = private_key.decrypt(num)

	bits = "{0:b}".format(num)

	while len(bits) != 32:
		bits = '0' + bits

	encrypted_bits = []

	for i in bits:
		encrypted_bits.append(public_key.encrypt(int(i)))

	return encrypted_bits

def binary_decomposition_client(public_key, num):
	bd = [int(x) for x in "{0:b}".format(num)]
	bd = ([0] * (32 - len(bd))) + bd

	return [public_key.encrypt(x) for x in bd]

def print_menu():
	print("Please choose one of the following options:")
	print("\t(1) Secure Multiplication")
	print("\t(2) Secure Minimum")
	print("\t(3) Secure Squared Euclidean Distance")
	print("\t(4) Secure Bit Decomposition")
	print("\t(9) QUIT")
	print()
	print("Option Number: ", end="")

	return str(input())

def secure_multiplication_client(server, public_key, private_key, N):
	# Recieve a' and b' from server
	a_prime = receive(server)
	b_prime = receive(server)

	# Decrypt
	ha = private_key.decrypt(a_prime)
	hb = private_key.decrypt(b_prime)

	# Multiply
	h = (ha * hb) % N

	# Send E(h) to server
	send(server, h)


def secure_lsb_client(server, private_key):
	Y = receive(server)
	y = private_key.decrypt(Y)

	if not y % 2: # y is even
		alpha = 0
	else:
		alpha = 1

	send(server, private_key.public_key.encrypt(alpha))


def svr_client(server, private_key):
	W = receive(server)

	if private_key.decrypt(W) == 0:
		γ = 1
	else:
		γ = 0

	send(server, γ)
	return γ


def secure_bit_decomposition_client(server, private_key):
	bitlength_m = receive(server)

	for i in range(0, bitlength_m):
		secure_lsb_client(server, private_key)

	if svr_client(server, private_key) == 1:
		return
	else:
		return secure_bit_decomposition_client(server, private_key)


def secure_minimum_client(server, public_key, private_key, N):
	for i in range(32):
		secure_multiplication_client(server, public_key, private_key, N)

	# Receive Gamma' and L'
	Gamma_prime = receive(server)
	L_prime = receive(server)

	# Decrypt L
	M = []
	for i in L_prime:
		M.append(private_key.decrypt(i))

	alpha = 0
	for i in M:
		if 1 == (i % N):
			alpha = 1
			break

	M_prime = []
	for g in Gamma_prime:
		M_prime.append(g * alpha)

	# Send M' and E(alpha)
	send(server, M_prime)
	send(server, public_key.encrypt(alpha))


def secure_squared_euclidean_distance_client(server, public_key, private_key, N, length):
	for i in range(length):
		secure_multiplication_client(server, public_key, private_key, N)
