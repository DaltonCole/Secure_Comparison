
from operator import itemgetter

from helper_helper import send, receive
from helper_server import secure_squared_euclidean_distance_server


def secure_kNN_C1(Bob, C2, database_T, public_key, k, m, n):
	"""
		database_T = E(t)
		n = db length / number of rows
		m = db row width / number of attributes
	"""

	## Part 2
	Q = receive(Bob)
	l = []
	for i, t in enumerate(database_T):
		d_i = secure_squared_euclidean_distance_server(C2, public_key, Q, t)
		l.append((i, d_i))

	# Send to C2
	send(C2, l)

	## Part 4
	# Receive delta from C2
	delta = receive(C2)

	for j, i_j in enumerate(delta):
		for h in range(m):
			r = public_key.get_random_lt_n()
			gamma = database_T[i_j][h] + r
			send(C2, gamma)
			send(Bob, r)



def secure_kNN_C2(Bob, C1, private_key, k, m, n):

	## Part 2
	for i in range(n):
		secure_squared_euclidean_distance_client(C1, private_key, m)

	## Part 3
	l = receive(C1)
	assert isinstance(l, list)
	assert isinstance(l[0], tuple)
	d = [(i, private_key.decrypt(d_i)) for (i, d_i) in l]

	# Calculate k minimum values
	sorted_d = sorted(d, key=itemgetter(1))
	best_k = sorted_d[:k]
	delta = tuple(i for (i, d_i) in best_k)

	# Send delta to C2
	send(C1, delta)

	## Part 5
	for j in range(k):
		for h in range(m):
			gamma = receive(C1)
			gamma_prime = private_key.decrypt(gamma)
			send(Bob, gamma_prime)


def bit_decomposition(num, private_key):
	num = private_key.decrypt(num)

	bits = "{0:b}".format(num)

	while len(bits) != 32:
		bits = '0' + bits

	encrypted_bits = []

	for i in bits:
		encrypted_bits.append(private_key.public_key.encrypt(int(i)))

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
	print("\t(5) Secure Bit-OR")
	print("\t(6) Secure Minimum-of-n")
	print("\t(C2) Secure k-Nearest Neighbor C2, keyholder")
	print("\t(C1) Secure k-Nearest Neighbor C1, database")
	print("\t(9) QUIT")
	print()
	print("Option Number: ", end="")

	return str(input())


def secure_multiplication_client(server, private_key):
	# Recieve a' and b' from server
	a_prime = receive(server)
	b_prime = receive(server)

	# Decrypt
	ha = private_key.decrypt(a_prime)
	hb = private_key.decrypt(b_prime)

	# Multiply
	h = (ha * hb) % private_key.public_key.n

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


def secure_minimum_of_n_client(server, private_key):
	n = receive(server)
	for _ in range(n):
		secure_bit_decomposition_client(server, private_key)
	for _ in range(n - 1):
		secure_minimum_client(server, private_key)


def secure_minimum_client(server, private_key):
	for i in range(32):
		secure_multiplication_client(server, private_key)

	# Receive Gamma' and L'
	Gamma_prime = receive(server)
	L_prime = receive(server)

	# Decrypt L
	M = []
	for i in L_prime:
		M.append(private_key.decrypt(i))

	alpha = 0
	for i in M:
		if 1 == (i % private_key.public_key.n):
			alpha = 1
			break

	M_prime = []
	for g in Gamma_prime:
		M_prime.append(g * alpha)

	# Send M' and E(alpha)
	send(server, M_prime)
	send(server, private_key.public_key.encrypt(alpha))


def secure_squared_euclidean_distance_client(server, private_key, length):
	for i in range(length):
		secure_multiplication_client(server, private_key)
