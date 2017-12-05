import socket
from phe import paillier
import pickle
from random import randrange
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

def bit_decomposition(socket, num, public_key, private_key):
	num = private_key.decrypt(num)

	bits = "{0:b}".format(num)

	while len(bits) != 32:
		bits = '0' + bits

	encrypted_bits = []

	for i in bits:
		encrypted_bits.append(public_key.encrypt(int(i)))

	return encrypted_bits

def print_menu():
	print("Please choose one of the following options:")
	print("\t(1) Secure Multiplication")
	print("\t(2) Secure Minimum")
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


def secure_minimum_client(server, public_key, private_key, N):
	print("Secure minimum selected, please enter v: ", end='')
	v = int(input())

	# Send v to server
	send(server, v)

	# Send v's bits to server
	send(server, bit_decomposition(server, public_key.encrypt(v), public_key, private_key))

	# Decompose 
	t = receive(server)
	send(server, bit_decomposition(server, t, public_key, private_key))

	for i in range(32):
		secure_multiplication_client(server, public_key, private_key, N)
