import socket
import sys
import argparse

from helper_helper import send, receive, get_vector_input, DEFAULT_PORT
from helper_client import  print_menu, read_csv_database, \
	secure_kNN_C1, secure_kNN_C2, \
	secure_multiplication_client, secure_bit_decomposition_client, \
	secure_minimum_client, secure_squared_euclidean_distance_client, \
	secure_minimum_of_n_client
from keys import sk_from_file, generate_keypair

OPTIONS = ('c1', 'c2', 'C1', 'C2', '1', '2', '3', '4', '5', '6', '9')

parser = argparse.ArgumentParser(description="Client for SkNN and its "
								"subprotocols.")
parser.add_argument('port', type=int, default=DEFAULT_PORT, nargs='?',
					help='port to connect to (default: %(default)s)')
parser.add_argument('-s', '--secret-key', type=argparse.FileType(),
					dest='sk', help='pregenerated secret key. If omitted we '
					'will generate a key pair.')
parser.add_argument('-o', '--option', choices=OPTIONS, metavar='OPT',
					dest='option', help='the option to execute. Start interactively to see available options')

ARGS = parser.parse_args()
port = ARGS.port
public_key = private_key = None

if ARGS.sk:
	private_key = sk_from_file(ARGS.sk)
	public_key = private_key.public_key
else:
	print("No secret key provided, starting key generation.")
	public_key, private_key = generate_keypair()


### Initalize Connection Process ###
# create a socket object
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = 'localhost'

if port < 1024 or 65535 < port:
	raise RuntimeError("Bad port, should be in [49153, 65534]")

# connection to hostname on the port.
server.connect((host, port))
#####################################

### Send Config Paramaters ###
# Send Public Key
send(server, public_key)
##############################

### Start Menu ###
while True:
	option = ARGS.option or print_menu()

	if 'c' in option.lower():
		Bob = server

		if '2' in option:
			# job is 'C2'
			send(server, 'c2')

			print("Secure k-Nearest Neighbor selected, you are C2.")
			port_C1C2 = port - 1
			send(server, port_C1C2)

			socket_C1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket_C1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			socket_C1.bind((host, port_C1C2))
			socket_C1.listen(10)
			print("Waiting for C1...")
			C1, C1_addr = socket_C1.accept()
			print("Heard from C1!")

			checkval = receive(C1)
			if checkval != port_C1C2:
				raise RuntimeError("Bad checkval from C1.")
			print("OK checkval from C1.")

			send(C1, public_key)

			m_n = receive(C1)
			assert isinstance(m_n, tuple) and len(m_n) == 2
			m, n = m_n

			print("Sent pk to C1. Starting SkNN.")
			secure_kNN_C2(Bob, C1, private_key, m, n)

			# TODO: handle result

		elif '1' in option:
			# job is 'C1'
			send(server, 'c1')

			print("Secure k-Nearest Neighbor selected, you are C1.")

			port_C1C2 = receive(Bob)
			print("Connecting to C2...")
			C2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			C2.connect((host, port_C1C2))
			send(C2, port_C1C2)
			pk = receive(C2)
			print("Received pk from C2.")

			print("Enter the filename of T, the encrypted database: ", end='')
			Tname = input('')
			database_T = read_csv_database(Tname, pk)
			m = len(database_T[0])
			n = len(database_T)
			print("Read database. (attributes, records) = (m, n) =", (m, n))

			send(Bob, (m, n))
			send(C1, (m, n))

			print("Read database. Starting SkNN.")
			secure_kNN_C1(Bob, C2, database_T, pk, m, n)

			# C1 is doesn't have a 'normal' connection to server, so we bail
			print("Thanks for your help, C1!")
			server.close()
			sys.exit()

		else:
			raise ValueError("Bad option {!r}".format(option))

	elif '1' in option:
		send(server, '1')
		print("Secure multiplication selected, please enter v: ", end='')
		# Get user input
		v = public_key.encrypt(int(input()))
		# Send v to server
		send(server, v)
		print("Sent v to server")
		secure_multiplication_client(server, public_key, private_key)

		# Confirmation for convenience of user
		print("u * v = {}".format(private_key.decrypt(receive(server))))
	elif '2' in option:
		send(server, '2')
		print("Secure minimum selected, please enter v: ", end='')
		enc_v = public_key.encrypt(int(input()))
		send(server, enc_v)
		secure_bit_decomposition_client(server, private_key)
		secure_bit_decomposition_client(server, private_key)
		secure_minimum_client(server, public_key, private_key)
		print("Min(u, v) = {}".format(private_key.decrypt(receive(server))))
	elif '3' in option:
		send(server, '3')
		print("Secure squared euclidean distance selected, please enter v: ", end='')
		v = get_vector_input(public_key)
		send(server, v)
		secure_squared_euclidean_distance_client(server, public_key, private_key, len(v))
		print("SSED(u, v) = {}".format(private_key.decrypt(receive(server))))

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
		secure_multiplication_client(server, public_key, private_key)
		print("OR(o1, o2) = {}".format(private_key.decrypt(receive(server))))

	elif '6' in option:
		print("Secure minimum-of-n selected, please enter some numbers: ", end='')
		d = tuple(map(int, input().split()))
		if len(d) < 2 and 'y' not in input("Too few inputs, 'y' to override: "):
			continue
		send(server, '6')

		enc_d = tuple(map(public_key.encrypt, d))
		send(server, enc_d)
		print("Sent [d] to server.")
		secure_minimum_of_n_client(server, private_key)
		dmin = receive(server)
		print("min(d) = {}".format(private_key.decrypt(dmin)))

	elif '9' in option or 'q' in option.lower():
		send(server, '9')
		break
	print()

"""
msg = pickle.loads(s.recv(4096))
print(private_key.decrypt(msg))
"""

server.close()
