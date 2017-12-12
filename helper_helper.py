
import pickle

def receive(sock):
    rawsize = sock.recv(128)
    size = int.from_bytes(rawsize, 'big')
    r = sock.recv(size)
    try:
        return pickle.loads(r)
    except Exception as err:
        print("###\n size = {}\n r = {}\n###".format(size, r))
        raise

def send(sock, data):
    pdata = pickle.dumps(data)
    size = len(pdata)
    rawsize = size.to_bytes(128, byteorder='big')
    sock.sendall(rawsize)
    sock.sendall(pdata)

def get_vector_input(public_key):
	print("\nEnter comma delimited vector: ")
	v = input().split(',')
	return [public_key.encrypt(int(x)) for x in v]
