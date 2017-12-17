
import pickle

DEFAULT_PORT = 49556

def receive(sock):
    rawsize = sock.recv(128)
    size = int.from_bytes(rawsize, 'big')

    r = buf_r = b''
    while len(r) < size:
        if buf_r: print("###Going for seconds...")
        buf_r = sock.recv(size - len(r))
        if not buf_r:
            if len(r) < size: print("###Predicting pickle error")
            break
        r += buf_r

    return pickle.loads(r)

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
