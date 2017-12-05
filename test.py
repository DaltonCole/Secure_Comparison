import pickle
from phe import paillier

public_key, private_key = paillier.generate_paillier_keypair()

data = pickle.dumps(public_key)
other_data = pickle.loads(data)

a = public_key.encrypt(1000)

data = pickle.dumps(a)
a = pickle.loads(data)

print(private_key.decrypt(a))