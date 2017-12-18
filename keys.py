
import json

from phe import paillier


def _pick_max_int(pk: paillier.PaillierPublicKey) -> int:
    return pk.n - 1


def make_pk(n: int) -> paillier.PaillierPublicKey:
    pk = paillier.PaillierPublicKey(n)
    pk.max_int = _pick_max_int(pk)
    return pk


def make_sk(n: int, p: int, q: int):
    pk = make_pk(n)
    return paillier.PaillierPrivateKey(pk, p, q)


def pk_to_file(pk: paillier.PaillierPublicKey, pkfile):
    # n
    data = {
        "n": pk.n
    }
    json.dump(data, pkfile, indent='\t')


def sk_to_file(sk: paillier.PaillierPrivateKey, skfile):
    # n, p, q
    data = {
        "n": sk.public_key.n,
        "p": sk.p,
        "q": sk.q
    }
    json.dump(data, skfile, indent='\t')


def pk_from_file(pkfile) -> paillier.PaillierPublicKey:
    data = json.load(pkfile)
    if "n" not in data:
        raise ValueError("pk file is missing key 'n'")

    return make_pk(data['n'])


def sk_from_file(skfile) -> paillier.PaillierPrivateKey:
    data = json.load(skfile)
    if any(attr not in data for attr in ('n', 'p', 'q')):
        raise ValueError("Missing keys in sk file")

    pk = make_pk(data['n'])
    sk = paillier.PaillierPrivateKey(pk, data['p'], data['q'])

    return sk


def generate_keypair(opt=None, basename=None):
    print("## Interactive Key Generation ##")

    if opt is None:
        print("How would you like to generate your key?")
        opt = input("(b) by bit-length, or (p) from p and q: ").lower()

    pk = sk = None

    if 'b' in opt:
        blen = input("Enter a bit-length for n (default: 2048): ").strip()
        blen = int(blen) if blen else paillier.DEFAULT_KEYSIZE
        pk, sk = paillier.generate_paillier_keypair(None, blen)
        pk.max_int = sk.public_key.max_int = _pick_max_int(pk)
    elif 'p' in opt:
        p = int(input("Enter private secret 'p': ").strip())
        q = int(input("Enter private secret 'q': ").strip())
        n = p * q
        sk = make_sk(n, p, q)
        pk = sk.public_key
    else:
        raise ValueError("Bad input option {!r}".format(opt))

    if basename is None:
        basename = input("Enter a basename for the key files: ")

    pkname = '{}.public.json'.format(basename)
    skname = '{}.private.json'.format(basename)

    with open(pkname, 'w') as pkfile:
        pk_to_file(pk, pkfile)
    print("Wrote pk to {!r}".format(pkname))
    with open(skname, 'w') as skfile:
        sk_to_file(sk, skfile)
    print("Wrote sk to {!r}".format(skname))

    return pk, sk


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser("Generate Paillier key pair interactively.")
    parser.add_argument('--name', help="Base file name for the output files.")
    exclus_grp = parser.add_mutually_exclusive_group()
    exclus_grp.add_argument('-p', '--pq', help="Generate from p and q values.",
                            action='store_const', const='p', dest='opt')
    exclus_grp.add_argument('-b', '--bit', help="Generate by bit-length.",
                            action='store_const', const='b', dest='opt')


    ARGS = parser.parse_args()

    generate_keypair(ARGS.opt, ARGS.name)
