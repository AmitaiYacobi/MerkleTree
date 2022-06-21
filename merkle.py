import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class MerkleTree:
    def __init__(self, hash_function):
        self.leafs = []
        self.root = None
        self.hash = hash_function

    def add_leaf(self, leaf_string):
        leaf_hash = self.hash(leaf_string.encode('utf-8')).hexdigest()
        leaf = (leaf_string, leaf_hash)
        self.leafs.append(leaf)
        hash_leafs = [leaf[1] for leaf in self.leafs]
        self.update_root(hash_leafs)

    def update_root(self, level):
        if len(level) == 1:
            self.root = level[0]
            return
        else:
            higher_level = []
            for i in range(0, len(level), 2):
                if i == len(level) - 1:
                    higher_level.append(level[i])
                    break
                else:
                    concatenated = "".join([level[i], level[i + 1]])
                    higher_level.append(self.hash(concatenated.encode('utf-8')).hexdigest())

            self.update_root(higher_level)

    def get_root(self):
        if self.root is None:
            print("")
        else:
            print(self.root)

    def get_proof_of_inclusion(self, position):
        position = int(position)
        if position < 0 or position > len(self.leafs) - 1:
            print("")
            return

        hash_leafs = [leaf[1] for leaf in self.leafs]
        proof = [self.root]
        proof = self.calculate_hashes(hash_leafs, position, proof)
        print(" ".join(proof))

    def calculate_hashes(self, level, position, proof):
        if len(level) == 1:
            return proof
        else:
            higher_level = []
            for i in range(0, len(level), 2):
                if i == len(level) - 1:
                    higher_level.append(level[i])
                    break
                else:
                    concatenated = "".join([level[i], level[i + 1]])
                    higher_level.append(self.hash(concatenated.encode('utf-8')).hexdigest())
            if position % 2 == 0:
                if position == len(level) - 1:
                    new_position = len(higher_level) - 1
                else:
                    proof.append('1' + level[position + 1])
                    concatenated = "".join([level[position], level[position + 1]])
                    hash_concatenated = self.hash(concatenated.encode('utf-8')).hexdigest()
                    new_position = higher_level.index(hash_concatenated)
                return self.calculate_hashes(higher_level, new_position, proof)
            else:
                proof.append('0' + level[position - 1])
                concatenated = "".join([level[position - 1], level[position]])
                hash_concatenated = self.hash(concatenated.encode('utf-8')).hexdigest()
                new_position = higher_level.index(hash_concatenated)
                return self.calculate_hashes(higher_level, new_position, proof)

    def check_proof_of_inclusion(self, leaf, proof):
        proof = " ".join(proof)
        hash_leafs = [leaf[1] for leaf in self.leafs]
        hash_leaf = self.hash(leaf.encode('utf-8')).hexdigest()
        position = hash_leafs.index(hash_leaf)
        real_proof = " ".join(self.calculate_hashes(hash_leafs, position, [self.root]))
        if proof == real_proof:
            print(True)
        else:
            print(False)

    def create_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        sk_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        pk_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print(str(sk_pem.decode()))
        print(str(pk_pem.decode()))

    def create_sign_on_root(self, inpt):
        line = input()
        private_key = inpt[2:]
        while line != "-----END RSA PRIVATE KEY-----":
            private_key += '\n'
            private_key += line
            line = input()
        private_key += '\n'
        private_key += line

        sign_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None,
        )

        signature = sign_key.sign(
            self.root.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signature = base64.b64encode(signature)
        print(signature.decode())

    def verify_sign(self, inpt):
        line = input()
        public_key = inpt[2:]
        while line != "-----END PUBLIC KEY-----":
            public_key += '\n'
            public_key += line
            line = input()
        public_key += '\n'
        public_key += line
        line = input()
        while line == '':
            line = input()
        sign_text = line.split(" ")
        if len(sign_text) == 2 and sign_text[1] != '':
            sign = sign_text[0]
            text = sign_text[1]
        else:
            sign = line
            text = input()
            while text == '':
                text = input()

        verify_key = serialization.load_pem_public_key(
            public_key.encode(),
            backend=None
        )

        try:
            verify_key.verify(
                base64.decodebytes(sign.encode()),
                text.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(True)

        except InvalidSignature:
            print(False)


def do_action(merkle_tree, option, first_line, inpt):
    if option == '1' and len(first_line) > 1:
        merkle_tree.add_leaf(first_line[1])

    elif option == '2' and len(first_line) == 1:
        merkle_tree.get_root()

    elif option == '3' and len(first_line) > 1:
        merkle_tree.get_proof_of_inclusion(first_line[1])

    elif option == '4' and len(first_line) > 2:
        merkle_tree.check_proof_of_inclusion(first_line[1], first_line[2:])

    elif option == '5':
        merkle_tree.create_keys()

    elif option == '6' and len(first_line) > 1:
        merkle_tree.create_sign_on_root(inpt)

    elif option == '7' and len(first_line) > 1:
        merkle_tree.verify_sign(inpt)

    else:
        print('')


def main():
    hash_function = hashlib.sha256
    merkle_tree = MerkleTree(hash_function)
    while True:
        inpt = input()
        first_line = inpt.split(' ')
        if first_line[0] == '':
            print('')
        else:
            option = inpt[0]
            do_action(merkle_tree, option, first_line, inpt)


if __name__ == "__main__":
    main()
