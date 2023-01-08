import hashlib


def hash_generator(data):
    result = hashlib.sha256(data.encode())
    return result.hexdigest()


class Block:
    def __init__(self, data, hash, prev_hash):
        self.data = data
        self.hash = hash
        self.prev_hash = prev_hash

class Blockchain:
    def __init__(self):
        hashLast = hash_generator('gen_last')
        hashStart = hash_generator('gen_hash')

        genesis = Block('gen-data', hashStart, hashLast)
        self.chain = [genesis]

    def add_block(self, data):
        prev_hash = self.chain[-1].hash # last item hash
        hash = hash_generator(data + prev_hash)
        new_block = Block(data, hash, prev_hash)
        self.chain.append(new_block)

bc = Blockchain()
bc.add_block('1')
bc.add_block('2')
bc.add_block('3')

for block in bc.chain:
    print(block.__dict__)
