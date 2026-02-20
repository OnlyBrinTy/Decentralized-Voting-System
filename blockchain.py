import datetime
import hashlib


class Block:
    def __init__(self, data, public_key):
        self.public_key = public_key
        self.signature = None

        self.blockNo = 0
        self.data = data
        self.next = None
        self.nonce = 0
        self.timestamp = datetime.datetime.now()
        self.prev_hash = 0x0

    def hash(self):
        h = hashlib.sha256()
        h.update(
            str(self.nonce).encode("utf-8")
            + str(self.data).encode("utf-8")
            + str(self.prev_hash).encode("utf-8")
            + str(self.timestamp).encode("utf-8")
            + str(self.blockNo).encode("utf-8")
        )
        return h.hexdigest()

    def mine(self, target):
        while int(self.hash(), 16) > target:
            self.nonce += 1
            
        print(self)


    def __str__(self):
        sig_hex = self.signature.hex()[:32] + "..." if self.signature else "None"
        return (
            f"Hash: {self.hash()}\n"
            f"Index: {self.blockNo}\n"
            f"Data: {self.data}\n"
            f"Signature: {sig_hex}\n"
            f"Nonce: {self.nonce}\n"
            f"----------------------------------------"
        )


class Blockchain:
    head = curr_block = Block("Genesis")

    def add(self, block):
        block.prev_hash = self.curr_block.hash()
        block.blockNo = self.curr_block.blockNo + 1

        self.curr_block.next = self.curr_block = block

def verify_chain(blockchain: Blockchain):
    current = blockchain.head
    while current is not None:
        if current.signature is None:
            return False, f"Block {current.blockNo} has no signature"
        if not verify_block(current, current.signature, blockchain.signer):
            return False, f"Block {current.blockNo} has invalid signature"
        current = current.next
    return True, "All blocks verified successfully"
