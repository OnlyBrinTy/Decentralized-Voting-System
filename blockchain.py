import datetime
import hashlib

MAX_NONCE = 2**32


def sign_block(block, signer):
    block_hash = block.hash()
    return signer.sign(block_hash)


def verify_block(block, signature, signer):
    block_hash = block.hash()
    return signer.verify(block_hash, signature)


class Block:
    def __init__(self, data):
        self.blockNo = 0
        self.data = data
        self.next = None
        self.nonce = 0
        self.timestamp = datetime.datetime.now()
        self.prev_hash = 0x0
        self.signature = None

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
    target = 2 ** (256 - diff)

    head = curr_block = Block("Genesis")

    def __init__(self, signer):
        self.signer = signer
        self.curr_block.signature = sign_block(self.curr_block, self.signer)

    def add(self, block):
        block.prev_hash = self.curr_block.hash()
        block.blockNo = self.curr_block.blockNo + 1
        self.curr_block.next = self.curr_block = block

    def mine(self, block):
        for _ in range(MAX_NONCE):
            if int(block.hash(), 16) <= self.target:
                self.add(block)
                block.signature = sign_block(block, self.signer)
                print(block)
                break
            else:
                block.nonce += 1


def verify_chain(blockchain: Blockchain):
    current = blockchain.head
    while current is not None:
        if current.signature is None:
            return False, f"Block {current.blockNo} has no signature"
        if not verify_block(current, current.signature, blockchain.signer):
            return False, f"Block {current.blockNo} has invalid signature"
        current = current.next
    return True, "All blocks verified successfully"
