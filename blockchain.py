import datetime
import hashlib

from rsassa_pss import RSASSA_PSS


class Block:
    def __init__(self, data, public_key):
        self.public_key = public_key
        self.signature = None
        self.signature_of_public_key = None

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

    def __str__(self):
        sig_hex = self.signature.hex() if self.signature else "None"
        return (
            f"\nHash: {self.hash()}\n"
            f"Index: {self.blockNo}\n"
            f"Data: {self.data}\n"
            f"Signature: {sig_hex}\n"
            f"Nonce: {self.nonce}\n"
            f"----------------------------------------"
        )


class Blockchain:
    def __init__(self, target):
        self.target = target
        self.head = self.curr_block = Block("Genesis", None)

    def add(self, block):
        block.prev_hash = self.curr_block.hash()
        block.blockNo = self.curr_block.blockNo + 1

        self.curr_block.next = self.curr_block = block

        self.mine()

    def mine(self):
        while int(self.curr_block.hash(), 16) > self.target:
            self.curr_block.nonce += 1
        print(self.curr_block)

    def verify_chain(self, authority_modulus):
        seen_keys = set()
        seen_nicknames = set()
        authority_verifier = RSASSA_PSS((0, authority_modulus))

        prev = self.head
        current = prev.next
        expected_index = 1

        while current is not None:
            if not isinstance(current.data, dict):
                raise ValueError(f"Block {current.blockNo}: data must be a dict")

            is_participant = "nickname" in current.data
            is_vote = "voted_for" in current.data

            if is_participant:
                if set(current.data.keys()) != {"nickname", "name"}:
                    raise ValueError(f"Block {current.blockNo}: participant block must have exactly 'nickname' and 'name' keys")
                if not all(isinstance(v, str) for v in current.data.values()):
                    raise ValueError(f"Block {current.blockNo}: all data values must be strings")
            elif is_vote:
                if set(current.data.keys()) != {"voted_for"}:
                    raise ValueError(f"Block {current.blockNo}: vote block must have exactly 'voted_for' key")
                if not isinstance(current.data["voted_for"], str):
                    raise ValueError(f"Block {current.blockNo}: all data values must be strings")
            else:
                raise ValueError(f"Block {current.blockNo}: data must be a participant or vote block")

            if current.blockNo != expected_index:
                raise ValueError(f"Block {current.blockNo}: expected index {expected_index}")

            if current.prev_hash != prev.hash():
                raise ValueError(f"Block {current.blockNo}: broken hash linkage")

            if int(current.hash(), 16) > self.target:
                raise ValueError(f"Block {current.blockNo}: hash does not meet target difficulty")

            if current.timestamp < prev.timestamp:
                raise ValueError(f"Block {current.blockNo}: timestamp is not in chronological order")

            if current.signature is None:
                raise ValueError(f"Block {current.blockNo}: missing block signature")
            verifier = RSASSA_PSS((0, current.public_key))
            if not verifier.verify(current.hash(), current.signature):
                raise ValueError(f"Block {current.blockNo}: invalid block signature")

            if current.signature_of_public_key is None:
                raise ValueError(f"Block {current.blockNo}: missing certificate")
            if not authority_verifier.verify(str(current.public_key), current.signature_of_public_key):
                raise ValueError(f"Block {current.blockNo}: invalid certificate for public key")

            if current.public_key in seen_keys:
                raise ValueError(f"Block {current.blockNo}: duplicate public key (already used in a previous block)")
            seen_keys.add(current.public_key)

            if is_vote and current.public_key % 100 <= 50:
                raise ValueError(f"Block {current.blockNo}: voting block must use a voter key (public_key % 100 > 50)")
            if is_participant and current.public_key % 100 >= 50:
                raise ValueError(f"Block {current.blockNo}: participant block must use a participant key (public_key % 100 < 50)")

            if is_participant:
                nickname = current.data["nickname"]
                if nickname in seen_nicknames:
                    raise ValueError(f"Block {current.blockNo}: duplicate nickname '{nickname}'")
                seen_nicknames.add(nickname)

            prev = current
            current = current.next
            expected_index += 1
