"""
Minimal blockchain used by the voting CLI.

Design choices (and why):
- The chain is stored as a singly-linked list (`Block.next`) because the CLI appends
  blocks sequentially and only ever traverses from the head; this keeps the model
  simple and makes rollback (unlinking the last block) trivial.
- Each block commits to its predecessor via `prev_hash`, and we recompute hashes
  from the in-memory fields to detect any tampering.
- Proof-of-Work is implemented as a hash target (`self.target`) to make blocks
  expensive to create. This is not meant to be production-grade consensus; it is a
  teaching/demo mechanism to make blocks non-trivial to forge.
- Blocks are signed (RSASSA-PSS) with the block creator’s key, and public keys are
  “certified” by an Authority signature to prevent arbitrary keys from being used.
- Validation is run after every attempted append; if validation fails, the append
  is rolled back so invalid blocks never persist in the chain.
"""

import datetime
import hashlib

from rsassa_pss import verify_signature


class Block:
    """A single block in the chain.

    Fields are intentionally simple and fully included in the block hash.
    The `data` payload is restricted by validation to one of two schemas:
    - participant registration: {"nickname": str, "name": str}
    - vote: {"voted_for": str}
    """

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
        """Compute the block hash over the current in-memory fields."""
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
            f"\nPrev hash: {self.prev_hash}\n"
            f"\nHash: {self.hash()}\n"
            f"Index: {self.blockNo}\n"
            f"Data: {self.data}\n"
            f"Signature: {sig_hex}\n"
            f"Nonce: {self.nonce}\n"
            f"----------------------------------------"
        )


class Blockchain:
    """Append-only chain with validation and rollback-on-failure.

    The CLI uses `add()` to attempt to append a new block. `add()` performs:
    link -> mine -> sign -> validate (entire chain). If validation fails, the new
    block is unlinked so the chain remains valid.
    """

    def __init__(self, target):
        """Create a new chain with the given Proof-of-Work target."""
        self.target = target
        self.head = self.curr_block = Block("Genesis", None)

    def add(self, block, signer, authority_modulus):
        """Attempt to append `block` to the chain.

        - Sets `prev_hash` and `blockNo`
        - Mines the block under `self.target`
        - Signs the mined block hash using `signer`
        - Validates the full chain; rolls back if validation fails
        """
        prev = self.curr_block
        block.prev_hash = prev.hash()
        block.blockNo = prev.blockNo + 1

        self.curr_block.next = self.curr_block = block
        self.mine()
        block.signature = signer.sign(block.hash())

        try:
            self.verify_chain(authority_modulus)
        except ValueError:
            prev.next = None
            self.curr_block = prev
            raise

    def mine(self):
        """Mine the current tip (`self.curr_block`) to satisfy the PoW target."""
        while int(self.curr_block.hash(), 16) > self.target:
            self.curr_block.nonce += 1
        print(self.curr_block)

    def verify_chain(self, authority_modulus):
        """Validate the full chain.

        Raises:
            ValueError: with a human-readable explanation of the first failure.

        What is validated (non-genesis blocks):
        - Indexes are sequential
        - Hash links are correct
        - Hash meets the PoW target
        - Timestamps are non-decreasing
        - Block signature is valid for the block hash
        - Public key certificate is valid under the Authority key
        - A public key is used at most once (prevents double-voting / duplicate registration)
        - Participant nicknames are unique
        - Vote targets must refer to an existing participant registered earlier in the chain
        - Key “type” matches block type via the modulus % 100 convention
        """
        seen_keys = set()
        seen_nicknames = set()

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
            block_hash = hashlib.sha256(current.hash().encode("utf-8")).digest()
            if not verify_signature(current.public_key, block_hash, current.signature):
                raise ValueError(f"Block {current.blockNo}: invalid block signature")

            if current.signature_of_public_key is None:
                raise ValueError(f"Block {current.blockNo}: missing certificate")
            cert_hash = hashlib.sha256(str(current.public_key).encode("utf-8")).digest()
            if not verify_signature(authority_modulus, cert_hash, current.signature_of_public_key):
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

            if is_vote:
                candidate = current.data["voted_for"]
                if candidate not in seen_nicknames:
                    raise ValueError(f"Block {current.blockNo}: candidate '{candidate}' does not exist")

            prev = current
            current = current.next
            expected_index += 1
