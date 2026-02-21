"""Interactive CLI for the blockchain-based voting demo.

Core flow:
- The Authority issues keys and signs (certifies) their public moduli.
- Users submit a certified key + private exponent to create blocks.
- The blockchain appends blocks via `Blockchain.add()`, which mines, signs, and
  validates the full chain; invalid blocks are rolled back automatically.
"""

import hashlib

from rsassa_pss import RSASSA_PSS, verify_signature
from blockchain import Block, Blockchain
from authority import Authority
from time import sleep

HELP_MESSAGE = """
Commands:
/issue_keys
/add_participant <nickname> <name> <participant_private_key> <participant_public_key> <participant_signature>
/vote <participant_nickname> <voter_private_key> <voter_public_key> <voter_signature>
/view_blockchain
/check_signature <public_key> <message_hash_hex> <signature_hex>
/list_all_participants
/exit
"""


class VotingCLI:
    """Command-line interface for issuing keys, registering candidates, and voting."""

    def __init__(self):
        difficulty = int(input("Set blockchain compute complexity from 0 to 30:"))
        self.authority = Authority()
        self.blockchain = Blockchain(2 ** (256 - difficulty))

    def _validate_key_and_signature(self, private_key, public_key, signature):
        parsed_private_key = int(private_key)
        parsed_public_key = int(public_key)
        parsed_signature = bytes.fromhex(signature)
        cert_hash = hashlib.sha256(str(parsed_public_key).encode("utf-8")).digest()
        if not verify_signature(self.authority.modulus, cert_hash, parsed_signature):
            raise ValueError("Unauthorized public key")

        return parsed_private_key, parsed_public_key, parsed_signature

    def issue_keys(self):
        voter_key, voting_signature = self.authority.issue_voter_key()
        participant_key, participant_signature = self.authority.issue_participant_key()
        print(
            "An authority has issued keys for you. Keep them secret. 'Public' and 'Private' keys are represented as public and private exponents respectively.\n\n"
        )
        print(f"Voter private key: {voter_key[0]}")
        print(f"Voter public key: {voter_key[1]}")
        print(f"Voter  signature: {voting_signature.hex()}")
        print(f"Participant private key: {participant_key[0]}")
        print(f"Participant public key: {participant_key[1]}")
        print(f"Participant signature: {participant_signature.hex()}")

    def add_participant(
        self, nickname, name, private_key, public_key, participant_signature
    ):
        private_key, public_key, signature = self._validate_key_and_signature(
            private_key, public_key, participant_signature
        )
        signer = RSASSA_PSS((private_key, public_key))

        block = Block({"nickname": nickname, "name": name}, public_key)
        block.signature_of_public_key = signature

        self.blockchain.add(block, signer, self.authority.modulus)

        print(f"Participant added: {nickname} ({name})")

    def vote(self, participant_nickname, private_key, public_key, voter_signature):
        private_key, public_key, signature = self._validate_key_and_signature(
            private_key, public_key, voter_signature
        )
        signer = RSASSA_PSS((private_key, public_key))

        block = Block({"voted_for": participant_nickname}, public_key)
        block.signature_of_public_key = signature

        self.blockchain.add(block, signer, self.authority.modulus)

        print(f"Vote recorded: {participant_nickname}")

    def view_blockchain(self):
        print("Viewing blockchain...")
        current = self.blockchain.head
        while current is not None:
            print(current, end="\n\n")
            current = current.next

    def check_signature(self, signer_modulus, message_hash_hex, signature_hex):
        modulus = int(signer_modulus)
        message_hash = bytes.fromhex(message_hash_hex)
        signature = bytes.fromhex(signature_hex)
        is_valid = verify_signature(modulus, message_hash, signature)
        print(f"Signature valid: {is_valid}")

    def list_all_participants(self):
        print("Listing all participants...")

        participants = {}

        current = self.blockchain.head.next
        while current is not None:
            if current.data.get("nickname"):
                participants[current.data["nickname"]] = 0
            elif current.data.get("voted_for"):
                participants[current.data["voted_for"]] += 1

            current = current.next

        participants = sorted(participants.items(), key=lambda x: x[1], reverse=True)

        print("\n\nParticipants:")
        for participant, votes in participants:
            print(f"{participant}: {votes} votes")

    def run(self):
        print(
            f"\nAuthority's public key: {self.authority.modulus}\n\nUse it to check the validity of participants' public keys. Only the authority can issue valid public keys."
        )
        sleep(1)

        while True:
            print(HELP_MESSAGE)
            user_input = input()
            args = user_input.split()

            try:
                match args[0]:
                    case "/issue_keys":
                        self.issue_keys()
                    case "/add_participant":
                        self.add_participant(
                            args[1], args[2], args[3], args[4], args[5]
                        )
                    case "/vote":
                        self.vote(args[1], args[2], args[3], args[4])
                    case "/check_signature":
                        self.check_signature(args[1], args[2], args[3])
                    case "/view_blockchain":
                        self.view_blockchain()
                    case "/view_participant":
                        self.view_participant(args[1])
                    case "/list_all_participants":
                        self.list_all_participants()
                    case "/exit":
                        break
                    case _:
                        print("Invalid command")
            except IndexError:
                print("Invalid command arguments")
            except Exception as e:
                print(f"Error: {e}")


if __name__ == "__main__":
    app = VotingCLI()
    app.run()
