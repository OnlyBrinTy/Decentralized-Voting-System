from rsassa_pss import RSASSA_PSS
from blockchain import Block, Blockchain
from blockchain import verify_chain
from authority import Authority
from time import sleep

HELP_MESSAGE = """
Commands:
/add_participant <nickname> <name>
/vote <participant_nickname> <private_key>
/view_blockchain
/check_signature <public_key> <signature>
/view_participant <nickname>
/list_all_participants
/exit
"""


class VotingCLI:
    def __init__(self):
        difficulty = int(input("Set blockchain compute complexity from 0 to 30:"))
        self.target = 2 ** (256 - difficulty)
        self.authority = Authority()
        self.blockchain = Blockchain(difficulty)

    def add_participant(self, nickname, name):
        print("An authority has issued a private key for you. Please keep it secret. You can check the validity of the key by running /check_signature <public_key> <signature>. ")
        key, signature = self.authority.issue_key()
        print(f"\nYour private key: {key[0]}")
        print(f"Your public key: {key[1]}")
        print(f"Your public key's signature: {signature.hex()}\n")

        signer = RSASSA_PSS(key)
        block = Block(f"New participant: {nickname} ({name})", signer.modulus)
        block.mine(self.target)

        self.blockchain.add(block)
        block.signature = signer.sign(block.hash())

        print(f"Participant added: {nickname} ({name})")

    def vote(self, participant_nickname, private_key):
        print(f"Voting for participant: {participant_nickname} with private key: {private_key}")

    def view_blockchain(self):
        print("Viewing blockchain...")

    def view_participant(self, nickname):
        print(f"Viewing participant: {nickname}")

    def list_all_participant(self):
        print("Listing all participants...")

    def run(self):
        print(f"\nAuthority's public key: {self.authority.public_key}.\n\nUse it to check the validity of participants' public keys. Only the authority can issue valid public keys.")
        sleep(2)

        while True:
            print(HELP_MESSAGE)
            user_input = input()
            args = user_input.split()

            try:
                match args[0]:
                    case "/add_participant":
                        self.add_participant(args[1], args[2])
                    case "/vote":
                        self.vote(args[1], args[2])
                    case "/view_blockchain":
                        self.view_blockchain()
                    case "/view_participant":
                        self.view_participant(args[1])
                    case "/list_all_participant":
                        self.list_all_participant()
                    case "/exit":
                        break
            except IndexError:
                print("Invalid command")
            except Exception as e:
                print(f"Error: {e}")


        for n in range(total):
            self.blockchain.mine(Block("Block " + str(n + 1)))

        print("\nVerifying blockchain signatures...")
        valid, message = verify_chain(self.blockchain)
        if valid:
            print(good(green(message)))
        else:
            print(bad(lightred(message)))

        print("\nFull blockchain:")
        while self.blockchain.head != None:
            print(self.blockchain.head)
            self.blockchain.head = self.blockchain.head.next


if __name__ == "__main__":
    app = VotingCLI()
    app.run()
