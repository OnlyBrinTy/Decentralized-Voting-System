from rsassa_pss import generate_keypair, RSASSA_PSS


class Authority:
    """
    Issues and certifies public keys used on the blockchain.

    Only public keys signed by the Authority are accepted by the chain validator.
    This prevents arbitrary users from introducing untrusted keys.

    This demo encodes key “type” in the modulus:
    - voter keys have modulus % 100 > 50
    - participant-registration keys have modulus % 100 < 50

    The blockchain validator enforces that voting blocks use voter keys and
    participant blocks use participant-registration keys. Combined with the
    “one key can appear only once in the chain” rule, this makes it impossible
    to vote twice or register twice with the same key.
    """

    KEY_SIZE = 1024

    def __init__(self):
        self._private_exponent, self.modulus = generate_keypair(key_size=self.KEY_SIZE)
        self.rsa_pss = RSASSA_PSS((self._private_exponent, self.modulus))

    def issue_voter_key(self):
        voter_key = generate_keypair(voting_modulus=True, key_size=self.KEY_SIZE)
        voting_signature = self.rsa_pss.sign(str(voter_key[1]))

        return voter_key, voting_signature

    def issue_participant_key(self):
        participant_key = generate_keypair(
            participant_modulus=True, key_size=self.KEY_SIZE
        )
        participant_signature = self.rsa_pss.sign(str(participant_key[1]))

        return participant_key, participant_signature
