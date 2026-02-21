from rsassa_pss import generate_keypair, RSASSA_PSS


class Authority:
    """
    Authority is the only entity that can issue keys to people;
    it binds one identity to a set of keys. Only the keys signed by
    the authorities' public keyare ligitimate for consensus

    In order to ensure anonymity, the authority issues two different
    keys: one is for voting, the other is for registring a candidate.
    Keys cannot be used to vote twice or register two candidates,
    as the voting key's last two digits are less than 50, and the participant
    key's last two digits are always greater than 50. Anyone can verify
    if a key is for voting or registering.
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
        participant_key = generate_keypair(participant_modulus=True, key_size=self.KEY_SIZE)
        participant_signature = self.rsa_pss.sign(str(participant_key[1]))
        
        return participant_key, participant_signature