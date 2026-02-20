from rsassa_pss import generate_keypair, RSASSA_PSS


class Authority:
    def __init__(self):
        self._private_exponent, self.modulus = generate_keypair()
        self.rsa_pss = RSASSA_PSS((self._private_exponent, self.modulus))


    def issue_key(self):
        key = generate_keypair()

        signature = self.rsa_pss.sign(key)

        return key, signature