"""
RSASSA-PSS (RSA Signature Scheme with Appendix - Probabilistic Signature Scheme)

A from-scratch implementation of RSA key generation and PSS signature scheme
as defined in RFC 8017 (PKCS #1 v2.2).
"""

import hashlib
import secrets
import math


PUBLIC_EXPONENT = 65537


def _is_prime_miller_rabin(candidate, num_rounds=40):
    if candidate < 2:
        return False
    if candidate == 2 or candidate == 3:
        return True
    if candidate % 2 == 0:
        return False

    power_of_two = 0
    odd_component = candidate - 1
    while odd_component % 2 == 0:
        power_of_two += 1
        odd_component //= 2

    for _ in range(num_rounds):
        witness = secrets.randbelow(candidate - 3) + 2
        test_value = pow(witness, odd_component, candidate)

        if test_value == 1 or test_value == candidate - 1:
            continue

        for _ in range(power_of_two - 1):
            test_value = pow(test_value, 2, candidate)
            if test_value == candidate - 1:
                break
        else:
            return False

    return True


def _generate_prime(bit_length):
    while True:
        candidate = secrets.randbits(bit_length)
        candidate |= 1 << (bit_length - 1)
        candidate |= 1

        if _is_prime_miller_rabin(candidate):
            return candidate


def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1

    gcd, prev_x, prev_y = _extended_gcd(b % a, a)
    current_x = prev_y - (b // a) * prev_x
    current_y = prev_x

    return gcd, current_x, current_y


def _mod_inverse(value, modulus):
    gcd, inverse, _ = _extended_gcd(value, modulus)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return inverse % modulus


def generate_keypair(key_size=2048, voting_modulus=False, participant_modulus=False):
    prime_bit_length = key_size // 2

    prime_p = _generate_prime(prime_bit_length)
    prime_q = _generate_prime(prime_bit_length)
    while prime_p == prime_q or voting_modulus and prime_p * prime_q % 100 < 50 or participant_modulus and prime_p * prime_q % 100 > 50:
        prime_q = _generate_prime(prime_bit_length)

    modulus = prime_p * prime_q
    euler_totient = (prime_p - 1) * (prime_q - 1)
    private_exponent = _mod_inverse(PUBLIC_EXPONENT, euler_totient)

    return private_exponent, modulus


def rsa_encrypt(plaintext_int, public_exponent, modulus):
    return pow(plaintext_int, public_exponent, modulus)


def rsa_decrypt(ciphertext_int, private_exponent, modulus):
    return pow(ciphertext_int, private_exponent, modulus)


class RSASSA_PSS:
    """
    RSASSA-PSS signature scheme implementation per RFC 8017.

    PSS (Probabilistic Signature Scheme) provides a randomized signature
    that is provably secure in the random oracle model.

    The signature process:
    1. Hash the message
    2. Apply PSS encoding (adds randomness via salt)
    3. Apply RSA private key operation

    The verification process:
    1. Apply RSA public key operation
    2. Verify PSS encoding structure
    3. Compare recovered hash with message hash
    """

    def __init__(self, key, hash_function=hashlib.sha256, salt_length=32):
        self.private_exponent, self.modulus = key
        self.hash_function = hash_function
        self.hash_length = hash_function().digest_size
        self.salt_length = salt_length

        self.key_size = self.modulus.bit_length()
        self.encoded_message_bits = self.key_size - 1
        self.encoded_message_length = math.ceil(self.encoded_message_bits / 8)

    def _mask_generation_function_1(self, seed, output_length):
        """
        MGF1 - Mask Generation Function based on a hash function (RFC 8017 B.2.1).

        Generates a pseudorandom mask of arbitrary length from a seed.
        Used to mask the data block in PSS encoding.

        Args:
            seed: Seed bytes for mask generation.
            output_length: Desired length of output mask in bytes.

        Returns:
            Mask bytes of length output_length.
        """
        mask = b""
        counter = 0

        while len(mask) < output_length:
            # Concatenate seed with 4-byte big-endian counter
            counter_bytes = counter.to_bytes(4, "big")
            mask += self.hash_function(seed + counter_bytes).digest()
            counter += 1

        return mask[:output_length]

    def _integer_to_bytes(self, integer_value, byte_length):
        """
        I2OSP - Integer to Octet String Primitive (RFC 8017 Section 4.1).

        Converts a non-negative integer to a byte string of specified length.

        Args:
            integer_value: Non-negative integer to convert.
            byte_length: Desired length of output byte string.

        Returns:
            Byte string of length byte_length representing the integer.
        """
        return integer_value.to_bytes(byte_length, "big")

    def _bytes_to_integer(self, byte_string):
        """
        OS2IP - Octet String to Integer Primitive (RFC 8017 Section 4.2).

        Converts a byte string to a non-negative integer.

        Args:
            byte_string: Byte string to convert.

        Returns:
            Non-negative integer representation.
        """
        return int.from_bytes(byte_string, "big")

    def _pss_encode(self, message, encoded_bits):
        """
        EMSA-PSS-ENCODE - PSS Encoding Operation (RFC 8017 Section 9.1.1).

        Creates a randomized encoded message from the input message.

        Structure of encoded message (EM):
        +-----------+---+------+--------+------+----+
        | zero pad  |0x01| salt | masked | hash |0xBC|
        +-----------+---+------+--------+------+----+
        |<---- masked data block ----->|

        Args:
            message: Message bytes to encode.
            encoded_bits: Desired bit length of encoded message.

        Returns:
            Encoded message bytes.

        Raises:
            ValueError: If encoded message length is too short.
        """
        # Step 1: Hash the message
        message_hash = self.hash_function(message).digest()

        encoded_length = math.ceil(encoded_bits / 8)

        # Step 2: Check length constraint
        min_length = self.hash_length + self.salt_length + 2
        if encoded_length < min_length:
            raise ValueError(
                f"Encoding error: encoded message length ({encoded_length}) "
                f"too short, minimum required is {min_length}"
            )

        # Step 3: Generate random salt
        salt = secrets.token_bytes(self.salt_length)

        # Step 4: Construct M' = (8 zero bytes) || message_hash || salt
        padded_message = b"\x00" * 8 + message_hash + salt

        # Step 5: Hash M' to get H
        hash_of_padded = self.hash_function(padded_message).digest()

        # Step 6: Construct data block: DB = PS || 0x01 || salt
        # PS is padding zeros to fill remaining space
        padding_zeros_length = encoded_length - self.salt_length - self.hash_length - 2
        data_block = b"\x00" * padding_zeros_length + b"\x01" + salt

        # Step 7: Generate mask and apply XOR
        data_block_mask = self._mask_generation_function_1(
            hash_of_padded, encoded_length - self.hash_length - 1
        )
        masked_data_block = bytes(
            data_byte ^ mask_byte
            for data_byte, mask_byte in zip(data_block, data_block_mask)
        )

        # Step 8: Clear leftmost bits to ensure EM < 2^(emBits)
        leftmost_zero_bits = 8 * encoded_length - encoded_bits
        if leftmost_zero_bits > 0:
            clear_mask = 0xFF >> leftmost_zero_bits
            masked_data_block = (
                bytes([masked_data_block[0] & clear_mask]) + masked_data_block[1:]
            )

        # Step 9: Construct encoded message: EM = maskedDB || H || 0xBC
        encoded_message = masked_data_block + hash_of_padded + b"\xbc"

        return encoded_message

    def _pss_verify(self, message, encoded_message, encoded_bits):
        """
        EMSA-PSS-VERIFY - PSS Verification Operation (RFC 8017 Section 9.1.2).

        Verifies that an encoded message is a valid PSS encoding of a message.

        Args:
            message: Original message bytes.
            encoded_message: Encoded message bytes to verify.
            encoded_bits: Bit length of encoded message.

        Returns:
            True if valid encoding, False otherwise.
        """
        message_hash = self.hash_function(message).digest()
        encoded_length = math.ceil(encoded_bits / 8)

        # Step 1: Check minimum length
        min_length = self.hash_length + self.salt_length + 2
        if encoded_length < min_length:
            return False

        # Step 2: Check encoded message length
        if len(encoded_message) != encoded_length:
            return False

        # Step 3: Check trailer byte is 0xBC
        trailer_byte = encoded_message[-1]
        if trailer_byte != 0xBC:
            return False

        # Step 4: Extract masked data block and hash
        masked_data_block = encoded_message[: encoded_length - self.hash_length - 1]
        extracted_hash = encoded_message[
            encoded_length - self.hash_length - 1 : encoded_length - 1
        ]

        # Step 5: Check that leftmost bits are zero
        leftmost_zero_bits = 8 * encoded_length - encoded_bits
        if leftmost_zero_bits > 0:
            top_bits_mask = 0xFF >> leftmost_zero_bits
            if masked_data_block[0] & ~top_bits_mask:
                return False

        # Step 6: Unmask the data block
        data_block_mask = self._mask_generation_function_1(
            extracted_hash, encoded_length - self.hash_length - 1
        )
        data_block = bytes(
            masked_byte ^ mask_byte
            for masked_byte, mask_byte in zip(masked_data_block, data_block_mask)
        )

        # Clear the leftmost bits that were zeroed during encoding
        if leftmost_zero_bits > 0:
            data_block = bytes([data_block[0] & top_bits_mask]) + data_block[1:]

        # Step 7: Check padding structure: should be zeros followed by 0x01
        padding_zeros_length = encoded_length - self.hash_length - self.salt_length - 2
        for i in range(padding_zeros_length):
            if data_block[i] != 0:
                return False

        separator_byte = data_block[padding_zeros_length]
        if separator_byte != 0x01:
            return False

        # Step 8: Extract salt and reconstruct M'
        recovered_salt = data_block[padding_zeros_length + 1 :]
        reconstructed_padded_message = b"\x00" * 8 + message_hash + recovered_salt

        # Step 9: Verify hash matches
        recomputed_hash = self.hash_function(reconstructed_padded_message).digest()

        return extracted_hash == recomputed_hash

    def sign(self, message):
        """
        Create RSASSA-PSS signature for a message.

        Args:
            message: Message to sign (string or bytes).

        Returns:
            Signature as bytes (length = key_size / 8).
        """

        if isinstance(message, str):
            message = message.encode("utf-8")

        # Step 1: Apply PSS encoding
        encoded_message = self._pss_encode(message, self.encoded_message_bits)

        # Step 2: Convert to integer
        message_representative = self._bytes_to_integer(encoded_message)

        signature_representative = rsa_decrypt(
            message_representative, self.private_exponent, self.modulus
        )

        signature_length = (self.key_size + 7) // 8
        signature = self._integer_to_bytes(signature_representative, signature_length)

        return signature

    def verify(self, message, signature):
        """
        Verify RSASSA-PSS signature for a message.

        Args:
            message: Original message (string or bytes).
            signature: Signature bytes to verify.

        Returns:
            True if signature is valid, False otherwise.
        """
        if isinstance(message, str):
            message = message.encode("utf-8")

        expected_signature_length = (self.key_size + 7) // 8
        if len(signature) != expected_signature_length:
            return False

        # Step 2: Convert signature to integer
        signature_representative = self._bytes_to_integer(signature)

        if signature_representative >= self.modulus:
            return False

        message_representative = rsa_encrypt(
            signature_representative, PUBLIC_EXPONENT, self.modulus
        )

        # Step 5: Convert to encoded message bytes
        try:
            encoded_message = self._integer_to_bytes(
                message_representative, self.encoded_message_length
            )
        except OverflowError:
            return False

        # Step 6: Verify PSS encoding
        return self._pss_verify(message, encoded_message, self.encoded_message_bits)
