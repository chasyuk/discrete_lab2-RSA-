import hashlib


def euclidean_algorithm(numerator, denominator):
    list_b = []
    remainder = numerator % denominator

    while remainder != 1:
        list_b.append(numerator // denominator)
        numerator = denominator
        denominator = remainder
        remainder = numerator % denominator

    list_b.append(numerator // denominator)

    return list_b


def reverse_euclidean_algorithm(numerator, denominator):
    list_b = euclidean_algorithm(numerator, denominator)

    a = 1
    b = -list_b.pop()
    while list_b:
        new_b = list_b.pop()
        temp = b
        b = a - b * new_b
        a = temp

    return b % numerator


def generate_keys():
    """Generate an RSA key pair (e, d, n)."""
    # Exponents 25 generate primes large enough (n ~ 10^50) so they can still safely encrypt
    # messages of length up to ~20 bytes without wrapping around modulo n.
    num_1 = 10**25 + 13
    num_2 = 10**25 + 223
    n = num_1 * num_2
    fi = (num_1 - 1) * (num_2 - 1)
    e = 2 ** 16 + 1
    d = reverse_euclidean_algorithm(fi, e)
    return e, d, n


def encode_message(message, e, n):
    """Encrypt a string message with RSA public key (e, n).
    Returns (sha256_hash, ciphertext_int).
    """
    message_bytes = message.encode('utf-8')
    message_int = int.from_bytes(message_bytes, byteorder='big')

    message_hash = hashlib.sha256(message_bytes).hexdigest()

    encoded_message = pow(message_int, e, n)

    return message_hash, encoded_message


def decode_message(encoded_message, d, n):
    """Decrypt an RSA-encrypted message.
    encoded_message is (sha256_hash, ciphertext_int).
    Returns the decrypted string.
    """
    message_hash, message = encoded_message
    decoded_message = pow(message, d, n)
    byte_length = (decoded_message.bit_length() + 7) // 8

    recovered_bytes = decoded_message.to_bytes(byte_length, byteorder='big')

    decoded_message_bytes = hashlib.sha256(recovered_bytes).hexdigest()

    if message_hash != decoded_message_bytes:
        print("Message was altered!")

    return recovered_bytes.decode('utf-8')


def symmetric_encrypt(plaintext, key):
    """XOR-encrypt plaintext using key (repeating key as needed).
    Returns a hex string.
    """
    key_bytes = key.encode('utf-8')
    plain_bytes = plaintext.encode('utf-8')
    encrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(plain_bytes)])
    return encrypted.hex()


def symmetric_decrypt(hex_cipher, key):
    """XOR-decrypt a hex string using key.
    Returns the plaintext string.
    """
    key_bytes = key.encode('utf-8')
    cipher_bytes = bytes.fromhex(hex_cipher)
    decrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(cipher_bytes)])
    return decrypted.decode('utf-8')
