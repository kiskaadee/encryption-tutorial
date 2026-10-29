import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from myencrypter.algorithms.rsa import DecryptionError, decrypt_rsa, encrypt_rsa


def test_rsa_encryption_decryption() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    message: bytes = b"Hello, from kiskaadee!"
    ciphertext: bytes = encrypt_rsa(public_key, message)

    assert isinstance(ciphertext, bytes)
    decrypted_message: bytes = decrypt_rsa(private_key, ciphertext)
    assert decrypted_message == message


def test_rsa_decryption_with_wrong_key_fails() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    wrong_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    message: bytes = b"Hello, from kiskaadee!"
    ciphertext: bytes = encrypt_rsa(public_key, message)

    assert isinstance(ciphertext, bytes)
    with pytest.raises(DecryptionError):
        decrypt_rsa(wrong_private_key, ciphertext)


def test_rsa_encryption_same_message_produces_different_ciphertext() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    message: bytes = b"Hello, from kiskaadee!"
    ciphertext1: bytes = encrypt_rsa(public_key, message)
    ciphertext2: bytes = encrypt_rsa(public_key, message)

    assert isinstance(ciphertext1, bytes)
    assert isinstance(ciphertext2, bytes)
    assert ciphertext1 != ciphertext2
    assert decrypt_rsa(private_key, ciphertext1) == message
    assert decrypt_rsa(private_key, ciphertext2) == message


def test_tampered_ciphertext_raises_decryption_error() -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    message: bytes = b"Alice message is top secret!"
    ciphertext: bytes = encrypt_rsa(public_key, message)

    ciphertext_array = bytearray(ciphertext)
    ciphertext_array[0] ^= 0xFF
    corrupted_ciphertext: bytes = bytes(ciphertext_array)

    with pytest.raises(DecryptionError):
        decrypt_rsa(private_key, corrupted_ciphertext)
