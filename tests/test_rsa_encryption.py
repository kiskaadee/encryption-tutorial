import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from myencrypter.algorithms.rsa import (
    DecryptionError,
    RSAConfig,
    decrypt_rsa,
    encrypt_rsa,
)


def _generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def test_rsa_encryption_decryption() -> None:
    private_key = _generate_private_key()
    public_key = private_key.public_key()

    message: bytes = b"Hello, from kiskaadee!"
    ciphertext: bytes = encrypt_rsa(public_key, message)

    assert isinstance(ciphertext, bytes)
    decrypted_message: bytes = decrypt_rsa(private_key, ciphertext)
    assert decrypted_message == message


def test_rsa_decryption_with_wrong_key_fails() -> None:
    private_key = _generate_private_key()
    wrong_private_key = _generate_private_key()
    public_key = private_key.public_key()

    message: bytes = b"Hello, from kiskaadee!"
    ciphertext: bytes = encrypt_rsa(public_key, message)

    assert isinstance(ciphertext, bytes)
    with pytest.raises(DecryptionError):
        decrypt_rsa(wrong_private_key, ciphertext)


def test_rsa_encryption_same_message_produces_different_ciphertext() -> None:
    private_key = _generate_private_key()
    public_key = private_key.public_key()

    message: bytes = b"Hello, from kiskaadee!"
    ciphertext1: bytes = encrypt_rsa(public_key, message)
    ciphertext2: bytes = encrypt_rsa(public_key, message)

    assert isinstance(ciphertext1, bytes)
    assert isinstance(ciphertext2, bytes)
    assert ciphertext1 != ciphertext2
    assert decrypt_rsa(private_key, ciphertext1) == message
    assert decrypt_rsa(private_key, ciphertext2) == message


def test_oaep_tampered_ciphertext_raises_decryption_error() -> None:
    """Configuration implicitly falls to OAEP default"""

    private_key = _generate_private_key()
    public_key = private_key.public_key()

    message: bytes = b"Alice message is top secret!"
    ciphertext: bytes = encrypt_rsa(public_key, message)

    ciphertext_array = bytearray(ciphertext)
    ciphertext_array[-1] ^= 0xFF
    corrupted_ciphertext: bytes = bytes(ciphertext_array)

    with pytest.raises(DecryptionError):
        decrypt_rsa(private_key, corrupted_ciphertext)


def test_pkcs1_tampered_ciphertext_implicitly_reject_tampered_message() -> None:
    """PCKS implementation should not raise a Value Error
    Expected: Implicit rejection (silent synthetic return)
    """
    private_key = _generate_private_key()
    custom_config = RSAConfig(padding_scheme="pkcs1v15")
    public_key = private_key.public_key()

    message: bytes = b"Shinigami loves apples!"
    ciphertext: bytes = encrypt_rsa(public_key, message, custom_config)

    # Tamper with the least significant byte instead of the most significant one
    ciphertext_array = bytearray(ciphertext)
    ciphertext_array[-1] ^= 0xFF
    corrupted_ciphertext: bytes = bytes(ciphertext_array)

    recovered = decrypt_rsa(private_key, corrupted_ciphertext, custom_config)

    assert isinstance(recovered, bytes)
    assert recovered != message


def test_pkcs1_wrong_key_decryption_implicitly_rejected() -> None:
    """Expected: Implicit rejection (silent synthetic return)"""
    private_key = _generate_private_key()
    public_key = private_key.public_key()

    custom_config = RSAConfig(padding_scheme="pkcs1v15")
    message: bytes = b"Shinigami loves apples!"
    ciphertext: bytes = encrypt_rsa(public_key, message, custom_config)
    recovered = decrypt_rsa(private_key, ciphertext, custom_config)
    assert isinstance(recovered, bytes)
    assert recovered == message

    wrong_private_key = _generate_private_key()
    try:
        recovered_wrong = decrypt_rsa(
            wrong_private_key,
            ciphertext,
            custom_config,
        )
        assert isinstance(recovered_wrong, bytes)
        assert recovered_wrong != message

    except DecryptionError:
        pass
