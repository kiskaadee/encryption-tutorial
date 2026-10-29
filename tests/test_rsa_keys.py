# The Cryptographic Concepts to Implement:
# RSA Key Generations
#   - Standard public exponent: e = 65537
#       0x10001, prime with Fermat property for efficient verification.
#   - Key Size: 2048-bit minimum (or 4096-bit)
# PEM Serialization
#   - Private Key:
#       Stored as PKCS#8 format
#       Permissions: 0o600 (rw-------); read/write only by owner
#   - Public Key:
#       Stored as SubjectPublicKeyInfo (SPKI) format with .pub suffix
#       Permissions: 0o664 (rw-r--r--); owner can read/write, others read-only)


import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from myencrypter.algorithms.rsa import (
    RSAKeyPair,
    generate_rsa_keypair,
    load_rsa_private_key_pem,
    load_rsa_public_key_pem,
    save_keypair_to_disk,
)

"""RSA key generation, serialization, and disk persistence tests."""


def test_generate_rsa_keypair_structure() -> None:
    """Key generation produces valid PEM-encoded PKCS#8 and SPKI key material."""
    keypair: RSAKeyPair = generate_rsa_keypair(key_size=2048)

    assert isinstance(keypair, RSAKeyPair)
    assert keypair.key_size_bits == 2048
    assert keypair.private_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert keypair.private_bytes.strip().endswith(b"-----END PRIVATE KEY-----")
    assert keypair.public_bytes.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert keypair.public_bytes.strip().endswith(b"-----END PUBLIC KEY-----")


def test_generate_rsa_keypair_rejects_insecure_size() -> None:
    """Key sizes below 2048 bits should be rejected for safety."""

    # not really sure how to continue
    with pytest.raises(ValueError, match="Key size must be at least 2048 bits"):
        generate_rsa_keypair(key_size=1024)


def test_save_and_load_keypair_roundtrip(tmp_path: Path) -> None:
    """Keys saved to disk must preserve correct file permissions and parse back.
    Assertions:
        - keys can be written to disk (<name> and <name>.pub)
        - The private key has strict permissions (0o600)
        - The public key has standard permissions (0o644)
        - Loading the PEM files back into typed key objects (load_rsa_private_key_pem,
        load_rsa_public_key_pem) successfully recreates valid RSA keys.
    """
    # 1 - instantiate temp path pytest fixture
    key_dest = tmp_path / "id_rsa"

    # 2 - call the function to be tested
    keypair = generate_rsa_keypair(key_size=2048)
    priv_path, pub_path = save_keypair_to_disk(keypair, key_dest)

    assert priv_path == key_dest
    assert pub_path == tmp_path / "id_rsa.pub"
    assert priv_path.exists()
    assert pub_path.exists()

    assert stat.S_IMODE(priv_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(pub_path.stat().st_mode) == 0o644

    loaded_priv = load_rsa_private_key_pem(priv_path)
    loaded_pub = load_rsa_public_key_pem(pub_path)

    assert isinstance(loaded_priv, rsa.RSAPrivateKey)
    assert isinstance(loaded_pub, rsa.RSAPublicKey)
    assert loaded_priv.key_size == 2048
    assert loaded_pub.key_size == 2048
