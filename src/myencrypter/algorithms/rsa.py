from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass(frozen=True)
class RSAConfig:
    """Configuration for RSA encryption/decryption."""

    padding_scheme: Literal["oaep", "pkcs1v15"] = "oaep"
    hash_algorithm: Literal["sha256", "sha512"] = "sha256"
    label: bytes | None = None

    def build_padding(self) -> padding.AsymmetricPadding:
        """Translate string attributes to cryptography library padding objects."""
        if self.padding_scheme == "oaep":
            hash_map = {
                "sha256": hashes.SHA256(),
                "sha512": hashes.SHA512(),
            }
            selected_hash = hash_map[self.hash_algorithm]
            return padding.OAEP(
                mgf=padding.MGF1(algorithm=selected_hash),
                algorithm=selected_hash,
                label=self.label,
            )

        elif self.padding_scheme == "pkcs1v15":
            return padding.PKCS1v15()

        raise ValueError(f"Unsupported padding scheme: {self.padding_scheme}")


@dataclass(frozen=True)
class RSAKeyPair:
    private_bytes: bytes
    public_bytes: bytes
    key_size_bits: int


class KeySizeError(ValueError):
    pass


class DecryptionError(Exception):
    pass


def _validate_rsa_key_size(key_size: int) -> int:
    if key_size < 2048:
        raise KeySizeError(f"Key size must be at least 2048 bits, got {key_size}")
    return key_size


def generate_rsa_keypair(key_size: int = 2048) -> RSAKeyPair:
    """Generate a new RSA private/public key pair."""
    valid_key_size = _validate_rsa_key_size(key_size)

    """
    1. Generating the Private Key Object
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=valid_key_size,
    )

    """
    2. Deriving the Public Key 
    In assymetric cryptography, the public key is mathematically derived
    from the private key
    """

    public_key = private_key.public_key()

    """
    3. Serializing to PEM format
    Cryptography keys in memory are mathematical objects; to send or 
    store them, we serialize them into PEM (Base64/ASCII armor) using 
    standard formats
    """

    # Private key -> PKCS#8 format (unencrypted for our experiment)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Public key -> SubjectPublicKeyInfo (SPKI) format
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    """
    4. Return the Dataclass
    """

    # raise NotImplementedError
    return RSAKeyPair(
        private_bytes=private_bytes,
        public_bytes=public_bytes,
        key_size_bits=key_size,
    )


def save_keypair_to_disk(keypair: RSAKeyPair, key_dest: Path) -> tuple[Path, Path]:
    # raise NotImplementedError
    priv_path = key_dest
    pub_path = Path(f"{key_dest}.pub")

    # 1. Write the private key and restrict permissions to owner-only (0x600)
    priv_path.write_bytes(keypair.private_bytes)
    priv_path.chmod(0o600)

    # 2. Write the public key and set standard permissions (0o644)
    pub_path.write_bytes(keypair.public_bytes)
    pub_path.chmod(0o644)

    return priv_path, pub_path


def load_rsa_private_key_pem(priv_path: Path) -> rsa.RSAPrivateKey:
    # raise NotImplementedError
    data = priv_path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError(f"Expected RSA private key, got {type(key)}")
    return key


def load_rsa_public_key_pem(pub_path: Path) -> rsa.RSAPublicKey:
    data = pub_path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError(f"Expected RSA public key, got {type(key)}")
    return key


def encrypt_rsa(
    public_key: rsa.RSAPublicKey, plaintext: bytes, config: RSAConfig | None = None
) -> bytes:
    """Encrypt plaintext bytes using RSA-OAEP with SHA-256."""

    cfg = config if config is not None else RSAConfig()
    pad = cfg.build_padding()

    return public_key.encrypt(plaintext=plaintext, padding=pad)


def decrypt_rsa(
    private_key: rsa.RSAPrivateKey, ciphertext: bytes, config: RSAConfig | None = None
) -> bytes:
    """Decrypt ciphertext bytes using RSA-OAEP with SHA-256."""

    cfg = config if config is not None else RSAConfig()

    try:
        pad = cfg.build_padding()
        return private_key.decrypt(ciphertext=ciphertext, padding=pad)
    except ValueError as exc:
        raise DecryptionError("Failed to decrypt with RSA: invalid padding") from exc
