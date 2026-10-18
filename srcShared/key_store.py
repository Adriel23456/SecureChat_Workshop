# =============================================================================
# key_store.py
# -----------------------------------------------------------------------------
# Saves and loads ONE participant's RSA key pair on disk:
#
#     srcXxx/keys/private_key.pem   -> PEM, PKCS#8, ENCRYPTED with a passphrase
#     srcXxx/keys/public_key.pem    -> PEM, SubjectPublicKeyInfo (not secret)
#
# Rules this class enforces:
#   - The private key is never written unencrypted.
#   - Loaded keys must be RSA and at least RSA_MINIMUM_KEY_SIZE bits.
#   - No method returns or prints the private key bytes; callers only get the
#     key OBJECT, which never leaves the process (and never the socket).
# =============================================================================

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from errors import KeyMaterialError


class KeyStore:
    """File storage for the local participant's RSA key pair."""

    def __init__(self, keys_folder, private_key_file_name, public_key_file_name, minimum_key_size):
        self._keys_folder = keys_folder
        self._private_key_path = os.path.join(keys_folder, private_key_file_name)
        self._public_key_path = os.path.join(keys_folder, public_key_file_name)
        self._minimum_key_size = minimum_key_size

    # -------------------------------------------------------------------------
    # Paths and existence
    # -------------------------------------------------------------------------
    def get_keys_folder(self):
        return self._keys_folder

    def get_private_key_path(self):
        return self._private_key_path

    def get_public_key_path(self):
        return self._public_key_path

    def private_key_exists(self):
        return os.path.isfile(self._private_key_path)

    def public_key_exists(self):
        return os.path.isfile(self._public_key_path)

    def key_pair_exists(self):
        """True only when BOTH files are present."""
        if not self.private_key_exists():
            return False
        if not self.public_key_exists():
            return False
        return True

    # -------------------------------------------------------------------------
    # Saving
    # -------------------------------------------------------------------------
    def save_key_pair(self, private_key, passphrase_bytes):
        """Write the private key (encrypted) and its public key to disk."""
        if len(passphrase_bytes) == 0:
            raise KeyMaterialError("La llave privada no se guarda sin frase de paso.")

        # Create srcXxx/keys/ if it does not exist yet.
        os.makedirs(self._keys_folder, exist_ok=True)

        # PKCS#8 is the standard container for private keys.
        # BestAvailableEncryption lets the library choose the strongest
        # password-based encryption it supports for that container.
        private_pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase_bytes),
        )

        # SubjectPublicKeyInfo is the standard container for public keys.
        public_key = private_key.public_key()
        public_pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self._write_bytes(self._private_key_path, private_pem_bytes)
        self._write_bytes(self._public_key_path, public_pem_bytes)

    def _write_bytes(self, file_path, data_bytes):
        file_handle = open(file_path, "wb")
        try:
            file_handle.write(data_bytes)
        finally:
            file_handle.close()

    # -------------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------------
    def load_public_key(self):
        """Read public_key.pem and return the public key object."""
        if not self.public_key_exists():
            raise KeyMaterialError("No existe la llave publica: " + self._public_key_path)

        pem_bytes = self._read_bytes(self._public_key_path)

        try:
            public_key = serialization.load_pem_public_key(pem_bytes)
        except ValueError:
            raise KeyMaterialError("El archivo de llave publica esta danado: " + self._public_key_path)

        self._check_public_key_strength(public_key)
        return public_key

    def load_private_key(self, passphrase_bytes):
        """Read private_key.pem, decrypt it with the passphrase and return the key object."""
        if not self.private_key_exists():
            raise KeyMaterialError("No existe la llave privada: " + self._private_key_path)

        pem_bytes = self._read_bytes(self._private_key_path)

        try:
            private_key = serialization.load_pem_private_key(pem_bytes, password=passphrase_bytes)
        except ValueError:
            # Raised when the passphrase is wrong or the file is corrupted.
            raise KeyMaterialError("Frase de paso incorrecta o archivo de llave privada danado.")
        except TypeError:
            # Raised when the file is encrypted but no passphrase was given
            # (or the other way around).
            raise KeyMaterialError("La llave privada requiere una frase de paso valida.")

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise KeyMaterialError("La llave privada no es RSA.")

        self._check_public_key_strength(private_key.public_key())
        return private_key

    def _read_bytes(self, file_path):
        file_handle = open(file_path, "rb")
        try:
            data_bytes = file_handle.read()
        finally:
            file_handle.close()
        return data_bytes

    def _check_public_key_strength(self, public_key):
        """Reject non-RSA keys and RSA keys smaller than the minimum size."""
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise KeyMaterialError("La llave publica no es RSA.")

        if public_key.key_size < self._minimum_key_size:
            raise KeyMaterialError(
                "La llave mide " + str(public_key.key_size) + " bits; el minimo es "
                + str(self._minimum_key_size) + " bits."
            )