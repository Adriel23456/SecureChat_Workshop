# =============================================================================
# key_management_actions.py
# -----------------------------------------------------------------------------
# The key-related menu options, shared by Alice and Bob:
#
#   - Generate my RSA key pair
#   - Show the fingerprint of my public key
#   - Register the trusted fingerprint of the peer (out-of-band)
#   - Verify that my private and public keys belong together
#   - Show the key status (used by the configuration screen)
#   - Prepare the session identity before a chat (Paso 3)
#
# This class only coordinates: it asks the user through ConsoleView and
# delegates the real work to RsaKeyGenerator, KeyStore, TrustedPeerStore,
# KeyFingerprint and KeyPairVerifier (all injected in the constructor).
#
# Security rules followed here:
#   - The private key is NEVER printed, not even partially.
#   - The passphrase is read without echo and never printed.
#   - Only the PUBLIC key fingerprint is shown.
# =============================================================================

from errors import KeyMaterialError
from key_fingerprint import KeyFingerprint
from session_identity import SessionIdentity


class KeyManagementActions:
    """Menu actions that manage the local key pair and the trusted peer fingerprint."""

    def __init__(self, view, key_store, trusted_peer_store, key_generator, key_verifier,
                 local_name, peer_name, text_encoding, min_passphrase_length,
                 fingerprint_size, fingerprint_short_size):
        # Collaborators.
        self._view = view
        self._key_store = key_store
        self._trusted_peer_store = trusted_peer_store
        self._key_generator = key_generator
        self._key_verifier = key_verifier

        # Settings.
        self._local_name = local_name
        self._peer_name = peer_name
        self._text_encoding = text_encoding
        self._min_passphrase_length = min_passphrase_length
        self._fingerprint_size = fingerprint_size
        self._fingerprint_short_size = fingerprint_short_size

    # =========================================================================
    # Option: generate my key pair
    # =========================================================================
    def generate_key_pair(self):
        self._view.show_section_title("Generar par de llaves RSA de " + self._local_name)

        # ---- Protect an existing pair from being overwritten by accident -------
        if self._key_store.key_pair_exists():
            self._view.show_warning("Ya existe un par de llaves en " + self._key_store.get_keys_folder())
            self._view.show_warning(
                "Si lo reemplaza, " + self._peer_name + " debera registrar de nuevo su huella."
            )
            replace_confirmed = self._view.read_yes_no("Desea reemplazarlo?")
            if not replace_confirmed:
                self._view.show_info("Operacion cancelada. Se conservan las llaves actuales.")
                return

        # ---- Passphrase that will encrypt the private key on disk --------------
        passphrase_bytes = self._ask_new_passphrase()
        if passphrase_bytes is None:
            return

        # ---- Generate and save -------------------------------------------------
        self._view.show_info(
            "Generando RSA-" + str(self._key_generator.get_key_size())
            + " (e = " + str(self._key_generator.get_public_exponent()) + "). Puede tardar unos segundos..."
        )
        private_key = self._key_generator.generate_private_key()
        self._key_store.save_key_pair(private_key, passphrase_bytes)

        # ---- Report (only public information) ----------------------------------
        public_key = private_key.public_key()
        fingerprint = KeyFingerprint.from_public_key(public_key, self._fingerprint_size)

        self._view.show_success("Par de llaves generado y guardado.")
        self._view.show_key_value("Llave privada (cifrada)", self._key_store.get_private_key_path())
        self._view.show_key_value("Llave publica", self._key_store.get_public_key_path())
        self._view.show_key_value("Tamano", str(public_key.key_size) + " bits")
        self._view.show_key_value("Huella SHA-256", fingerprint.to_display_text())
        self._view.show_info(
            "Comparta esta huella con " + self._peer_name
            + " por un canal independiente (en la otra terminal, en voz alta...)."
        )
        self._view.show_warning("La llave privada y la frase de paso NUNCA se comparten.")

    def _ask_new_passphrase(self):
        """
        Ask for a new passphrase twice. Returns the passphrase as bytes, or
        None if the two entries differ or it is too short.
        """
        self._view.show_info(
            "La llave privada se guardara cifrada con una frase de paso (minimo "
            + str(self._min_passphrase_length) + " caracteres). No se mostrara al escribirla."
        )

        first_entry = self._view.read_secret("Nueva frase de paso: ")
        if len(first_entry) < self._min_passphrase_length:
            self._view.show_error(
                "La frase de paso debe tener al menos " + str(self._min_passphrase_length) + " caracteres."
            )
            return None

        second_entry = self._view.read_secret("Repita la frase de paso: ")
        if first_entry != second_entry:
            self._view.show_error("Las frases de paso no coinciden. No se genero nada.")
            return None

        return first_entry.encode(self._text_encoding)

    # =========================================================================
    # Option: show my fingerprint
    # =========================================================================
    def show_own_fingerprint(self):
        self._view.show_section_title("Huella de la llave publica de " + self._local_name)

        if not self._key_store.public_key_exists():
            self._view.show_warning("Todavia no hay llave publica. Genere primero su par de llaves.")
            return

        # Showing the fingerprint only needs the PUBLIC key; no passphrase.
        public_key = self._key_store.load_public_key()
        fingerprint = KeyFingerprint.from_public_key(public_key, self._fingerprint_size)
        public_numbers = public_key.public_numbers()

        self._view.show_key_value("Archivo", self._key_store.get_public_key_path())
        self._view.show_key_value("Algoritmo", "RSA")
        self._view.show_key_value("Tamano del modulo n", str(public_key.key_size) + " bits")
        self._view.show_key_value("Exponente publico e", str(public_numbers.e))
        self._view.show_key_value("Huella SHA-256", fingerprint.to_display_text())
        self._view.show_key_value("Huella corta", fingerprint.to_short_text(self._fingerprint_short_size))
        self._view.show_info("La huella es publica: mostrarla no revela ningun secreto.")

    # =========================================================================
    # Option: register the peer's trusted fingerprint
    # =========================================================================
    def register_peer_fingerprint(self):
        self._view.show_section_title("Registrar huella de confianza de " + self._peer_name)

        # ---- Show the current one, if any --------------------------------------
        if self._trusted_peer_store.has_trusted_fingerprint():
            current_fingerprint = self._trusted_peer_store.load_trusted_fingerprint()
            self._view.show_key_value("Huella registrada", current_fingerprint.to_display_text())
            replace_confirmed = self._view.read_yes_no("Desea reemplazarla?")
            if not replace_confirmed:
                self._view.show_info("Se conserva la huella registrada.")
                return

        # ---- Ask for the new one -----------------------------------------------
        self._view.show_info(
            "En la terminal de " + self._peer_name + " elija 'Ver huella de mi llave publica'"
            + " y copie aqui la huella completa."
        )
        self._view.show_info("Se acepta con o sin ':' y con o sin el prefijo 'SHA256:'.")
        typed_text = self._view.read_line("Huella de " + self._peer_name + ": ")

        try:
            new_fingerprint = KeyFingerprint.from_text(typed_text, self._fingerprint_size)
        except KeyMaterialError as error:
            self._view.show_error(str(error))
            return

        # ---- Confirm and save --------------------------------------------------
        self._view.show_key_value("Huella leida", new_fingerprint.to_display_text())
        save_confirmed = self._view.read_yes_no(
            "Confirma que coincide EXACTAMENTE con la que muestra " + self._peer_name + "?"
        )
        if not save_confirmed:
            self._view.show_info("No se guardo la huella.")
            return

        self._trusted_peer_store.save_trusted_fingerprint(new_fingerprint)
        self._view.show_success("Huella de " + self._peer_name + " registrada en " + self._trusted_peer_store.get_file_path())

    # =========================================================================
    # Option: verify my keys
    # =========================================================================
    def verify_own_keys(self):
        self._view.show_section_title("Verificar el par de llaves de " + self._local_name)

        if not self._key_store.key_pair_exists():
            self._view.show_warning("Falta la llave privada o la publica. Genere primero su par de llaves.")
            return

        # ---- Load both keys from disk ------------------------------------------
        public_key = self._key_store.load_public_key()
        self._view.show_success("Llave publica cargada (" + str(public_key.key_size) + " bits).")

        passphrase_text = self._view.read_secret("Frase de paso de la llave privada: ")
        passphrase_bytes = passphrase_text.encode(self._text_encoding)

        try:
            private_key = self._key_store.load_private_key(passphrase_bytes)
        except KeyMaterialError as error:
            self._view.show_error(str(error))
            return

        self._view.show_success("Llave privada descifrada y cargada en memoria (no se muestra).")

        # ---- Run the three checks ----------------------------------------------
        verification_result = self._key_verifier.verify(private_key, public_key)

        for check in verification_result.checks:
            if check.passed:
                self._view.show_success(check.name)
            else:
                self._view.show_error(check.name + " -> " + check.detail)

        if verification_result.all_passed():
            self._view.show_success("La llave publica corresponde a la llave privada.")
        else:
            self._view.show_error("Las llaves NO corresponden. Genere un par nuevo.")

    # =========================================================================
    # Before a chat: load everything the handshake needs (Paso 3)
    # =========================================================================
    def prepare_session_identity(self):
        """
        Check the prerequisites and unlock the private key.

        Returns a SessionIdentity, or None (after explaining why) if the chat
        cannot start yet. Called BEFORE connecting, so the handshake never
        has to wait for the user to type.
        """
        self._view.show_section_title("Preparando la identidad de " + self._local_name)

        if not self._key_store.key_pair_exists():
            self._view.show_error("No hay par de llaves. Use primero la opcion 'Generar mi par de llaves RSA'.")
            return None

        if not self._trusted_peer_store.has_trusted_fingerprint():
            self._view.show_error(
                "No hay huella de confianza de " + self._peer_name
                + ". Use primero la opcion 'Registrar huella de confianza de " + self._peer_name + "'."
            )
            return None

        trusted_fingerprint = self._trusted_peer_store.load_trusted_fingerprint()

        passphrase_text = self._view.read_secret("Frase de paso de la llave privada: ")
        passphrase_bytes = passphrase_text.encode(self._text_encoding)

        try:
            private_key = self._key_store.load_private_key(passphrase_bytes)
        except KeyMaterialError as error:
            self._view.show_error(str(error))
            return None

        identity = SessionIdentity(self._local_name, private_key, trusted_fingerprint)
        own_fingerprint = KeyFingerprint.from_public_key(identity.public_key, self._fingerprint_size)

        self._view.show_success("Llave privada desbloqueada (permanece solo en memoria).")
        self._view.show_key_value("Huella propia", own_fingerprint.to_short_text(self._fingerprint_short_size))
        self._view.show_key_value(
            "Huella esperada de " + self._peer_name,
            trusted_fingerprint.to_short_text(self._fingerprint_short_size),
        )
        return identity

    # =========================================================================
    # Status (used by the configuration screen)
    # =========================================================================
    def show_key_status(self):
        self._view.show_key_value("Carpeta de llaves", self._key_store.get_keys_folder())

        if self._key_store.private_key_exists():
            self._view.show_key_value("Llave privada", "presente (cifrada)")
        else:
            self._view.show_key_value("Llave privada", "NO generada")

        if self._key_store.public_key_exists():
            try:
                public_key = self._key_store.load_public_key()
                fingerprint = KeyFingerprint.from_public_key(public_key, self._fingerprint_size)
                self._view.show_key_value("Huella propia", fingerprint.to_short_text(self._fingerprint_short_size))
            except KeyMaterialError as error:
                self._view.show_key_value("Llave publica", "ERROR: " + str(error))
        else:
            self._view.show_key_value("Llave publica", "NO generada")

        if self._trusted_peer_store.has_trusted_fingerprint():
            try:
                trusted_fingerprint = self._trusted_peer_store.load_trusted_fingerprint()
                self._view.show_key_value(
                    "Huella de " + self._peer_name,
                    trusted_fingerprint.to_short_text(self._fingerprint_short_size),
                )
            except KeyMaterialError as error:
                self._view.show_key_value("Huella de " + self._peer_name, "ERROR: " + str(error))
        else:
            self._view.show_key_value("Huella de " + self._peer_name, "NO registrada")