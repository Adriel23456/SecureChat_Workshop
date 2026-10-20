# =============================================================================
# main.py (Bob)
# -----------------------------------------------------------------------------
# Entry point of Bob's program. Run it from inside srcBob:
#
#     python main.py
#
# Bob is the participant that WAITS for the connection, so he must be started
# before Alice chooses "Conectarse".
#
# Shared code (chat session, framing, messages, console, keys) lives in
# ../srcShared; the block below makes it importable without __init__.py.
#
# This file only builds the objects and runs the menu. All the real work is
# done by the classes in the other files (composition root).
# =============================================================================

# -----------------------------------------------------------------------------
# Make srcShared importable
# -----------------------------------------------------------------------------
# Python only looks for modules in the folder of the script being run (this
# srcXxx folder) and in the installed packages. srcShared is a sibling folder,
# so its absolute path is added to sys.path BEFORE importing anything from it.
# This must stay above every import that comes from srcShared.
import os
import sys

SHARED_FOLDER_NAME = "srcShared"

THIS_FOLDER = os.path.dirname(os.path.abspath(__file__))
REPOSITORY_ROOT = os.path.dirname(THIS_FOLDER)
SHARED_FOLDER = os.path.join(REPOSITORY_ROOT, SHARED_FOLDER_NAME)

if not os.path.isdir(SHARED_FOLDER):
    print("[ERROR] No se encontro la carpeta compartida: " + SHARED_FOLDER)
    sys.exit(1)

if SHARED_FOLDER not in sys.path:
    sys.path.append(SHARED_FOLDER)

# -----------------------------------------------------------------------------
# Imports (local folder first, then srcShared)
# -----------------------------------------------------------------------------
import config
import shared_config
from bob_handshake import BobHandshake
from binary_fields import BinaryFields
from chat_session import ChatSession
from chat_session import ChatSettings
from console_view import ConsoleView
from errors import HandshakeError
from errors import KeyMaterialError
from errors import ProtocolError
from errors import SecureChatError
from handshake_base import HandshakeSettings
from key_management_actions import KeyManagementActions
from keyboard_input import create_key_source
from key_pair_verifier import KeyPairVerifier
from key_store import KeyStore
from menu_option import MenuOption
from message import MessageCodec
from nonce_sequence import NonceLayout
from rsa_key_generator import RsaKeyGenerator
from rsa_operations import RsaOperations
from secure_channel import SecureChannelSettings
from tcp_server import TcpServer
from trusted_peer_store import TrustedPeerStore

# Bob's keys live inside his own folder: srcBob/keys/ (ignored by git).
KEYS_FOLDER = os.path.join(THIS_FOLDER, shared_config.KEYS_FOLDER_NAME)


class BobApplication:
    """Main menu of Bob's program."""

    def __init__(self):
        # On a Windows console the chat prompt reads key by key (Paso 5), so
        # incoming messages never erase what the user is typing.
        self._view = ConsoleView(config.USE_COLORS, create_key_source(), config.KEYBOARD_POLL_INTERVAL)
        self._codec = MessageCodec(shared_config.TEXT_ENCODING)
        self._running = True

        # ---- Handshake helpers (Paso 3) --------------------------------------------
        self._binary_fields = BinaryFields(shared_config.FIELD_LENGTH_FORMAT)
        self._rsa_operations = RsaOperations()
        self._handshake_settings = HandshakeSettings.from_shared_config(
            shared_config,
            config.HANDSHAKE_TIMEOUT,
            config.SHOW_HANDSHAKE_DETAILS,
        )

        # ---- Message protection (Paso 4) -------------------------------------------
        nonce_layout = NonceLayout(
            shared_config.NONCE_DIRECTION_SIZE_BYTES,
            shared_config.NONCE_COUNTER_SIZE_BYTES,
        )
        self._channel_settings = SecureChannelSettings.from_shared_config(shared_config, nonce_layout)

        # ---- Chat options (Paso 5) ---------------------------------------------------
        self._chat_settings = ChatSettings(
            config.LOCAL_NAME,
            config.EXIT_COMMAND,
            config.DETAIL_COMMAND,
            config.STATUS_COMMAND,
            config.HELP_COMMAND,
            config.RECEIVER_JOIN_TIMEOUT,
            config.SHOW_MESSAGE_DETAILS,
            shared_config.MESSAGE_HEX_PREVIEW_SIZE_BYTES,
        )

        # ---- Key management (Paso 2) -------------------------------------------
        key_store = KeyStore(
            KEYS_FOLDER,
            shared_config.PRIVATE_KEY_FILE_NAME,
            shared_config.PUBLIC_KEY_FILE_NAME,
            shared_config.RSA_MINIMUM_KEY_SIZE,
        )
        trusted_peer_store = TrustedPeerStore(
            os.path.join(KEYS_FOLDER, config.TRUSTED_PEER_FINGERPRINT_FILE_NAME),
            shared_config.FINGERPRINT_SIZE_BYTES,
        )
        key_generator = RsaKeyGenerator(shared_config.RSA_KEY_SIZE, shared_config.RSA_PUBLIC_EXPONENT)
        key_verifier = KeyPairVerifier(shared_config.KEY_SELF_TEST_SIZE_BYTES)

        self._key_actions = KeyManagementActions(
            self._view,
            key_store,
            trusted_peer_store,
            key_generator,
            key_verifier,
            config.LOCAL_NAME,
            config.EXPECTED_PEER_NAME,
            shared_config.TEXT_ENCODING,
            shared_config.MIN_PASSPHRASE_LENGTH,
            shared_config.FINGERPRINT_SIZE_BYTES,
            shared_config.FINGERPRINT_SHORT_SIZE_BYTES,
        )

        # ---- Menu ----------------------------------------------------------------
        # Adding a new menu entry only requires adding one MenuOption here
        # (open for extension, closed for modification).
        self._menu_options = []
        self._menu_options.append(MenuOption("1", "Esperar conexion de Alice e iniciar chat", self._start_chat))
        self._menu_options.append(MenuOption("2", "Generar mi par de llaves RSA", self._key_actions.generate_key_pair))
        self._menu_options.append(MenuOption("3", "Ver huella de mi llave publica", self._key_actions.show_own_fingerprint))
        self._menu_options.append(MenuOption("4", "Registrar huella de confianza de Alice", self._key_actions.register_peer_fingerprint))
        self._menu_options.append(MenuOption("5", "Verificar mis llaves (prueba)", self._key_actions.verify_own_keys))
        self._menu_options.append(MenuOption("6", "Ver configuracion actual", self._show_configuration))
        self._menu_options.append(MenuOption("7", "Salir", self._exit_application))

    # -------------------------------------------------------------------------
    # Main loop
    # -------------------------------------------------------------------------
    def run(self):
        self._view.show_banner(config.APP_TITLE)

        while self._running:
            self._view.show_menu(self._menu_options)

            try:
                typed_option = self._view.read_line("Seleccione una opcion: ")
            except KeyboardInterrupt:
                self._view.show_blank_line()
                break
            except EOFError:
                break

            self._execute_option(typed_option.strip())

        self._view.show_info("Programa finalizado.")

    def _execute_option(self, typed_option):
        """Find the MenuOption whose key matches and run its action."""
        selected_option = None
        for menu_option in self._menu_options:
            if menu_option.key == typed_option:
                selected_option = menu_option
                break

        if selected_option is None:
            self._view.show_warning("Opcion no valida: '" + typed_option + "'. Use " + self._list_valid_keys() + ".")
            return

        # Safety net shared by every option: Ctrl+C cancels only the current
        # option, and a key problem is reported instead of crashing the menu.
        try:
            selected_option.action()
        except KeyboardInterrupt:
            self._view.show_blank_line()
            self._view.show_warning("Operacion cancelada por el usuario.")
        except EOFError:
            self._view.show_blank_line()
            self._view.show_warning("Entrada cerrada; operacion cancelada.")
        except KeyMaterialError as error:
            self._view.show_error(str(error))

    def _list_valid_keys(self):
        """Build the text "1, 2, 3, ..." from the menu options."""
        valid_keys = []
        for menu_option in self._menu_options:
            valid_keys.append(menu_option.key)
        return ", ".join(valid_keys)

    # -------------------------------------------------------------------------
    # Option 1: wait for Alice and chat
    # -------------------------------------------------------------------------
    def _start_chat(self):
        # ---- Unlock the private key BEFORE listening (Paso 3) -----------------------
        # The handshake must not stop halfway to wait for a passphrase.
        identity = self._key_actions.prepare_session_identity()
        if identity is None:
            self._view.show_warning("No se inicia el chat hasta completar los requisitos anteriores.")
            return

        server = TcpServer(
            config.HOST,
            config.PORT,
            config.LISTEN_BACKLOG,
            config.SOCKET_POLL_TIMEOUT,
            shared_config.MAX_FRAME_SIZE,
        )

        self._view.show_info(server.describe())
        self._view.show_info("Presione Ctrl+C para cancelar la espera.")

        # ---- Wait for the connection ----------------------------------------
        try:
            connection = server.establish()
        except KeyboardInterrupt:
            self._view.show_blank_line()
            self._view.show_warning("Espera cancelada por el usuario.")
            return
        except OSError as error:
            # Typical case on Windows: WinError 10048, the port is already in use.
            self._view.show_error("No se pudo abrir " + config.HOST + ":" + str(config.PORT) + " -> " + str(error))
            self._view.show_info("Revise que no haya otra instancia de Bob abierta o cambie PORT en config.py.")
            return

        # ---- Handshake + chat ---------------------------------------------------
        handshake = BobHandshake(
            connection,
            self._codec,
            self._view,
            self._binary_fields,
            self._rsa_operations,
            identity,
            config.EXPECTED_PEER_NAME,
            self._handshake_settings,
        )

        session = ChatSession(
            connection,
            self._codec,
            self._view,
            handshake,
            self._channel_settings,
            self._chat_settings,
        )

        try:
            session.run()
        except HandshakeError as error:
            self._view.show_error("Handshake abortado: " + str(error))
            self._view.show_error("La conexion se cerro sin intercambiar mensajes de chat.")
        except ProtocolError as error:
            self._view.show_error("Error de protocolo: " + str(error))
        except SecureChatError as error:
            self._view.show_error(str(error))
        except OSError as error:
            self._view.show_error("Error de red: " + str(error))
        except KeyboardInterrupt:
            self._view.show_blank_line()
            self._view.show_warning("Sesion interrumpida por el usuario.")
        finally:
            # ChatSession already closes it; this is a safety net.
            connection.close()

    # -------------------------------------------------------------------------
    # Option 6: show configuration
    # -------------------------------------------------------------------------
    def _show_configuration(self):
        self._view.show_section_title("Configuracion actual (srcBob/config.py + srcShared/shared_config.py)")
        self._view.show_key_value("Nombre local", config.LOCAL_NAME)
        self._view.show_key_value("Par esperado", config.EXPECTED_PEER_NAME)
        self._view.show_key_value("Host de escucha", config.HOST)
        self._view.show_key_value("Puerto", config.PORT)
        self._view.show_key_value("Tamano maximo de trama", str(shared_config.MAX_FRAME_SIZE) + " bytes")
        self._view.show_key_value("Prefijo de longitud", str(shared_config.LENGTH_PREFIX_SIZE) + " bytes (" + shared_config.LENGTH_PREFIX_FORMAT + ")")
        self._view.show_key_value(
            "Comandos del chat",
            config.HELP_COMMAND + " " + config.DETAIL_COMMAND + " " + config.STATUS_COMMAND + " " + config.EXIT_COMMAND,
        )
        if self._view.supports_interruptible_input():
            self._view.show_key_value("Entrada del chat", "interrumpible (tecla por tecla / select)")
        else:
            self._view.show_key_value("Entrada del chat", "bloqueante (entrada redirigida)")
        self._view.show_key_value("Timeout por paso del handshake", str(config.HANDSHAKE_TIMEOUT) + " s")
        self._view.show_key_value("Clave de sesion", str(shared_config.SESSION_KEY_SIZE_BITS) + " bits (AES-GCM)")
        self._view.show_key_value(
            "Nonce de mensajes",
            str(shared_config.NONCE_DIRECTION_SIZE_BYTES) + " B direccion + "
            + str(shared_config.NONCE_COUNTER_SIZE_BYTES) + " B contador",
        )
        self._view.show_key_value("RSA para llaves nuevas", str(shared_config.RSA_KEY_SIZE) + " bits, e = " + str(shared_config.RSA_PUBLIC_EXPONENT))

        self._view.show_section_title("Estado de las llaves")
        self._key_actions.show_key_status()

    # -------------------------------------------------------------------------
    # Option 7: exit
    # -------------------------------------------------------------------------
    def _exit_application(self):
        self._running = False


def main():
    application = BobApplication()
    application.run()


if __name__ == "__main__":
    main()