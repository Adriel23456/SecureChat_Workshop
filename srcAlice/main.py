# =============================================================================
# main.py (Alice)
# -----------------------------------------------------------------------------
# Entry point of Alice's program. Run it from inside srcAlice:
#
#     python main.py
#
# Alice is the participant that STARTS the connection, so Bob must already be
# waiting (Bob's menu option 1) before Alice chooses "Conectarse".
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
from chat_session import ChatSession
from console_view import ConsoleView
from errors import KeyMaterialError
from errors import PeerNotAvailableError
from errors import ProtocolError
from errors import SecureChatError
from key_management_actions import KeyManagementActions
from key_pair_verifier import KeyPairVerifier
from key_store import KeyStore
from menu_option import MenuOption
from message import MessageCodec
from rsa_key_generator import RsaKeyGenerator
from tcp_client import TcpClient
from trusted_peer_store import TrustedPeerStore

# Alice's keys live inside her own folder: srcAlice/keys/ (ignored by git).
KEYS_FOLDER = os.path.join(THIS_FOLDER, shared_config.KEYS_FOLDER_NAME)


class AliceApplication:
    """Main menu of Alice's program."""

    def __init__(self):
        self._view = ConsoleView(config.USE_COLORS)
        self._codec = MessageCodec(shared_config.TEXT_ENCODING)
        self._running = True

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
        self._menu_options.append(MenuOption("1", "Conectarse con Bob e iniciar chat", self._start_chat))
        self._menu_options.append(MenuOption("2", "Generar mi par de llaves RSA", self._key_actions.generate_key_pair))
        self._menu_options.append(MenuOption("3", "Ver huella de mi llave publica", self._key_actions.show_own_fingerprint))
        self._menu_options.append(MenuOption("4", "Registrar huella de confianza de Bob", self._key_actions.register_peer_fingerprint))
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
    # Option 1: connect to Bob and chat
    # -------------------------------------------------------------------------
    def _start_chat(self):
        client = TcpClient(
            config.HOST,
            config.PORT,
            config.CONNECT_TIMEOUT,
            config.SOCKET_POLL_TIMEOUT,
            shared_config.MAX_FRAME_SIZE,
        )

        self._view.show_info(client.describe())

        # ---- Connect ----------------------------------------------------------
        try:
            connection = client.establish()
        except PeerNotAvailableError as error:
            self._view.show_error(str(error))
            return
        except KeyboardInterrupt:
            self._view.show_blank_line()
            self._view.show_warning("Conexion cancelada por el usuario.")
            return

        # ---- Chat -------------------------------------------------------------
        session = ChatSession(
            connection,
            self._codec,
            self._view,
            config.LOCAL_NAME,
            config.EXPECTED_PEER_NAME,
            config.EXIT_COMMAND,
            config.HELLO_TIMEOUT,
            config.RECEIVER_JOIN_TIMEOUT,
        )

        try:
            session.run()
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
        self._view.show_section_title("Configuracion actual (srcAlice/config.py + srcShared/shared_config.py)")
        self._view.show_key_value("Nombre local", config.LOCAL_NAME)
        self._view.show_key_value("Par esperado", config.EXPECTED_PEER_NAME)
        self._view.show_key_value("Host de Bob", config.HOST)
        self._view.show_key_value("Puerto", config.PORT)
        self._view.show_key_value("Timeout de conexion", str(config.CONNECT_TIMEOUT) + " s")
        self._view.show_key_value("Tamano maximo de trama", str(shared_config.MAX_FRAME_SIZE) + " bytes")
        self._view.show_key_value("Prefijo de longitud", str(shared_config.LENGTH_PREFIX_SIZE) + " bytes (" + shared_config.LENGTH_PREFIX_FORMAT + ")")
        self._view.show_key_value("Comando de salida", config.EXIT_COMMAND)
        self._view.show_key_value("RSA para llaves nuevas", str(shared_config.RSA_KEY_SIZE) + " bits, e = " + str(shared_config.RSA_PUBLIC_EXPONENT))

        self._view.show_section_title("Estado de las llaves")
        self._key_actions.show_key_status()

    # -------------------------------------------------------------------------
    # Option 7: exit
    # -------------------------------------------------------------------------
    def _exit_application(self):
        self._running = False


def main():
    application = AliceApplication()
    application.run()


if __name__ == "__main__":
    main()