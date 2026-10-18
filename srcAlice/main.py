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
# Shared code (chat session, framing, messages, console) lives in
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
from errors import PeerNotAvailableError
from errors import ProtocolError
from errors import SecureChatError
from message import MessageCodec
from tcp_client import TcpClient


class MenuOption:
    """One entry of the main menu: the key to type, its label and its action."""

    def __init__(self, key, label, action):
        self.key = key
        self.label = label
        self.action = action


class AliceApplication:
    """Main menu of Alice's program."""

    def __init__(self):
        self._view = ConsoleView(config.USE_COLORS)
        self._codec = MessageCodec(shared_config.TEXT_ENCODING)
        self._running = True

        # Adding a new menu entry only requires adding one MenuOption here
        # (open for extension, closed for modification).
        self._menu_options = []
        self._menu_options.append(MenuOption("1", "Conectarse con Bob e iniciar chat", self._start_chat))
        self._menu_options.append(MenuOption("2", "Ver configuracion actual", self._show_configuration))
        self._menu_options.append(MenuOption("3", "Salir", self._exit_application))

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
            self._view.show_warning("Opcion no valida: '" + typed_option + "'. Use 1, 2 o 3.")
            return

        selected_option.action()

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
    # Option 2: show configuration
    # -------------------------------------------------------------------------
    def _show_configuration(self):
        self._view.show_blank_line()
        self._view.show_info("Configuracion actual (srcAlice/config.py):")
        self._view.show_key_value("Nombre local", config.LOCAL_NAME)
        self._view.show_key_value("Par esperado", config.EXPECTED_PEER_NAME)
        self._view.show_key_value("Host de Bob", config.HOST)
        self._view.show_key_value("Puerto", config.PORT)
        self._view.show_key_value("Timeout de conexion", str(config.CONNECT_TIMEOUT) + " s")
        self._view.show_key_value("Tamano maximo de trama", str(shared_config.MAX_FRAME_SIZE) + " bytes")
        self._view.show_key_value("Prefijo de longitud", str(shared_config.LENGTH_PREFIX_SIZE) + " bytes (" + shared_config.LENGTH_PREFIX_FORMAT + ")")
        self._view.show_key_value("Comando de salida", config.EXIT_COMMAND)

    # -------------------------------------------------------------------------
    # Option 3: exit
    # -------------------------------------------------------------------------
    def _exit_application(self):
        self._running = False


def main():
    application = AliceApplication()
    application.run()


if __name__ == "__main__":
    main()