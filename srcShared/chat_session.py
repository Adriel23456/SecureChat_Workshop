# =============================================================================
# chat_session.py
# -----------------------------------------------------------------------------
# One conversation between the two participants, from the handshake until
# the connection is closed.
#
# Two threads work at the same time during the chat:
#
#   main thread      -> reads the keyboard and SENDS messages
#   receiver thread  -> RECEIVES messages and prints them
#
# Windows cannot wait on the keyboard and a socket with select(), so threads
# are the portable way to read and receive at the same time.
#
# Life cycle of a session:
#   1. Handshake  : role-specific object (AliceHandshake / BobHandshake). The
#                   keyboard is NOT read and no chat message is accepted until
#                   it finishes. If it fails, ABORT is sent and the session ends.
#   2. Chat       : keyboard loop + receiver thread.
#   3. Closing    : /salir sends BYE; Ctrl+C or peer loss also ends it.
#   4. Cleanup    : stop the receiver thread and close the socket.
# =============================================================================

import threading

from errors import ConnectionClosedError
from errors import FrameTooLargeError
from errors import HandshakeError
from errors import ProtocolError
from message import Message
from message import MessageType


class ChatSession:
    """Runs the handshake and then the chat over an already connected FramedConnection."""

    def __init__(self, connection, codec, view, handshake, local_name, exit_command,
                 receiver_join_timeout):
        # Collaborators (injected, so they can be replaced in later steps).
        self._connection = connection
        self._codec = codec
        self._view = view
        self._handshake = handshake

        # Settings.
        self._local_name = local_name
        self._exit_command = exit_command
        self._receiver_join_timeout = receiver_join_timeout

        # Filled in by the handshake.
        self._session_material = None
        self._peer_name = "par"

        # Set when the session must end, by either thread.
        self._stop_event = threading.Event()

        # True when the end was requested locally (/salir or Ctrl+C), so the
        # receiver thread does not report it as an unexpected disconnection.
        self._local_exit_requested = False

        self._receiver_thread = None

    # =========================================================================
    # Public entry point
    # =========================================================================
    def run(self):
        """
        Run the whole session. Always closes the connection before returning.

        HandshakeError escapes after ABORT was sent; the caller reports it.
        """
        try:
            self._run_handshake()
            self._view.show_secure_session_established(
                self._session_material, self._connection.get_peer_address_text()
            )
            self._view.show_chat_instructions(self._exit_command)
            self._start_receiver_thread()
            self._keyboard_loop()
        finally:
            self._finish()

    # =========================================================================
    # 1. Handshake
    # =========================================================================
    def _run_handshake(self):
        try:
            self._session_material = self._handshake.perform()
        except HandshakeError as error:
            # Tell the peer why, then let the caller close the connection.
            self._handshake.send_abort(str(error))
            raise

        self._peer_name = self._session_material.peer_name

    # =========================================================================
    # 2a. Receiving (runs in its own thread)
    # =========================================================================
    def _start_receiver_thread(self):
        # daemon=True: if something goes badly wrong, this thread will never
        # keep the program alive on its own after the main thread exits.
        self._receiver_thread = threading.Thread(target=self._receive_loop, name="receiver", daemon=True)
        self._receiver_thread.start()

    def _receive_loop(self):
        """Receive frames until the session stops, the peer leaves or an error occurs."""
        while not self._stop_event.is_set():
            # ---- Wait for the next frame ------------------------------------
            try:
                payload = self._connection.receive_frame(self._stop_event)
            except ConnectionClosedError:
                self._report_peer_lost("El par cerro la conexion sin despedirse.")
                break
            except ConnectionResetError:
                # On Windows this is WinError 10054: the peer process died.
                self._report_peer_lost("La conexion fue interrumpida abruptamente por el par.")
                break
            except FrameTooLargeError as error:
                self._report_peer_lost("Trama rechazada: " + str(error))
                break
            except OSError as error:
                # Expected when we closed the socket ourselves; otherwise a real error.
                if not self._stop_event.is_set():
                    self._report_peer_lost("Error de red: " + str(error))
                break

            # None means stop_event was set while waiting.
            if payload is None:
                break

            # ---- Interpret the frame ----------------------------------------
            try:
                received_message = self._codec.decode(payload)
            except ProtocolError as error:
                self._view.show_warning("Mensaje invalido descartado: " + str(error))
                continue

            if received_message.message_type == MessageType.CHAT:
                self._show_chat_message(received_message)
            elif received_message.message_type == MessageType.BYE:
                self._report_peer_lost(self._peer_name + " termino la sesion.")
                break
            else:
                # Handshake messages after the handshake are not allowed.
                self._view.show_warning("Mensaje inesperado durante el chat: " + received_message.message_type.name)

        # Whatever the reason, the session is over from the receiver's side.
        self._stop_event.set()

    def _show_chat_message(self, received_message):
        try:
            text = self._codec.body_to_text(received_message.body)
        except ProtocolError as error:
            self._view.show_warning("Mensaje de chat invalido descartado: " + str(error))
            return
        self._view.show_peer_message(self._peer_name, text)

    def _report_peer_lost(self, reason):
        """Tell the user the conversation ended because of the peer."""
        if self._local_exit_requested:
            return
        self._view.show_warning(reason)
        # The main thread is still blocked inside input(); it only notices
        # the end of the session after the user presses Enter.
        self._view.show_info("Presione Enter para volver al menu.")

    # =========================================================================
    # 2b. Sending (main thread)
    # =========================================================================
    def _keyboard_loop(self):
        """Read lines from the keyboard and send them until the session ends."""
        chat_prompt = self._view.build_chat_prompt(self._local_name)

        while not self._stop_event.is_set():
            try:
                typed_line = self._view.read_line(chat_prompt)
            except KeyboardInterrupt:
                self._view.show_blank_line()
                self._view.show_warning("Ctrl+C detectado: cerrando la sesion.")
                self._say_goodbye()
                break
            except EOFError:
                self._say_goodbye()
                break

            # The peer may have left while the user was typing.
            if self._stop_event.is_set():
                break

            text = typed_line.strip()

            if text == "":
                continue

            if text == self._exit_command:
                self._say_goodbye()
                break

            self._send_chat_text(text)

    def _send_chat_text(self, text):
        """Send one chat line. Stops the session if the socket is broken."""
        chat_message = Message(MessageType.CHAT, self._codec.text_to_body(text))
        try:
            self._connection.send_frame(self._codec.encode(chat_message))
        except FrameTooLargeError as error:
            # Only this message is rejected; the session continues.
            self._view.show_error(str(error))
        except OSError as error:
            self._view.show_error("No se pudo enviar el mensaje: " + str(error))
            self._stop_event.set()

    # =========================================================================
    # 3. Closing
    # =========================================================================
    def _say_goodbye(self):
        """Mark the exit as local and notify the peer with a BYE message."""
        self._local_exit_requested = True
        bye_message = Message(MessageType.BYE, b"")
        try:
            self._connection.send_frame(self._codec.encode(bye_message))
            self._view.show_info("Despedida enviada a " + self._peer_name + ".")
        except OSError:
            # The peer is already gone; nothing else to do.
            pass

    # =========================================================================
    # 4. Cleanup
    # =========================================================================
    def _finish(self):
        """Stop the receiver thread and close the socket (always runs)."""
        self._stop_event.set()

        if self._receiver_thread is not None:
            # The receiver wakes up every SOCKET_POLL_TIMEOUT seconds, sees
            # stop_event and returns, so this join is short.
            self._receiver_thread.join(self._receiver_join_timeout)

        self._connection.close()

        # Drop our reference to the session key; it is not needed any more.
        self._session_material = None

        self._view.show_info("Sesion cerrada.")