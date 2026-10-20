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
# Both sides can therefore write and receive at any moment. Windows cannot
# wait on the keyboard and a socket with select(), so threads are used.
#
# Life cycle of a session:
#   1. Handshake  : role-specific object (AliceHandshake / BobHandshake). The
#                   keyboard is NOT read and no chat message is accepted until
#                   it finishes. If it fails, ABORT is sent and the session ends.
#   2. Chat       : keyboard loop + receiver thread. EVERY record (CHAT and
#                   BYE) goes through SecureChannel (AES-256-GCM). There is no
#                   code path that writes user text to the socket in clear.
#                   Lines starting with "/" are local commands, never sent.
#   3. Closing    : /salir sends an encrypted BYE. The peer verifies it, shows
#                   it, and BOTH sides return to the menu by themselves.
#   4. Cleanup    : stop the receiver thread, close the socket, drop every
#                   reference to the session key and print a summary.
#
# Paso 6 (integrity):
#   - /alterar [ct|tag|nonce|tipo] alters ONE byte of our next record after it
#     was encrypted and before it is sent (controlled test).
#   - Every rejected record is reported as "MENSAJE RECHAZADO", shows no
#     plaintext and is discarded. RejectionPolicy ends the session after
#     MAX_CONSECUTIVE_REJECTIONS rejections in a row.
# =============================================================================

import threading

import shared_config
from chat_commands import ChatCommand
from chat_commands import ChatCommandRegistry
from errors import ConnectionClosedError
from errors import FrameTooLargeError
from errors import HandshakeError
from errors import MessageAuthenticationError
from errors import NonceExhaustedError
from errors import ProtocolError
from errors import ReplayError
from message import Message
from message import MessageCodec
from message import MessageType
from record_tamperer import RecordTamperer
from rejection_policy import RejectionPolicy
from secure_channel import SecureChannel

# Titles shown in "MENSAJE RECHAZADO: <title>".
REJECTION_TITLE_AUTHENTICATION = "autenticacion fallida"
REJECTION_TITLE_REPLAY = "repeticion o direccion invalida"
REJECTION_TITLE_FORMAT = "formato invalido"


class ChatSettings:
    """Per-side chat options (injected from main.py)."""

    def __init__(self, local_name, exit_command, detail_command, status_command, help_command,
                 receiver_join_timeout, show_message_details, message_preview_size):
        self.local_name = local_name
        self.exit_command = exit_command
        self.detail_command = detail_command
        self.status_command = status_command
        self.help_command = help_command
        self.receiver_join_timeout = receiver_join_timeout
        self.show_message_details = show_message_details
        self.message_preview_size = message_preview_size


class ChatSession:
    """Runs the handshake and then the encrypted, bidirectional chat."""

    def __init__(self, connection, codec, view, handshake, channel_settings, chat_settings):
        # Collaborators (injected).
        self._connection = connection
        self._codec = codec
        self._view = view
        self._handshake = handshake
        self._channel_settings = channel_settings
        self._settings = chat_settings

        # Detailed view (nonce / ciphertext / tag). Changed with /detalle from
        # the main thread and read by the receiver thread; assigning a bool is
        # atomic in Python, so no lock is needed.
        self._show_details = chat_settings.show_message_details

        # Filled in after the handshake.
        self._session_material = None
        self._secure_channel = None
        self._peer_name = "par"
        self._session_id_text = ""

        # Counters for /estado and for the final summary.
        self._sent_count = 0
        self._received_count = 0
        self._rejected_count = 0
        self._tampered_sent_count = 0

        # Paso 6: what happens after a rejected record.
        self._rejection_policy = RejectionPolicy(shared_config.MAX_CONSECUTIVE_REJECTIONS)

        # Paso 6: controlled integrity test. None = next message goes intact.
        self._tamperer = RecordTamperer(
            MessageCodec.TYPE_FIELD_SIZE,
            shared_config.NONCE_DIRECTION_SIZE_BYTES,
            channel_settings.nonce_layout.get_nonce_size(),
            channel_settings.tag_size,
            int(MessageType.CHAT),
            int(MessageType.BYE),
        )
        self._armed_tamper_target = None

        # Set when the session must end, by either thread.
        self._stop_event = threading.Event()

        # True when the end was requested locally (/salir, Ctrl+C or the
        # rejection policy), so the receiver thread does not report it as an
        # unexpected disconnection.
        self._local_exit_requested = False

        # Why the session ended (shown in the summary).
        self._end_reason = "sin iniciar"

        self._receiver_thread = None

        # Local commands typed during the chat.
        self._commands = ChatCommandRegistry()
        self._register_commands()

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
            self._view.show_chat_instructions(self._commands.get_all())
            self._view.show_detail_mode(self._show_details)
            self._end_reason = "en curso"
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
        self._session_id_text = self._session_material.get_session_id_text()

        # From here on, every message goes through the secure channel.
        self._secure_channel = SecureChannel(self._session_material, self._channel_settings)

    # =========================================================================
    # Local commands
    # =========================================================================
    def _register_commands(self):
        tamper_targets_text = " | ".join(self._tamperer.get_targets())

        self._commands.register(ChatCommand(
            self._settings.help_command,
            self._settings.help_command,
            "muestra esta lista de comandos",
            self._command_help))
        self._commands.register(ChatCommand(
            self._settings.detail_command,
            self._settings.detail_command,
            "activa / desactiva la vista de nonce, ciphertext y tag",
            self._command_toggle_details))
        self._commands.register(ChatCommand(
            self._settings.status_command,
            self._settings.status_command,
            "muestra contadores e informacion de la sesion",
            self._command_status))
        self._commands.register(ChatCommand(
            shared_config.TAMPER_COMMAND,
            shared_config.TAMPER_COMMAND + " [" + tamper_targets_text + "]",
            "PRUEBA: altera 1 byte del proximo mensaje enviado",
            self._command_arm_tamper))
        self._commands.register(ChatCommand(
            self._settings.exit_command,
            self._settings.exit_command,
            "termina la sesion (despedida cifrada)",
            self._command_exit))

    def _execute_command(self, text):
        """Run a local command. Returns True if the chat must end."""
        name, argument = self._commands.split(text)
        command = self._commands.find(name)
        if command is None:
            self._view.show_warning(
                "Comando desconocido: '" + text + "'. Use " + self._settings.help_command + " (no se envio nada)."
            )
            return False
        return command.action(argument)

    def _command_help(self, argument):
        self._view.show_commands(self._commands.get_all())
        return False

    def _command_toggle_details(self, argument):
        self._show_details = not self._show_details
        self._view.show_detail_mode(self._show_details)
        return False

    def _command_status(self, argument):
        status_pairs = []
        status_pairs.append(("Par", self._peer_name + " @ " + self._connection.get_peer_address_text()))
        status_pairs.append(("Id de sesion", self._session_id_text))
        status_pairs.append(("Mensajes enviados", str(self._sent_count)))
        status_pairs.append(("  de ellos alterados", str(self._tampered_sent_count)))
        status_pairs.append(("Mensajes recibidos (validos)", str(self._received_count)))
        status_pairs.append(("Mensajes rechazados", str(self._rejected_count)))
        status_pairs.append((
            "Rechazos seguidos",
            str(self._rejection_policy.get_consecutive()) + " de " + str(self._rejection_policy.get_max_consecutive()),
        ))
        status_pairs.append(("Ultimo seq enviado", str(self._secure_channel.get_last_sent_counter())))
        status_pairs.append(("Ultimo seq aceptado", str(self._secure_channel.get_last_received_counter())))
        if self._show_details:
            status_pairs.append(("Vista detallada", "activada"))
        else:
            status_pairs.append(("Vista detallada", "desactivada"))
        self._view.show_session_status(status_pairs)
        return False

    def _command_arm_tamper(self, argument):
        """Paso 6: the NEXT chat message will leave with one altered byte."""
        target = argument
        if target == "":
            target = RecordTamperer.TARGET_CIPHERTEXT

        if not self._tamperer.is_valid_target(target):
            self._view.show_warning(
                "Campo desconocido: '" + target + "'. Use uno de: " + " | ".join(self._tamperer.get_targets()) + "."
            )
            return False

        self._armed_tamper_target = target
        self._view.show_tamper_armed(target)
        return False

    def _command_exit(self, argument):
        self._say_goodbye()
        return True

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
                self._reject(REJECTION_TITLE_FORMAT, str(error))
                continue

            if received_message.message_type == MessageType.CHAT:
                self._handle_encrypted_chat(received_message, len(payload))
            elif received_message.message_type == MessageType.BYE:
                goodbye_is_authentic = self._handle_encrypted_bye(received_message)
                if goodbye_is_authentic:
                    self._end_reason = self._peer_name + " cerro la sesion con /salir"
                    self._view.show_peer_goodbye(self._peer_name)
                    break
            else:
                # Handshake messages after the handshake are not allowed.
                self._reject(
                    REJECTION_TITLE_FORMAT,
                    "mensaje inesperado durante el chat: " + received_message.message_type.name,
                )

        # Whatever the reason, the session is over from the receiver's side.
        # Setting the event also wakes the keyboard prompt, so this side goes
        # back to the menu by itself.
        self._stop_event.set()

    def _handle_encrypted_chat(self, received_message, frame_size):
        """Verify and decrypt one CHAT record; print the plaintext ONLY if it is authentic."""
        nonce_size = self._channel_settings.nonce_layout.get_nonce_size()
        self._view.show_incoming_record(
            self._peer_name,
            received_message.body,
            nonce_size,
            self._channel_settings.tag_size,
            frame_size,
            self._show_details,
            self._settings.message_preview_size,
        )

        # SecureChannel turns cryptography's InvalidTag into
        # MessageAuthenticationError; in every except branch below no
        # plaintext exists, so nothing of the message can be printed.
        try:
            opened_record = self._secure_channel.open(MessageType.CHAT, received_message.body)
        except MessageAuthenticationError as error:
            self._reject(REJECTION_TITLE_AUTHENTICATION, str(error))
            return
        except ReplayError as error:
            self._reject(REJECTION_TITLE_REPLAY, str(error))
            return
        except ProtocolError as error:
            self._reject(REJECTION_TITLE_FORMAT, str(error))
            return

        try:
            text = self._codec.body_to_text(opened_record.plaintext)
        except ProtocolError as error:
            self._reject(REJECTION_TITLE_FORMAT, str(error))
            return

        self._rejection_policy.record_acceptance()
        self._received_count = self._received_count + 1
        self._view.show_record_verified(opened_record.counter, self._peer_name, text)

    def _handle_encrypted_bye(self, received_message):
        """Return True only if the BYE record is authentic."""
        try:
            self._secure_channel.open(MessageType.BYE, received_message.body)
        except MessageAuthenticationError as error:
            self._reject(REJECTION_TITLE_AUTHENTICATION, "BYE falso o alterado ignorado: " + str(error))
            return False
        except ReplayError as error:
            self._reject(REJECTION_TITLE_REPLAY, "BYE repetido ignorado: " + str(error))
            return False
        except ProtocolError as error:
            self._reject(REJECTION_TITLE_FORMAT, "BYE invalido ignorado: " + str(error))
            return False
        self._rejection_policy.record_acceptance()
        return True

    def _reject(self, title, reason):
        """
        Discard a record (Paso 6 policy) and end the session if too many
        records in a row were rejected.
        """
        self._rejected_count = self._rejected_count + 1
        session_must_end = self._rejection_policy.record_rejection()
        self._view.show_rejected_record(
            title,
            reason,
            self._rejection_policy.get_consecutive(),
            self._rejection_policy.get_max_consecutive(),
        )

        if session_must_end:
            # The channel is treated as compromised: no goodbye is sent and
            # nothing else that arrives is trusted.
            self._local_exit_requested = True
            self._end_reason = (
                str(self._rejection_policy.get_max_consecutive())
                + " mensajes rechazados seguidos: canal considerado comprometido"
            )
            self._view.show_error(
                "Se rechazaron " + str(self._rejection_policy.get_max_consecutive())
                + " mensajes seguidos. El canal se considera comprometido; se cierra la sesion."
            )
            self._stop_event.set()

    def _report_peer_lost(self, reason):
        """Tell the user the conversation ended because of the peer."""
        if self._local_exit_requested:
            return
        self._end_reason = reason
        self._view.show_warning(reason)
        # Only the blocking fallback cannot be woken up by stop_event.
        if not self._view.supports_interruptible_input():
            self._view.show_info("Presione Enter para volver al menu.")

    # =========================================================================
    # 2b. Sending (main thread)
    # =========================================================================
    def _keyboard_loop(self):
        """Read lines from the keyboard and send them until the session ends."""
        chat_prompt = self._view.build_chat_prompt()

        while not self._stop_event.is_set():
            try:
                typed_line = self._view.read_chat_line(chat_prompt, self._stop_event)
            except KeyboardInterrupt:
                self._view.show_blank_line()
                self._view.show_warning("Ctrl+C detectado: cerrando la sesion.")
                self._say_goodbye()
                break
            except EOFError:
                self._say_goodbye()
                break

            # None: the session ended while waiting (peer left or error).
            if typed_line is None:
                break

            # The peer may have left while the user was typing.
            if self._stop_event.is_set():
                break

            text = typed_line.strip()

            if text == "":
                continue

            if self._commands.is_command(text):
                chat_must_end = self._execute_command(text)
                if chat_must_end:
                    break
                continue

            self._send_chat_text(text)

    def _send_chat_text(self, text):
        """Encrypt one chat line with AES-GCM and send it. Plaintext never reaches the socket."""
        plaintext = self._codec.text_to_body(text)

        try:
            sealed_record = self._secure_channel.seal(MessageType.CHAT, plaintext)
        except NonceExhaustedError as error:
            self._view.show_error(str(error))
            self._end_reason = "contador de nonces agotado"
            self._stop_event.set()
            return

        chat_message = Message(MessageType.CHAT, sealed_record.body)
        frame_payload = self._codec.encode(chat_message)

        self._view.show_outgoing_plaintext(text, len(plaintext))
        self._view.show_outgoing_record(
            sealed_record,
            len(frame_payload),
            self._show_details,
            self._settings.message_preview_size,
        )

        # ---- Paso 6: controlled alteration, AFTER encrypting, BEFORE sending ----
        message_was_tampered = False
        if self._armed_tamper_target is not None:
            tamper_result = self._tamperer.tamper(frame_payload, self._armed_tamper_target)
            frame_payload = tamper_result.payload
            self._armed_tamper_target = None
            message_was_tampered = True
            self._view.show_tamper_applied(tamper_result)

        try:
            self._connection.send_frame(frame_payload)
        except FrameTooLargeError as error:
            # Only this message is rejected; the session continues.
            self._view.show_error(str(error))
            return
        except OSError as error:
            self._view.show_error("No se pudo enviar el mensaje: " + str(error))
            self._end_reason = "error de red al enviar"
            self._stop_event.set()
            return

        self._sent_count = self._sent_count + 1
        if message_was_tampered:
            self._tampered_sent_count = self._tampered_sent_count + 1

    # =========================================================================
    # 3. Closing
    # =========================================================================
    def _say_goodbye(self):
        """Mark the exit as local and notify the peer with an ENCRYPTED BYE."""
        self._local_exit_requested = True
        self._end_reason = "cerrada localmente con " + self._settings.exit_command

        try:
            sealed_record = self._secure_channel.seal(MessageType.BYE, b"")
        except NonceExhaustedError:
            return

        bye_message = Message(MessageType.BYE, sealed_record.body)
        try:
            self._connection.send_frame(self._codec.encode(bye_message))
            self._view.show_info(
                "Despedida cifrada enviada a " + self._peer_name + " (seq=" + str(sealed_record.counter) + ")."
            )
        except OSError:
            # The peer is already gone; nothing else to do.
            pass

    # =========================================================================
    # 4. Cleanup
    # =========================================================================
    def _finish(self):
        """Stop the receiver thread, close the socket and forget the key (always runs)."""
        self._stop_event.set()

        if self._receiver_thread is not None:
            # The receiver wakes up every SOCKET_POLL_TIMEOUT seconds, sees
            # stop_event and returns, so this join is short.
            self._receiver_thread.join(self._settings.receiver_join_timeout)

        self._connection.close()

        session_was_established = self._session_material is not None

        # Drop every reference to the session key. Python cannot guarantee the
        # bytes are wiped from RAM (immutable bytes, garbage collector, OpenSSL
        # copy), but after this no SecureChat object can use the key.
        if self._secure_channel is not None:
            self._secure_channel.close()
            self._secure_channel = None
        if self._session_material is not None:
            self._session_material.forget_session_key()
            self._session_material = None

        if session_was_established:
            summary_pairs = []
            summary_pairs.append(("Motivo del cierre", self._end_reason))
            summary_pairs.append(("Id de sesion", self._session_id_text))
            summary_pairs.append(("Mensajes enviados", str(self._sent_count)))
            summary_pairs.append(("  de ellos alterados", str(self._tampered_sent_count)))
            summary_pairs.append(("Mensajes recibidos (validos)", str(self._received_count)))
            summary_pairs.append(("Mensajes rechazados", str(self._rejected_count)))
            summary_pairs.append(("Clave de sesion", "referencias eliminadas"))
            self._view.show_session_summary(summary_pairs)

        self._view.show_info("Sesion cerrada.")