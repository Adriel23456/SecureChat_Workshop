# =============================================================================
# console_view.py
# -----------------------------------------------------------------------------
# Everything the user SEES goes through this class. No other class calls
# print() or input() directly.
#
# The tricky part: the receiver thread prints incoming messages while the
# user is typing in the main thread. To keep the screen readable:
#   - every print is protected by a lock, and blocks of lines are printed
#     together, so two messages never mix;
#   - while a prompt is active, the prompt line is erased, the message is
#     printed, and the prompt is written again TOGETHER WITH THE TEXT THE
#     USER HAD ALREADY TYPED (Paso 5), so nothing typed is lost on screen.
#
# Visual labels used during the chat (Paso 5):
#   [TÚ]          what the local user wrote (plaintext, stays local)
#   [CIFRADO →]   what was sent through the socket (nonce, ciphertext, tag)
#   [← CIFRADO]   what arrived from the socket, before any verification
#   [TAG OK]      the tag was verified
#   [ALICE]/[BOB] message recovered AFTER the verification
#   [!]           errors and rejected messages ("MENSAJE RECHAZADO", Paso 6)
#   [i]           information
# =============================================================================

import codecs
import getpass
import os
import select
import sys
import threading
import time


# -----------------------------------------------------------------------------
# ANSI escape codes (understood by Windows Terminal and modern PowerShell)
# -----------------------------------------------------------------------------
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"

# Moves the cursor to the start of the line and erases it.
CLEAR_CURRENT_LINE = "\r\033[2K"

# Width of the banner and menu separators.
SEPARATOR_WIDTH = 60

# Width of the left column in "key : value" lines.
KEY_COLUMN_WIDTH = 28

# Width of the "usage" column in the list of chat commands.
COMMAND_USAGE_WIDTH = 34

# -----------------------------------------------------------------------------
# Chat labels (Paso 5)
# -----------------------------------------------------------------------------
LABEL_LOCAL = "[TÚ]"
LABEL_SENT = "[CIFRADO →]"
LABEL_RECEIVED = "[← CIFRADO]"
LABEL_TAG_OK = "[TAG OK]"
LABEL_PROBLEM = "[!]"
LABEL_INFO = "[i]"

# -----------------------------------------------------------------------------
# Special keys returned by msvcrt.getwch() on Windows
# -----------------------------------------------------------------------------
KEY_ENTER = "\r"
KEY_NEW_LINE = "\n"
KEY_BACKSPACE = "\x08"
KEY_CTRL_C = "\x03"
KEY_ESCAPE = "\x1b"
# Arrow keys, F1..F12, Insert, Delete... arrive as one of these prefixes
# followed by a second character that identifies the key.
EXTENDED_KEY_PREFIXES = ["\x00", "\xe0"]

# Bytes read at a time from stdin when there is no Windows console.
STDIN_READ_CHUNK_SIZE = 1024


class ConsoleView:
    """Thread-safe console output and keyboard input."""

    def __init__(self, use_colors, key_source, keyboard_poll_interval):
        self._use_colors = use_colors

        # WindowsConsoleKeySource, or None when there is no Windows console.
        self._key_source = key_source

        # How often (seconds) the chat prompt checks for keys / end of session.
        self._keyboard_poll_interval = keyboard_poll_interval

        # Only one thread at a time may write to the screen.
        self._print_lock = threading.Lock()

        # Text of the prompt currently waiting for input; "" when none.
        self._active_prompt = ""

        # Characters the user has typed in the active chat prompt (key mode).
        self._typed_text = ""

        # Used only when reading stdin without a Windows console (Linux, pipes).
        self._stdin_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._pending_stdin_text = ""

        # On the classic Windows console, calling os.system("") switches on
        # ANSI color support for this process. It does nothing harmful elsewhere.
        if os.name == "nt":
            os.system("")

    # -------------------------------------------------------------------------
    # Low-level helpers
    # -------------------------------------------------------------------------
    def _paint(self, text, color):
        """Wrap text in a color, or return it untouched if colors are off."""
        if self._use_colors:
            return color + text + COLOR_RESET
        return text

    def _write_line(self, text):
        """Write one line safely, even if the user is typing."""
        lines = [text]
        self._write_lines(lines)

    def _write_lines(self, lines):
        """
        Write several lines as ONE block, even if the user is typing.

        If a prompt is active: erase the prompt line, print all the lines,
        then write the prompt again followed by what the user had typed.
        """
        with self._print_lock:
            if self._active_prompt != "":
                if self._use_colors:
                    sys.stdout.write(CLEAR_CURRENT_LINE)
                else:
                    sys.stdout.write("\n")
                for line in lines:
                    sys.stdout.write(line + "\n")
                sys.stdout.write(self._active_prompt + self._typed_text)
            else:
                for line in lines:
                    sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def supports_interruptible_input(self):
        """
        True if read_chat_line() can stop by itself when the session ends.
        False only in the blocking fallback (Windows with redirected input).
        """
        if self._key_source is not None:
            return True
        if os.name != "nt":
            return True
        return False

    # -------------------------------------------------------------------------
    # Input for menus (simple, blocking)
    # -------------------------------------------------------------------------
    def read_line(self, prompt):
        """
        Show a prompt and wait for the user to press Enter.

        KeyboardInterrupt (Ctrl+C) and EOFError are NOT caught here; the
        caller decides what they mean in its own context.
        """
        with self._print_lock:
            self._active_prompt = prompt
            self._typed_text = ""

        try:
            typed_text = input(prompt)
        finally:
            with self._print_lock:
                self._active_prompt = ""

        return typed_text

    def read_secret(self, prompt):
        """
        Ask for a secret (passphrase) WITHOUT showing what is typed.

        getpass hides the characters in a real terminal (PowerShell, Windows
        Terminal, VS Code terminal). The typed value is returned to the caller
        and never printed.
        """
        with self._print_lock:
            self._active_prompt = prompt
            self._typed_text = ""

        try:
            secret_text = getpass.getpass(prompt)
        finally:
            with self._print_lock:
                self._active_prompt = ""

        return secret_text

    def read_yes_no(self, question):
        """Ask a yes/no question. Only "s" or "si" (any case) count as yes."""
        answer = self.read_line(question + " [s/N]: ")
        normalized_answer = answer.strip().lower()
        if normalized_answer == "s":
            return True
        if normalized_answer == "si":
            return True
        return False

    # -------------------------------------------------------------------------
    # Input for the chat (interruptible, Paso 5)
    # -------------------------------------------------------------------------
    def read_chat_line(self, prompt, stop_event):
        """
        Read one chat line. Returns the text, or None if stop_event was set
        while waiting (for example, the peer said goodbye).

        Raises KeyboardInterrupt on Ctrl+C and EOFError if the input closes.
        """
        if self._key_source is not None:
            return self._read_line_key_by_key(prompt, stop_event)

        if os.name != "nt":
            return self._read_line_with_select(prompt, stop_event)

        # Windows with redirected input: no way to poll; plain blocking read.
        return self.read_line(prompt)

    def _read_line_key_by_key(self, prompt, stop_event):
        """Windows console: build the line ourselves from single keys."""
        with self._print_lock:
            self._active_prompt = prompt
            self._typed_text = ""
            sys.stdout.write(prompt)
            sys.stdout.flush()

        try:
            while True:
                if stop_event.is_set():
                    return None

                if not self._key_source.has_key():
                    time.sleep(self._keyboard_poll_interval)
                    continue

                key = self._key_source.read_key()
                line_finished, finished_text = self._handle_key(key)
                if line_finished:
                    return finished_text
        finally:
            with self._print_lock:
                self._active_prompt = ""
                self._typed_text = ""

    def _handle_key(self, key):
        """
        Apply one key to the line being typed.

        Returns (True, text) when Enter finishes the line, (False, None) otherwise.
        """
        # ---- Enter: the line is complete -----------------------------------------
        if key == KEY_ENTER or key == KEY_NEW_LINE:
            with self._print_lock:
                finished_text = self._typed_text
                # Erase the prompt line; the session prints "[TÚ] ..." instead.
                if self._use_colors:
                    sys.stdout.write(CLEAR_CURRENT_LINE)
                else:
                    sys.stdout.write("\n")
                sys.stdout.flush()
            return True, finished_text

        # ---- Ctrl+C ----------------------------------------------------------------
        if key == KEY_CTRL_C:
            raise KeyboardInterrupt()

        # ---- Backspace: delete the last character -----------------------------------
        if key == KEY_BACKSPACE:
            with self._print_lock:
                if len(self._typed_text) > 0:
                    self._typed_text = self._typed_text[:-1]
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            return False, None

        # ---- Arrows, function keys...: read and ignore the second character ----------
        if key in EXTENDED_KEY_PREFIXES:
            self._key_source.read_key()
            return False, None

        # ---- Escape and other control characters: ignored --------------------------
        if key == KEY_ESCAPE:
            return False, None
        if key < " ":
            return False, None

        # ---- Normal character: add it and show it ------------------------------------
        with self._print_lock:
            self._typed_text = self._typed_text + key
            sys.stdout.write(key)
            sys.stdout.flush()
        return False, None

    def _read_line_with_select(self, prompt, stop_event):
        """
        No Windows console (Linux / pipes): wait on stdin with select() so the
        wait can still be interrupted. The terminal shows the typed text itself.
        """
        with self._print_lock:
            self._active_prompt = prompt
            self._typed_text = ""
            sys.stdout.write(prompt)
            sys.stdout.flush()

        stdin_descriptor = sys.stdin.fileno()

        try:
            while True:
                # A complete line may already be waiting from a previous read.
                complete_line = self._take_pending_stdin_line()
                if complete_line is not None:
                    return complete_line

                if stop_event.is_set():
                    return None

                ready_list = select.select([stdin_descriptor], [], [], self._keyboard_poll_interval)[0]
                if len(ready_list) == 0:
                    continue

                raw_bytes = os.read(stdin_descriptor, STDIN_READ_CHUNK_SIZE)
                if raw_bytes == b"":
                    raise EOFError()

                decoded_text = self._stdin_decoder.decode(raw_bytes)
                self._pending_stdin_text = self._pending_stdin_text + decoded_text
        finally:
            with self._print_lock:
                self._active_prompt = ""

    def _take_pending_stdin_line(self):
        """Remove and return the first complete line from the pending text, or None."""
        new_line_position = self._pending_stdin_text.find("\n")
        if new_line_position < 0:
            return None
        line = self._pending_stdin_text[:new_line_position]
        self._pending_stdin_text = self._pending_stdin_text[new_line_position + 1:]
        return line.rstrip("\r")

    # -------------------------------------------------------------------------
    # Generic messages
    # -------------------------------------------------------------------------
    def show_blank_line(self):
        self._write_line("")

    def show_info(self, text):
        self._write_line(self._paint(LABEL_INFO + " " + text, COLOR_CYAN))

    def show_success(self, text):
        self._write_line(self._paint("[OK] " + text, COLOR_GREEN))

    def show_warning(self, text):
        self._write_line(self._paint(LABEL_PROBLEM + " " + text, COLOR_YELLOW))

    def show_error(self, text):
        self._write_line(self._paint(LABEL_PROBLEM + " ERROR: " + text, COLOR_RED))

    # -------------------------------------------------------------------------
    # Banner and menu
    # -------------------------------------------------------------------------
    def show_banner(self, title):
        separator = "=" * SEPARATOR_WIDTH
        self._write_line(self._paint(separator, COLOR_BLUE))
        self._write_line(self._paint("  " + title, COLOR_BOLD))
        self._write_line(self._paint(separator, COLOR_BLUE))

    def show_menu(self, menu_options):
        """menu_options is a list of MenuOption objects (see main.py)."""
        self.show_blank_line()
        self._write_line(self._paint("----- MENU -----", COLOR_BOLD))
        for menu_option in menu_options:
            line = "  " + menu_option.key + ") " + menu_option.label
            self._write_line(line)

    def show_section_title(self, title):
        """Small heading used by the key management screens."""
        self.show_blank_line()
        self._write_line(self._paint("----- " + title + " -----", COLOR_BOLD))

    def show_key_value(self, key, value):
        """Print an aligned "key : value" line (used by the configuration screen)."""
        padded_key = key.ljust(KEY_COLUMN_WIDTH)
        self._write_line("  " + padded_key + ": " + str(value))

    # -------------------------------------------------------------------------
    # Chat: prompt, instructions and commands
    # -------------------------------------------------------------------------
    def build_chat_prompt(self):
        """Prompt shown while chatting: "[TÚ] > "."""
        return self._paint(LABEL_LOCAL + " > ", COLOR_GREEN)

    def show_chat_instructions(self, commands):
        self.show_info("Todos los mensajes viajan cifrados y autenticados con AES-256-GCM.")
        self.show_info("Escriba un mensaje y presione Enter para enviarlo. Comandos disponibles:")
        self.show_commands(commands)

    def show_commands(self, commands):
        """commands is a list of ChatCommand objects."""
        lines = []
        for command in commands:
            lines.append("      " + command.usage.ljust(COMMAND_USAGE_WIDTH) + " " + command.description)
        self._write_lines(lines)

    def show_detail_mode(self, enabled):
        if enabled:
            self.show_info("Vista detallada ACTIVADA: se muestran nonce, ciphertext y tag.")
        else:
            self.show_info("Vista detallada DESACTIVADA: una linea por mensaje cifrado.")

    def show_session_status(self, status_pairs):
        """status_pairs is a list of (label, value) tuples."""
        self.show_section_title("Estado de la sesion")
        for status_pair in status_pairs:
            self.show_key_value(status_pair[0], status_pair[1])

    # -------------------------------------------------------------------------
    # Chat: encrypted records (Paso 4 + labels of Paso 5)
    # -------------------------------------------------------------------------
    def _format_hex(self, data_bytes, preview_size):
        """Hexadecimal of data_bytes, cut at preview_size bytes. Display only, NOT encryption."""
        preview_hex = data_bytes[:preview_size].hex()
        if len(data_bytes) > preview_size:
            preview_hex = preview_hex + "..."
        return preview_hex

    def show_outgoing_plaintext(self, text, plaintext_size):
        """What the local user wrote, BEFORE encryption (stays in this terminal)."""
        self._write_line(
            self._paint(LABEL_LOCAL + " ", COLOR_GREEN) + text
            + self._paint("  (" + str(plaintext_size) + " bytes UTF-8, no sale de esta terminal)", COLOR_CYAN)
        )

    def show_outgoing_record(self, sealed_record, frame_payload_size, show_details, preview_size):
        """What actually goes into the socket: nonce, ciphertext and tag."""
        lines = []
        header = (
            LABEL_SENT + " seq=" + str(sealed_record.counter)
            + " | trama de " + str(frame_payload_size) + " bytes enviada por el socket"
        )
        lines.append(self._paint(header, COLOR_YELLOW))
        if show_details:
            lines.append("      nonce      (" + str(len(sealed_record.nonce)) + " B): " + sealed_record.nonce.hex())
            lines.append(
                "      ciphertext (" + str(len(sealed_record.ciphertext)) + " B): "
                + self._format_hex(sealed_record.ciphertext, preview_size)
            )
            lines.append("      tag        (" + str(len(sealed_record.tag)) + " B): " + sealed_record.tag.hex())
        self._write_lines(lines)

    def show_incoming_record(self, peer_name, body, nonce_size, tag_size, frame_payload_size,
                             show_details, preview_size):
        """What arrived from the socket, BEFORE any verification."""
        lines = []
        header = LABEL_RECEIVED + " de " + peer_name + " | trama de " + str(frame_payload_size) + " bytes recibida"
        lines.append(self._paint(header, COLOR_YELLOW))
        if show_details:
            if len(body) < nonce_size + tag_size:
                lines.append("      (registro demasiado corto para separar nonce y tag)")
            else:
                nonce = body[:nonce_size]
                ciphertext = body[nonce_size:len(body) - tag_size]
                tag = body[len(body) - tag_size:]
                lines.append("      nonce      (" + str(len(nonce)) + " B): " + nonce.hex())
                lines.append("      ciphertext (" + str(len(ciphertext)) + " B): " + self._format_hex(ciphertext, preview_size))
                lines.append("      tag        (" + str(len(tag)) + " B): " + tag.hex())
        self._write_lines(lines)

    def show_record_verified(self, counter, peer_name, text):
        """Tag OK, then the recovered plaintext labelled with the peer name in capitals."""
        lines = []
        lines.append(self._paint(LABEL_TAG_OK + " seq=" + str(counter) + " autentico; plaintext recuperado:", COLOR_GREEN))
        lines.append(self._paint("[" + peer_name.upper() + "] ", COLOR_MAGENTA) + text)
        self._write_lines(lines)

    def show_rejected_record(self, title, reason, consecutive, max_consecutive):
        """
        A record failed verification. NOTHING of its content is printed.

        title is the kind of failure ("autenticacion fallida", ...); reason
        is the technical detail; consecutive / max_consecutive show how close
        the session is to being closed by the rejection policy (Paso 6).
        """
        lines = []
        lines.append(self._paint(LABEL_PROBLEM + " MENSAJE RECHAZADO: " + title, COLOR_BOLD + COLOR_RED))
        lines.append(self._paint(LABEL_PROBLEM + "   motivo: " + reason, COLOR_RED))
        lines.append(self._paint(LABEL_PROBLEM + "   no se muestra ningun plaintext de este mensaje; se descarta.", COLOR_RED))
        lines.append(self._paint(
            LABEL_PROBLEM + "   rechazos seguidos: " + str(consecutive) + " de " + str(max_consecutive)
            + " (al llegar al maximo se cierra la sesion)", COLOR_RED))
        self._write_lines(lines)

    def show_tamper_armed(self, target):
        self.show_warning(
            "PRUEBA DE INTEGRIDAD: el proximo mensaje que envie saldra con 1 byte alterado (" + target + ")."
        )

    def show_tamper_applied(self, tamper_result):
        """Show which byte of OUR record was changed before sending it (Paso 6)."""
        lines = []
        lines.append(self._paint(
            LABEL_PROBLEM + " PRUEBA: se altero 1 byte del " + tamper_result.field_name
            + " DESPUES de cifrar y ANTES de enviar", COLOR_BOLD + COLOR_YELLOW))
        lines.append(self._paint(
            LABEL_PROBLEM + "   posicion " + str(tamper_result.position) + " de la trama (sin contar el prefijo de longitud): "
            + format(tamper_result.original_value, "02x") + " -> " + format(tamper_result.altered_value, "02x"),
            COLOR_YELLOW))
        self._write_lines(lines)

    def show_peer_goodbye(self, peer_name):
        self._write_line(
            self._paint(LABEL_TAG_OK + " ", COLOR_GREEN)
            + self._paint("[" + peer_name.upper() + "] cerro la sesion (despedida cifrada y verificada).", COLOR_MAGENTA)
        )

    def show_session_summary(self, summary_pairs):
        """summary_pairs is a list of (label, value) tuples shown when the session ends."""
        self.show_section_title("Resumen de la sesion")
        for summary_pair in summary_pairs:
            self.show_key_value(summary_pair[0], summary_pair[1])

    # -------------------------------------------------------------------------
    # Handshake specific
    # -------------------------------------------------------------------------
    def show_handshake_title(self, title):
        self.show_blank_line()
        self._write_line(self._paint("===== " + title + " =====", COLOR_BLUE))

    def show_handshake_step(self, direction, text):
        """direction is "->" (sent) or "<-" (received)."""
        self._write_line(self._paint("[HS " + direction + "] ", COLOR_BLUE) + text)

    def show_bytes_preview(self, label, data_bytes, preview_size):
        """
        Show the size of a binary value and its first bytes in hexadecimal.

        Hexadecimal is only a way to DISPLAY bytes; it is not encryption.
        Only public values (randoms, ciphertexts, signatures) are shown here.
        """
        preview_hex = data_bytes[:preview_size].hex()
        suffix = ""
        if len(data_bytes) > preview_size:
            suffix = "..."
        self._write_line(
            "        " + label + " (" + str(len(data_bytes)) + " bytes): " + preview_hex + suffix
        )

    def show_secure_session_established(self, session_material, peer_address_text):
        """Big visible banner shown on both terminals once the handshake succeeded."""
        separator = "=" * SEPARATOR_WIDTH
        self.show_blank_line()
        self._write_line(self._paint(separator, COLOR_GREEN))
        self._write_line(self._paint("  SESION SEGURA ESTABLECIDA", COLOR_BOLD + COLOR_GREEN))
        self._write_line(self._paint(separator, COLOR_GREEN))
        self.show_key_value("Conectado con", session_material.peer_name + " @ " + peer_address_text)
        self.show_key_value("Huella del par (verificada)", session_material.peer_fingerprint.to_display_text())
        self.show_key_value("Clave de sesion", str(session_material.get_session_key_size_bits()) + " bits AES (no se muestra)")
        self.show_key_value("Id de sesion", session_material.get_session_id_text())
        self._write_line(self._paint(separator, COLOR_GREEN))
        self.show_info("El 'Id de sesion' debe ser IGUAL en ambas terminales.")