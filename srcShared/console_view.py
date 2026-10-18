# =============================================================================
# console_view.py
# -----------------------------------------------------------------------------
# Everything the user SEES goes through this class. No other class calls
# print() or input() directly.
#
# The tricky part: the receiver thread prints incoming messages while the
# main thread is waiting inside input(). To keep the screen readable, every
# print is protected by a lock and, if a prompt is active, the prompt is
# written again below the incoming message.
# =============================================================================

import getpass
import os
import sys
import threading


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


class ConsoleView:
    """Thread-safe console output and keyboard input."""

    def __init__(self, use_colors):
        self._use_colors = use_colors

        # Only one thread at a time may write to the screen.
        self._print_lock = threading.Lock()

        # Text of the prompt currently waiting in input(); "" when none.
        self._active_prompt = ""

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
        """Write one line safely, even if another thread is inside input()."""
        lines = [text]
        self._write_lines(lines)

    def _write_lines(self, lines):
        """
        Write several lines as ONE block, even if another thread is inside input().

        If a prompt is active, the line where the user is typing is erased,
        all the lines are printed together, and the prompt is printed again
        below them. Writing the block under a single lock keeps the lines of
        one message from being mixed with the lines of another.
        """
        with self._print_lock:
            if self._active_prompt != "":
                if self._use_colors:
                    sys.stdout.write(CLEAR_CURRENT_LINE)
                else:
                    sys.stdout.write("\n")
                for line in lines:
                    sys.stdout.write(line + "\n")
                sys.stdout.write(self._active_prompt)
            else:
                for line in lines:
                    sys.stdout.write(line + "\n")
            sys.stdout.flush()

    # -------------------------------------------------------------------------
    # Input
    # -------------------------------------------------------------------------
    def read_line(self, prompt):
        """
        Show a prompt and wait for the user to press Enter.

        KeyboardInterrupt (Ctrl+C) and EOFError are NOT caught here; the
        caller decides what they mean in its own context.
        """
        with self._print_lock:
            self._active_prompt = prompt

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
    # Generic messages
    # -------------------------------------------------------------------------
    def show_blank_line(self):
        self._write_line("")

    def show_info(self, text):
        self._write_line(self._paint("[i] " + text, COLOR_CYAN))

    def show_success(self, text):
        self._write_line(self._paint("[OK] " + text, COLOR_GREEN))

    def show_warning(self, text):
        self._write_line(self._paint("[!] " + text, COLOR_YELLOW))

    def show_error(self, text):
        self._write_line(self._paint("[ERROR] " + text, COLOR_RED))

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
    # Chat specific
    # -------------------------------------------------------------------------
    def build_chat_prompt(self, local_name):
        """Prompt shown while chatting, for example "[Bob] > "."""
        return self._paint("[" + local_name + "] > ", COLOR_GREEN)

    def show_chat_instructions(self, exit_command):
        self.show_info("Todos los mensajes viajan cifrados y autenticados con AES-256-GCM.")
        self.show_info("Escriba un mensaje y presione Enter para enviarlo.")
        self.show_info("Escriba " + exit_command + " para terminar la sesion.")

    # -------------------------------------------------------------------------
    # Encrypted records (Paso 4)
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
            self._paint("[TU - texto plano local] ", COLOR_GREEN) + text
            + self._paint("  (" + str(plaintext_size) + " bytes UTF-8, no sale de esta terminal)", COLOR_CYAN)
        )

    def show_outgoing_record(self, sealed_record, frame_payload_size, show_details, preview_size):
        """What actually goes into the socket: nonce, ciphertext and tag."""
        lines = []
        header = (
            "[CIFRADO ->] seq=" + str(sealed_record.counter)
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
        header = "[<- CIFRADO] de " + peer_name + " | trama de " + str(frame_payload_size) + " bytes recibida"
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
        """Tag OK, then the recovered plaintext, printed together."""
        lines = []
        lines.append(self._paint("[TAG OK] seq=" + str(counter) + " autentico; plaintext recuperado:", COLOR_GREEN))
        lines.append(self._paint("[" + peer_name + "] ", COLOR_MAGENTA) + text)
        self._write_lines(lines)

    def show_rejected_record(self, reason):
        lines = []
        lines.append(self._paint("[RECHAZADO] " + reason, COLOR_RED))
        lines.append(self._paint("[RECHAZADO] No se muestra ningun contenido de este mensaje.", COLOR_RED))
        self._write_lines(lines)

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