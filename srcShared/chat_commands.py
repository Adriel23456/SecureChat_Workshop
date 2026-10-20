# =============================================================================
# chat_commands.py
# -----------------------------------------------------------------------------
# Commands the user can type during the chat (they start with "/" and are
# NEVER sent to the peer):
#
#   /salir             end the session (encrypted goodbye)
#   /detalle           show / hide nonce, ciphertext and tag of every message
#   /estado            show counters and session information
#   /alterar [campo]   integrity test: alter 1 byte of the next message (Paso 6)
#   /ayuda             list the commands
#
# A typed command is split into its NAME (first word) and an optional
# ARGUMENT (the rest of the line). The action of every command receives the
# argument ("" when there is none) and returns True if the chat must end.
#
# ChatCommandRegistry only stores and finds commands; what each command does
# is defined by ChatSession when it registers them. Adding a new command is
# one register() call (open for extension, closed for modification).
# =============================================================================


class ChatCommand:
    """One chat command: its name, how to use it, a description and its action."""

    def __init__(self, name, usage, description, action):
        self.name = name
        self.usage = usage
        self.description = description
        self.action = action


class ChatCommandRegistry:
    """Ordered list of chat commands."""

    # Every command starts with this character.
    COMMAND_PREFIX = "/"

    def __init__(self):
        self._commands = []

    def register(self, command):
        self._commands.append(command)

    def get_all(self):
        return self._commands

    def is_command(self, text):
        """True if the text looks like a command (starts with "/")."""
        return text.startswith(self.COMMAND_PREFIX)

    def split(self, text):
        """Return (name, argument). "/alterar TAG" -> ("/alterar", "tag")."""
        clean_text = text.strip()
        space_position = clean_text.find(" ")
        if space_position < 0:
            return clean_text.lower(), ""
        name = clean_text[:space_position].lower()
        argument = clean_text[space_position + 1:].strip().lower()
        return name, argument

    def find(self, name):
        """Return the command with that exact name, or None."""
        for command in self._commands:
            if command.name == name:
                return command
        return None