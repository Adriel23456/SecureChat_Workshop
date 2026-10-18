# =============================================================================
# menu_option.py
# -----------------------------------------------------------------------------
# One entry of a console menu. Shared by Alice's and Bob's main.py so both
# menus are built the same way.
# =============================================================================


class MenuOption:
    """One entry of the main menu: the key to type, its label and its action."""

    def __init__(self, key, label, action):
        # What the user types to choose this option ("1", "2", ...).
        self.key = key

        # Text shown next to the key.
        self.label = label

        # Method (with no arguments) executed when the option is chosen.
        self.action = action