import random
from pathlib import Path
import os

# Automatically resolve base and default message directory
BASE_DIR = Path(__file__).parent
DEFAULT_MESSAGES_DIR = BASE_DIR / "messages"

class MessageManager:
    _instances = {}

    def __init__(self, name: str, filepath: str, shuffle_mode: bool = False):
        self.name = name
        self.filepath = self._resolve_path(filepath)
        self.shuffle_mode = shuffle_mode
        self.messages = []
        self.last_message = None
        self.last_mtime = None
        self._shuffled_pool = []  # used in shuffle mode
        self._load_messages(force=True)

    def _resolve_path(self, filepath: str) -> Path:
        """
        If filepath is a bare filename, resolve it inside DEFAULT_MESSAGES_DIR.
        If it's an absolute or relative path, resolve it as given.
        """
        path = Path(filepath)
        # If path has no directory part (i.e., just a filename), use default dir
        if not path.parent or str(path.parent) in (".", ""):
            full_path = DEFAULT_MESSAGES_DIR / path
        else:
            full_path = path
        full_path = full_path.expanduser().resolve()
        # Ensure directory exists
        full_path.parent.mkdir(parents=True, exist_ok=True)
        return full_path

    def _load_messages(self, force: bool = False):
        """Load messages from file, with optional forced reload."""
        if not self.filepath.exists():
            raise FileNotFoundError(f"Message file not found: {self.filepath}")

        current_mtime = os.path.getmtime(self.filepath)

        # Only reload if forced or file was modified
        if force or self.last_mtime is None or current_mtime > self.last_mtime:
            with open(self.filepath, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            if not lines:
                raise ValueError(f"No valid messages found in {self.filepath}")
            self.messages = lines
            self.last_mtime = current_mtime
            self._reset_shuffle_pool()

    def _reset_shuffle_pool(self):
        """Reset shuffle pool when in shuffle mode."""
        if self.shuffle_mode:
            self._shuffled_pool = self.messages.copy()
            random.shuffle(self._shuffled_pool)

    def _get_shuffle_message(self):
        """Return next message from shuffled pool, reshuffle when empty."""
        if not self._shuffled_pool:
            self._reset_shuffle_pool()
        return self._shuffled_pool.pop()

    def _get_random_message(self):
        """Return a random message, avoiding repeat of last one."""
        if len(self.messages) == 1:
            return self.messages[0]

        message = random.choice(self.messages)
        while message == self.last_message:
            message = random.choice(self.messages)
        self.last_message = message
        return message

    def get_message(self):
        """Return a message, auto reloading file if changed."""
        self._load_messages()  # reload if file changed
        if self.shuffle_mode:
            return self._get_shuffle_message()
        return self._get_random_message()

    @classmethod
    def get_instance(cls, name: str, filepath: str, shuffle_mode: bool = False):
        """Return or create a MessageManager instance keyed by name."""
        key = (name, str(Path(filepath).resolve()))
        if key not in cls._instances:
            cls._instances[key] = cls(name, filepath, shuffle_mode)
        return cls._instances[key]


def get_message(name: str, filepath: str, shuffle_mode: bool = True) -> str:
    """
    Convenience wrapper to fetch a message for a given caller name.
    Automatically uses the default /messages directory if only a filename is given.
    """
    manager = MessageManager.get_instance(name, filepath, shuffle_mode)
    return manager.get_message()
