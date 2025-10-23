import threading
from rich.console import Console

dm_console = Console(
    soft_wrap=True,
    tab_size=4,
    highlight=False,
    highlighter=None,
)

dm_console_lock = threading.Lock()


def dm_print(msg: str, *args, **kwargs) -> None:
    # If someone has a better idea I'll be open for it. This is just
    # here to synchronize the logging output
    if kwargs.pop("locked", False):
        dm_console.print(msg, *args, **kwargs)
    else:
        with dm_console_lock:
            dm_console.print(msg, *args, **kwargs)


__all__ = ["dm_console", "dm_console_lock", "dm_print"]
