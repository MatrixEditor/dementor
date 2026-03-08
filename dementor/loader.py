# Copyright (c) 2025-Present MatrixEditor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading
import types
import typing

from importlib.machinery import SourceFileLoader

import dementor
from dementor.config.session import SessionConfig
from dementor.paths import DEMENTOR_PATH

# --------------------------------------------------------------------------- #
# Type aliases for the optional protocol entry‑points
# --------------------------------------------------------------------------- #
ApplyConfigFunc = typing.Callable[[SessionConfig], None]
"""Type alias for function that applies protocol configuration.

Signature: `apply_config(session: SessionConfig) -> None`

Used by protocol modules to customize global configuration based on protocol-specific needs.
"""

CreateServersFunc = typing.Callable[[SessionConfig], list[threading.Thread]]
"""Type alias for function that creates server threads for a protocol.

Signature: `create_server_threads(session: SessionConfig) -> list[threading.Thread]`

Returns a list of `threading.Thread` instances configured to run protocol servers.
"""


# --------------------------------------------------------------------------- #
# Structural protocol used for static type checking
# --------------------------------------------------------------------------- #
class ProtocolModule(typing.Protocol):
    """Protocol defining the expected interface for a Dementor protocol module.

    Modules must expose at least one of `apply_config` or `create_server_threads`.
    Optionally, may define a nested `config` submodule for hierarchical configuration.

    :cvar config: Optional submodule containing additional configuration logic.
    :vartype config: ProtocolModule | None
    :cvar apply_config: Function to apply protocol-specific config to session.
    :vartype apply_config: ApplyConfigFunc | None
    :cvar create_server_threads: Function to spawn protocol server threads.
    :vartype create_server_threads: CreateServersFunc | None
    """

    config: "ProtocolModule | None"
    apply_config: ApplyConfigFunc | None
    create_server_threads: CreateServersFunc | None


class ProtocolLoader:
    """Loads and manages protocol modules from filesystem.

    Searches for `.py` protocol files in predefined paths and optionally user-supplied directories.
    Provides methods to load modules, apply configuration, and spawn server threads.

    :ivar rs_path: Path to built-in protocol directory (`DEMENTOR_PATH/protocols`).
    :vartype rs_path: str
    :ivar search_path: List of directories to scan for protocol modules.
    :vartype search_path: list[str]
    """

    def __init__(self) -> None:
        """Initialize loader with default protocol search paths.

        Searches:
        1. Dementor package's internal `protocols/` directory
        2. External `DEMENTOR_PATH/protocols/` directory (for user extensions)
        """
        self.rs_path: str = os.path.join(DEMENTOR_PATH, "protocols")
        self.search_path: list[str] = [
            os.path.join(os.path.dirname(dementor.__file__), "protocols"),
            self.rs_path,
        ]

    # --------------------------------------------------------------------- #
    # Loading helpers
    # --------------------------------------------------------------------- #
    def load_protocol(self, protocol_path: str) -> types.ModuleType:
        """Dynamically load a protocol module from a Python file.

        Uses `SourceFileLoader` to import the module without requiring it to be in `sys.path`.

        :param protocol_path: Absolute path to the `.py` protocol file.
        :type protocol_path: str
        :return: Loaded module object.
        :rtype: types.ModuleType
        :raises ImportError: If module cannot be loaded.
        """
        loader = SourceFileLoader("protocol", protocol_path)
        protocol = types.ModuleType(loader.name)
        loader.exec_module(protocol)
        return protocol

    # --------------------------------------------------------------------- #
    # Discovery helpers
    # --------------------------------------------------------------------- #
    def get_protocols(
        self,
        session: SessionConfig | None = None,
    ) -> dict[str, str]:
        """Discover all available protocol modules in search paths.

        Scans directories and files for `.py` files (excluding `__init__.py`).
        Optionally extends search paths with `session.extra_modules`.

        :param session: Optional session to extend search paths with custom modules.
        :type session: SessionConfig | None
        :return: Dict mapping protocol name (without `.py`) to full file path.
        :rtype: dict[str, str]

        Example:
        >>> loader = ProtocolLoader()
        >>> protocols = loader.get_protocols()
        >>> protocols["smb"]  # -> "/path/to/dementor/protocols/smb.py"
        """
        protocols: dict[str, str] = {}
        protocol_paths: list[str] = list(self.search_path)

        if session is not None:
            protocol_paths.extend(session.extra_modules)

        for path in protocol_paths:
            if not os.path.exists(path):
                # Missing entries are ignored – they may be optional.
                continue

            if os.path.isfile(path):
                if not path.endswith(".py"):
                    continue
                name = os.path.basename(path)[:-3]  # strip .py
                protocols[name] = path
                continue

            for filename in os.listdir(path):
                if not filename.endswith(".py") or filename == "__init__.py":
                    continue
                protocol_path = os.path.join(path, filename)
                name = filename[:-3]  # strip extension
                protocols[name] = protocol_path

        return protocols

    # --------------------------------------------------------------------- #
    # Hook dispatchers
    # --------------------------------------------------------------------- #
    def apply_config(self, protocol: ProtocolModule, session: SessionConfig) -> None:
        """Apply protocol-specific configuration to the session.

        Looks for `apply_config(session)` function. If not found, checks for a nested `config` submodule
        and recursively applies its config.

        :param protocol: Loaded protocol module.
        :type protocol: ProtocolModule
        :param session: Session configuration to modify.
        :type session: SessionConfig
        """
        apply_config_fn: ApplyConfigFunc | None = getattr(
            protocol, "apply_config", None
        )

        if apply_config_fn is not None:
            # signature is: apply_config(session: SessionConfig)
            apply_config_fn(session)
        else:
            # Fallback to a nested config module, if present.
            if hasattr(protocol, "config"):
                config_mod: ProtocolModule | None = protocol.config
                if config_mod is not None:
                    self.apply_config(config_mod, session)

    def create_servers(
        self,
        protocol: ProtocolModule,
        session: SessionConfig,
    ) -> list[threading.Thread]:
        """Create and return server threads for the given protocol.

        Looks for `create_server_threads(session)` function. Returns empty list if not defined.

        :param protocol: Loaded protocol module.
        :type protocol: ProtocolModule
        :param session: Session configuration for server setup.
        :type session: SessionConfig
        :return: List of thread objects ready to be started.
        :rtype: list[threading.Thread]
        """
        create_server_threads: CreateServersFunc | None = getattr(
            protocol,
            "create_server_threads",
            None,
        )

        if create_server_threads is None:
            return []

        # Defensive conversion to list in case the protocol returns a tuple,
        # generator or other iterable.
        return list(create_server_threads(session))
