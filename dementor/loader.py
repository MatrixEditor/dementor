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
from dementor.config.toml import TomlConfig

import os
import threading
import types
import typing
import dementor

from importlib.machinery import SourceFileLoader


from dementor.config.session import SessionConfig
from dementor.paths import DEMENTOR_PATH
from dementor.servers import BaseServerThread, ServerThread

# --------------------------------------------------------------------------- #
# Type aliases for the optional protocol entry‑points
# --------------------------------------------------------------------------- #
ApplyConfigFunc = typing.Callable[[SessionConfig], None]
"""Type alias for function that applies protocol configuration.

Signature: `apply_config(session: SessionConfig) -> None`

Used by protocol modules to customize global configuration based on protocol-specific needs.
"""

CreateServersFunc = typing.Callable[[SessionConfig], list[BaseServerThread]]
"""Type alias for function that creates server threads for a protocol.

Signature: `create_server_threads(session: SessionConfig) -> list[BaseServerThread]`

Returns a list of `threading.Thread` instances configured to run protocol servers.
"""


# --------------------------------------------------------------------------- #
# Structural protocol used for static type checking
# --------------------------------------------------------------------------- #
class BaseProtocolModule:
    name: str
    config_ty: type[TomlConfig] | None
    config_attr: str | None
    config_enabled_attr: str | None
    config_list: bool

    def apply_config(self, session: SessionConfig) -> None:
        config_ty = getattr(self, "config_ty", None)
        config_attr = getattr(self, "config_attr", None)
        if config_ty is not None and config_attr is not None:
            config_is_list = getattr(self, "config_list", False)
            if config_is_list:
                config = list(
                    map(
                        lambda cfg: config_ty.build_config(cfg),
                        getattr(session, config_attr, []),
                    )
                )
            else:
                config = config_ty.build_config(session)

            setattr(session, config_attr, config)
        else:
            raise NotImplementedError(
                "apply_config must be implemented by protocol modules if config_ty and config_attr are not set"
            )

    def create_server_thread(
        self, session: SessionConfig, server_config: TomlConfig
    ) -> BaseServerThread:
        raise NotImplementedError(
            "create_server_thread must be implemented by protocol modules"
        )

    def create_server_threads(self, session: SessionConfig) -> list[BaseServerThread]:
        config_attr: str | None = getattr(self, "config_attr", None)
        config_enabled_attr: str | None = getattr(self, "config_enabled_attr", None)
        if config_enabled_attr is not None and not getattr(
            session, config_enabled_attr, False
        ):
            return []

        if config_attr is not None:
            config: TomlConfig | list[TomlConfig] | None = getattr(
                session, config_attr, None
            )
            threads = []
            if config is not None:
                if isinstance(config, list):
                    threads.extend(
                        [self.create_server_thread(session, cfg) for cfg in config]
                    )
                else:
                    threads.append(self.create_server_thread(session, config))
            return threads
        else:
            raise NotImplementedError(
                "create_server_threads must be implemented by protocol modules if config_attr is not set"
            )


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
        apply_config_fn: ApplyConfigFunc | None = getattr(protocol, "apply_config", None)

        if apply_config_fn is not None:
            # signature is: apply_config(session: SessionConfig)
            apply_config_fn(session)
        # Fallback to a nested config module, if present.
        elif hasattr(protocol, "config"):
            config_mod: ProtocolModule | None = protocol.config
            if config_mod is not None:
                self.apply_config(config_mod, session)

    def create_servers(
        self,
        protocol: ProtocolModule,
        session: SessionConfig,
    ) -> list[BaseServerThread]:
        """Create and return server threads for the given protocol.

        Looks for `create_server_threads(session)` function. Returns empty list if not defined.

        :param protocol: Loaded protocol module.
        :type protocol: ProtocolModule
        :param session: Session configuration for server setup.
        :type session: SessionConfig
        :return: List of thread objects ready to be started.
        :rtype: list[BaseServerThread]
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


class ProtocolManager:
    """Manages loaded protocol modules for a session.

    Provides methods to start and stop protocol services, and retrieve details about each module.
    """

    def __init__(
        self, session: SessionConfig, loader: ProtocolLoader | None = None
    ) -> None:
        """Initialize the manager with a session.

        Sets up protocols and threads for the session.

        :param session: Session configuration.
        :type session: SessionConfig
        """
        self.session: SessionConfig = session
        self.loader: ProtocolLoader = loader or ProtocolLoader()
        self.protocols: dict[str, ProtocolModule] = {}
        if not session.protocols:
            session.protocols = self.loader.get_protocols(session)

        for name, path in session.protocols.items():
            protocol = self.loader.load_protocol(path)
            self.protocols[name] = protocol
            self.loader.apply_config(protocol, session)

        self.threads: dict[str, list[BaseServerThread]] = {}
        for name, protocol in self.protocols.items():
            try:
                servers = self.loader.create_servers(protocol, session)
                self.threads[name.lower()] = list(servers)
            except Exception as e:
                # Log error if needed, but for now pass
                pass

        self.started: set[str] = set()

    def start_all(self) -> None:
        """Start all protocol services."""
        for name, thread_list in self.threads.items():
            self._start_protocol(name, thread_list)

    def start(self, protocol_name: str) -> None:
        """Start a specific protocol service.

        :param protocol_name: Name of the protocol to start.
        :type protocol_name: str
        :raises ValueError: If protocol not found.
        """
        if protocol_name.lower() not in self.threads:
            raise ValueError(f"Protocol '{protocol_name}' not found")
        thread_list = self.threads[protocol_name.lower()]
        self._start_protocol(protocol_name.lower(), thread_list)

    def _start_protocol(self, name: str, thread_list: list[BaseServerThread]) -> None:
        """Internal method to start threads for a protocol."""
        if name in self.started:
            return  # Already started
        for thread in thread_list:
            thread.daemon = True
            thread.start()
        self.started.add(name)

    def stop_all(self, timeout: float = 5.0) -> None:
        """Stop all protocol services.

        :param timeout: Timeout in seconds to wait for threads to stop.
        :type timeout: float
        """
        for name in list(self.started):
            self.stop(name, timeout)

    def stop(self, protocol_name: str, timeout: float = 5.0) -> None:
        """Stop a specific protocol service.

        :param protocol_name: Name of the protocol to stop.
        :type protocol_name: str
        :param timeout: Timeout in seconds to wait for threads to stop.
        :type timeout: float
        :raises ValueError: If protocol not found or not started.
        """
        name = protocol_name.lower()
        if name not in self.threads:
            raise ValueError(f"Protocol '{protocol_name}' not found")
        if name not in self.started:
            return  # Not started
        thread_list = self.threads[name]
        for thread in thread_list:
            if thread.is_alive():
                thread.shutdown()
                thread.join(timeout)
        self.started.discard(name)

    def get_details(self, protocol_name: str) -> dict[str, typing.Any]:
        """Get details about a protocol module.

        :param protocol_name: Name of the protocol.
        :type protocol_name: str
        :return: Dictionary with protocol details.
        :rtype: dict[str, typing.Any]
        :raises ValueError: If protocol not found.
        """
        name = protocol_name.lower()
        if name not in self.protocols:
            raise ValueError(f"Protocol '{protocol_name}' not found")
        protocol = self.protocols[name]
        path = self.session.protocols.get(name, "")
        thread_list = self.threads.get(name, [])
        return {
            "name": name,
            "path": path,
            "thread_count": len(thread_list),
            "running": name in self.started,
            "has_apply_config": hasattr(protocol, "apply_config")
            and protocol.apply_config is not None,
            "has_create_servers": hasattr(protocol, "create_server_threads")
            and protocol.create_server_threads is not None,
        }

    def list_protocols(self) -> list[str]:
        """List all available protocol names.

        :return: List of protocol names.
        :rtype: list[str]
        """
        return list(self.protocols.keys())

    def is_running(self, protocol_name: str) -> bool:
        """Check if a protocol is running.

        :param protocol_name: Name of the protocol.
        :type protocol_name: str
        :return: True if running, False otherwise.
        :rtype: bool
        :raises ValueError: If protocol not found.
        """
        name = protocol_name.lower()
        if name not in self.protocols:
            raise ValueError(f"Protocol '{protocol_name}' not found")
        return name in self.started
