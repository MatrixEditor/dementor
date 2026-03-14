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
import types
import typing
import pathlib
import dementor

from typing import Generic
from typing_extensions import TypeVar
from importlib.machinery import SourceFileLoader

from dementor.config.util import get_value
from dementor.config.toml import TomlConfig
from dementor.config.session import SessionConfig
from dementor.paths import DEMENTOR_PATH
from dementor.servers import BaseServerThread, ServerThread
from dementor.log.logger import dm_logger

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
DEFAULT_ATTR = "<DEFAULT>"

_ConfigTy = TypeVar("_ConfigTy", bound=TomlConfig, default=TomlConfig)


class BaseProtocolModule(Generic[_ConfigTy]):
    name: str
    config_ty: type[_ConfigTy] | None
    config_attr: str | None
    config_enabled_attr: str | None
    config_list: bool
    poisoner: bool = False
    server_ty: type | None = None

    def _get_config_attr(self) -> str | None:
        attr = getattr(self, "config_attr", None)
        if attr == DEFAULT_ATTR:
            attr = f"{self.name.lower()}_config"
        return attr

    def _get_config_enabled_attr(self) -> str | None:
        attr = getattr(self, "config_enabled_attr", None)
        if attr == DEFAULT_ATTR:
            attr = f"{self.name.lower()}_enabled"
        return attr

    def apply_config(self, session: SessionConfig) -> None:
        config_ty = getattr(self, "config_ty", None)
        config_attr = self._get_config_attr()

        if config_ty is not None and config_attr is not None:
            config_is_list = getattr(self, "config_list", False)
            if config_is_list:
                config = [
                    config_ty(cfg) for cfg in get_value(config_ty._section_, "Server", [])
                ]
            else:
                config = TomlConfig.build_config(config_ty)

            setattr(session, config_attr, config)
        else:
            raise NotImplementedError(
                "apply_config must be implemented by protocol modules if config_ty and config_attr are not set"
            )

    def create_server_thread(
        self, session: SessionConfig, server_config: _ConfigTy
    ) -> BaseServerThread[_ConfigTy]:
        server_ty: type | None = getattr(self, "server_ty", None)
        if server_ty is not None:
            return ServerThread(session, server_config, server_ty)

        raise NotImplementedError(
            "create_server_thread must be implemented by protocol modules"
        )

    def create_server_threads(self, session: SessionConfig) -> list[BaseServerThread]:
        config_attr: str | None = self._get_config_attr()
        config_enabled_attr: str | None = self._get_config_enabled_attr()
        if config_enabled_attr is not None and not getattr(
            session, config_enabled_attr, False
        ):
            return []

        if config_attr is not None:
            config: _ConfigTy | list[_ConfigTy] | None = getattr(
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

        raise NotImplementedError(
            "create_server_threads must be implemented by protocol modules if config_attr is not set"
        )


class ProtocolModuleType(typing.Protocol):
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

    __proto__: list[str | type[BaseProtocolModule]]
    apply_config: ApplyConfigFunc | None


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
    def load_protocol(self, protocol_path: str) -> ProtocolModuleType:
        """Dynamically load a protocol module from a Python file.

        Uses `SourceFileLoader` to import the module without requiring it to be in `sys.path`.

        :param protocol_path: Absolute path to the `.py` protocol file.
        :type protocol_path: str
        :return: Loaded module object.
        :rtype: types.ModuleType
        :raises ImportError: If module cannot be loaded.
        """
        path = pathlib.Path(protocol_path)
        loader = SourceFileLoader(f"protocol.{path.stem}", protocol_path)
        protocol = types.ModuleType(loader.name)
        loader.exec_module(protocol)
        return protocol

    # --------------------------------------------------------------------- #
    # Discovery helpers
    # --------------------------------------------------------------------- #
    def resolve_protocols(
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

    def create_protocols(
        self, paths: dict[str, str], session: SessionConfig
    ) -> dict[str, BaseProtocolModule]:
        """Load and instantiate protocol modules based on session configuration.

        :param session: Session configuration containing protocol paths.
        :type session: SessionConfig
        :return: Dict mapping protocol name to instantiated module object.
        :rtype: dict[str, BaseProtocolModule]
        """
        protocols: dict[str, BaseProtocolModule] = {}
        for path in paths.values():
            module = self.load_protocol(path)
            if hasattr(module, "apply_config"):
                apply_config_fn: ApplyConfigFunc | None = getattr(
                    module, "apply_config", None
                )
                if not callable(apply_config_fn):
                    raise TypeError(f"apply_config in {path} must be a callable function")

                apply_config_fn(session)

            for protocol_ty_name in getattr(module, "__proto__", []):
                protocol_ty = getattr(module, protocol_ty_name, None)
                if isinstance(protocol_ty_name, type):
                    protocol_ty = protocol_ty_name

                if protocol_ty is not None and issubclass(
                    protocol_ty, BaseProtocolModule
                ):
                    protocol = protocol_ty()
                    if protocol.name in protocols:
                        raise ValueError(
                            f"Duplicate protocol name '{protocol.name}' found in {path}"
                        )

                    protocol.apply_config(session)
                    protocols[protocol.name.lower()] = protocol
        return protocols

    # --------------------------------------------------------------------- #
    # Hook dispatchers
    # --------------------------------------------------------------------- #
    def create_servers(
        self,
        protocol: BaseProtocolModule,
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
        return protocol.create_server_threads(session)


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
        if not session.protocols:
            session.protocols = self.loader.resolve_protocols(session)

        self.protocols: dict[str, BaseProtocolModule] = self.loader.create_protocols(
            session.protocols, session
        )
        self.threads: dict[str, list[BaseServerThread]] = {}
        self.started: set[str] = set()

    def create_all_threads(self) -> None:
        """Create server threads for all loaded protocols."""
        for name, protocol in self.protocols.items():
            try:
                servers = self.loader.create_servers(protocol, self.session)
                self.threads[name.lower()] = list(servers)
            except Exception as e:
                # Log error if needed, but for now pass
                dm_logger.error(f"Error creating servers for protocol '{name}': {e}")
                self.threads[name.lower()] = []

    def create_threads(self, name: str) -> None:
        """Create server threads for all loaded protocols."""
        protocol = self.protocols[name.lower()]
        try:
            servers = self.loader.create_servers(protocol, self.session)
            self.threads[name.lower()] = list(servers)
        except Exception as e:
            # Log error if needed, but for now pass
            dm_logger.error(f"Error creating servers for protocol '{name}': {e}")
            self.threads[name.lower()] = []

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
            thread.shutdown()
            if thread.is_alive():
                thread.join(timeout)

            del thread
        self.started.discard(name)

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
        """
        name: str = protocol_name.lower()
        threads = self.threads.get(name, [])
        return any(t.is_running() for t in threads)
