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

# Type aliases for the optional protocol entry-points
ApplyConfigFunc = typing.Callable[[SessionConfig], None]

DEFAULT_ATTR = "<DEFAULT>"
_ConfigTy = TypeVar("_ConfigTy", bound=TomlConfig, default=TomlConfig)


class BaseProtocolModule(Generic[_ConfigTy]):
    """Base class for all protocol modules."""

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
    __proto__: list[str | type[BaseProtocolModule]]
    apply_config: ApplyConfigFunc | None


class ProtocolLoader:
    def __init__(self) -> None:
        self.rs_path: str = str(pathlib.Path(DEMENTOR_PATH) / "protocols")
        self.search_path: list[str] = [
            str(pathlib.Path(dementor.__file__).parent / "protocols"),
            self.rs_path,
        ]

    # Loading helpers
    def load_protocol(self, protocol_path: str) -> ProtocolModuleType:
        path = pathlib.Path(protocol_path)
        loader = SourceFileLoader(f"protocol.{path.stem}", protocol_path)
        protocol = types.ModuleType(loader.name)
        loader.exec_module(protocol)
        return protocol

    def resolve_protocols(
        self,
        session: SessionConfig | None = None,
    ) -> dict[str, str]:
        protocols: dict[str, str] = {}
        protocol_paths: list[str] = list(self.search_path)

        if session is not None:
            protocol_paths.extend(session.extra_modules)

        for path_str in protocol_paths:
            path = pathlib.Path(path_str)
            if not path.exists():
                # Missing entries are ignored
                continue

            if path.is_file():
                if path.suffix != ".py":
                    continue
                protocols[path.stem] = str(path)
                continue

            for child in path.iterdir():
                if child.suffix != ".py" or child.name == "__init__.py":
                    continue
                protocols[child.stem] = str(child)

        return protocols

    def create_protocols(
        self, paths: dict[str, str], session: SessionConfig
    ) -> dict[str, BaseProtocolModule]:
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

    def create_servers(
        self,
        protocol: BaseProtocolModule,
        session: SessionConfig,
    ) -> list[BaseServerThread]:
        return protocol.create_server_threads(session)


class ProtocolManager:
    def __init__(
        self, session: SessionConfig, loader: ProtocolLoader | None = None
    ) -> None:
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
        for name, protocol in self.protocols.items():
            try:
                servers = self.loader.create_servers(protocol, self.session)
                self.threads[name.lower()] = list(servers)
            except Exception as e:
                dm_logger.error(f"Error creating servers for protocol '{name}': {e}")
                self.threads[name.lower()] = []

    def create_threads(self, name: str) -> None:
        protocol = self.protocols[name.lower()]
        try:
            self.started.discard(name.lower())
            servers = self.loader.create_servers(protocol, self.session)
            self.threads[name.lower()] = list(servers)
        except Exception as e:
            dm_logger.error(f"Error creating servers for protocol '{name}': {e}")
            self.threads[name.lower()] = []

    def start_all(self) -> None:
        for name, thread_list in self.threads.items():
            self._start_protocol(name, thread_list)

    def start(self, protocol_name: str) -> None:
        if protocol_name.lower() not in self.threads:
            raise ValueError(f"Protocol '{protocol_name}' not found")
        thread_list = self.threads[protocol_name.lower()]
        self._start_protocol(protocol_name.lower(), thread_list)

    def _start_protocol(self, name: str, thread_list: list[BaseServerThread]) -> None:
        if name in self.started:
            return  # Already started
        for thread in thread_list:
            thread.daemon = True
            thread.start()
        self.started.add(name)

    def stop_all(self, timeout: float = 5.0) -> None:
        for name in list(self.started):
            self.stop(name, timeout)

    def stop(self, protocol_name: str, timeout: float = 5.0) -> None:
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
        return list(self.protocols.keys())

    def is_running(self, protocol_name: str) -> bool:
        name: str = protocol_name.lower()
        threads = self.threads.get(name, [])
        return any(t.is_running() for t in threads)
