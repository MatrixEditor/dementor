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
import threading
import types
import os
import dementor
import typing

from importlib.machinery import SourceFileLoader
from dementor.config.session import SessionConfig
from dementor.paths import DEMENTOR_PATH


ApplyConfigFunc = typing.Callable[[SessionConfig], None]
CreateServersFunc = typing.Callable[[SessionConfig], list[threading.Thread]]


class ProtocolModule(typing.Protocol):
    config: "ProtocolModule | None"
    apply_config: ApplyConfigFunc | None
    create_server_threads: CreateServersFunc | None


class ProtocolLoader:
    def __init__(self) -> None:
        self.rs_path: str = os.path.join(DEMENTOR_PATH, "protocols")
        self.search_path: list[str] = [
            os.path.join(os.path.dirname(dementor.__file__), "protocols"),
            self.rs_path,
        ]

    def load_protocol(self, protocol_path: str) -> types.ModuleType:
        loader = SourceFileLoader("protocol", protocol_path)
        protocol = types.ModuleType(loader.name)
        loader.exec_module(protocol)
        return protocol

    def get_protocols(self, session: SessionConfig | None = None) -> dict[str, str]:
        protocols: dict[str, str] = {}
        protocol_paths: list[str] = list(self.search_path)

        if session is not None:
            protocol_paths.extend(session.extra_modules)

        for path in protocol_paths:
            if not os.path.exists(path):
                continue

            if os.path.isfile(path):
                if not path.endswith(".py"):
                    continue

                protocol_path = path
                name = os.path.basename(path)[:-3]
                protocols[name] = protocol_path
                continue

            # TODO: check for directory
            for filename in os.listdir(path):
                if not filename.endswith(".py") or filename == "__init__.py":
                    continue

                protocol_path = os.path.join(path, filename)
                name = filename[:-3]
                protocols[name] = protocol_path

        return protocols

    def apply_config(self, protocol: ProtocolModule, session: SessionConfig):
        # if config is defined, apply it
        apply_config_fn: ApplyConfigFunc | None = getattr(
            protocol, "apply_config", None
        )
        if apply_config_fn is not None:
            # sgnature is: apply_config(session: SessionConfig)
            apply_config_fn(session)
        else:
            # maybe another submodule?
            if hasattr(protocol, "config"):
                config_mod = protocol.config
                if config_mod is not None:
                    self.apply_config(config_mod, session)

    def create_servers(
        self,
        protocol: ProtocolModule,
        session: SessionConfig,
    ) -> list[threading.Thread]:
        # creates servers for the given protocol (if defined)
        create_server_threads: CreateServersFunc | None = getattr(
            protocol, "create_server_threads", None
        )
        if create_server_threads is None:
            return []

        return create_server_threads(session)
