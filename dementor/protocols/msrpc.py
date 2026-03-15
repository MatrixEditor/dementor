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
from typing_extensions import override
from collections import defaultdict

from dementor.loader import BaseProtocolModule, ApplyConfigFunc
from dementor.config.session import SessionConfig
from dementor.servers import BaseServerThread, ServerThread
from dementor.protocols.msrpc.rpc import MSRPCServer, RPCConfig, RPCConnection

__proto__ = ["MSRPC"]


class MSRPC(BaseProtocolModule):
    name: str = "MSRPC"
    config_ty = RPCConfig
    config_attr = "rpc_config"
    config_enabled_attr = "rpc_enabled"

    @override
    def apply_config(self, session: SessionConfig) -> None:
        super().apply_config(session)
        for module in session.rpc_config.rpc_modules:
            # load custom config
            apply_config_fn: ApplyConfigFunc | None = getattr(
                module, "apply_config", None
            )
            if apply_config_fn:
                apply_config_fn(session)

    @override
    def create_server_threads(self, session: SessionConfig) -> list[BaseServerThread]:
        # connection data will be shared across both servers
        conn_data = defaultdict(RPCConnection)
        return (
            [
                ServerThread(
                    session,
                    session.rpc_config,
                    MSRPCServer,
                    server_address=(session.bind_address, 135),
                    handles=conn_data,
                ),
                ServerThread(
                    session,
                    session.rpc_config,
                    MSRPCServer,
                    server_address=(session.bind_address, session.rpc_config.epm_port),
                    handles=conn_data,
                ),
            ]
            if session.rpc_enabled
            else []
        )
