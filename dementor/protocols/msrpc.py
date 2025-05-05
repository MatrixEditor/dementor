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
from collections import defaultdict
from dementor.config.toml import TomlConfig
from dementor.servers import ServerThread
from dementor.protocols.msrpc.rpc import MSRPCServer, RPCConfig, RPCConnection


def apply_config(session):
    session.rpc_config = TomlConfig.build_config(RPCConfig)

    for module in session.rpc_config.rpc_modules:
        # load custom config
        if hasattr(module, "apply_config"):
            module.apply_config(session)


def create_server_threads(session):
    addr = "::" if session.ipv6 else session.ipv4  # necessary

    # connection data will be shared across both servers
    conn_data = defaultdict(RPCConnection)
    return (
        [
            ServerThread(
                session,
                MSRPCServer,
                server_address=(addr, 135),
                handles=conn_data,
            ),
            ServerThread(
                session,
                MSRPCServer,
                server_address=(addr, session.rpc_config.epm_port),
                handles=conn_data,
            ),
        ]
        if session.rpc_enabled
        else []
    )
