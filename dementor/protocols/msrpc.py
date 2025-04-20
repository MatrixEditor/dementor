from collections import defaultdict
from dementor.config import TomlConfig
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
    return [
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
