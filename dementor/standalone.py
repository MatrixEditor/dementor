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
import argparse
import asyncio
import tomllib

from scapy.arch import get_if_addr, in6_getifaddr

from dementor.config import SessionConfig, TomlConfig
from dementor import logger, database, config
from dementor.logger import dm_logger
from dementor.loader import ProtocolLoader


def serve(
    interface: str,
    analyze_only: bool = False,
    config_path: str | None = None,
    session: SessionConfig | None = None,
    supress_output: bool = False,
    loop: asyncio.AbstractEventLoop | None = None,
    run_forever: bool = True,
) -> None:
    if session is None:
        session = SessionConfig()

    if config_path:
        try:
            config.init_from_file(config_path)
        except tomllib.TOMLDecodeError as e:
            dm_logger.error(f"Failed to load configuration file: {e}")
            return

    logger.init()
    logger.ProtocolLogger.init_logfile(session)

    if interface and not session.interface:
        session.interface = interface
        try:
            session.ipv4 = get_if_addr(session.interface)
        except ValueError:
            # interface does not exist
            dm_logger.error(
                f"Interface {session.interface} does not exist or is not up, check your configuration"
            )
            return

        session.ipv6 = next(
            (ip[0] for ip in in6_getifaddr() if ip[2] == session.interface), None
        )
        if session.ipv4 == "0.0.0.0" and not session.ipv6:
            # current interface is not available
            dm_logger.error(
                f"Interface {session.interface} is not available, check your configuration"
            )
            return

    session.analysis = analyze_only

    # Setup database for current session
    if not getattr(session, "db", None):
        session.db_config = TomlConfig.build_config(database.DatabaseConfig)
        db_path = database.init_dementor_db(session)
        session.db = database.DementorDB(database.init_engine(db_path), session)

    # Load protocols
    loader = ProtocolLoader()
    protocols = {}
    for name, path in loader.get_protocols(session).items():
        protocol = loader.load_protocol(path)
        protocols[name] = protocol
        loader.apply_config(protocol, session)

    if not supress_output:
        pass

    if not getattr(session, "loop", None):
        session.loop = loop or asyncio.get_event_loop()

    asyncio.set_event_loop(session.loop)
    threads = []
    for name, protocol in protocols.items():
        try:
            servers = loader.create_servers(protocol, session)
            threads.extend(servers)
        except Exception as e:
            dm_logger.exception(f"Failed to create server for protocol {name}: {e}")

    # Start threads
    for thread in threads:
        thread.daemon = True
        thread.start()

    if run_forever:
        try:
            session.loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop_session(session, threads)


def stop_session(session: SessionConfig, threads=None) -> None:
    # 1. stop event loop
    session.loop.stop()

    # 2. close threads
    for thread in threads or []:
        del thread

    # 3. close database
    session.db.close()


# --- main
def main() -> None:
    from impacket.version import version as ImpacketVersion
    from scapy import VERSION as ScapyVersion

    print(
        f"Dementor.py - Running with Scapy v{ScapyVersion} and Impacket v{ImpacketVersion}\n"
    )

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-I",
        "--interface",
        dest="interface",
        metavar="NAME",
        required=True,
        help="Network interface to use (required for poisoning)",
    )
    parser.add_argument(
        "-A",
        "--analyze",
        dest="analyze_only",
        action="store_true",
        help="Only analyze traffic, don't respond to requests",
    )
    parser.add_argument(
        "-c",
        "--config",
        dest="config_path",
        metavar="PATH",
        required=False,
        default=None,
        help="Path to a configuration file (otherwise standard path is used)",
    )

    # these are not used actually (only here for documentation)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--verbose", action="store_true")

    argv = parser.parse_args()
    serve(
        interface=argv.interface,
        analyze_only=argv.analyze_only,
        config_path=argv.config_path,
    )


if __name__ == "__main__":
    main()
