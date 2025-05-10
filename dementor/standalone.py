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
import asyncio
import tomllib
import json
import typer
import pathlib

from typing import List
from typing_extensions import Annotated

from impacket.version import version as ImpacketVersion
from aiosmtpd import __version__ as AiosmtpdVersion
from aioquic import __version__ as AioquicVersion
from scapy import VERSION as ScapyVersion
from scapy.arch import get_if_addr, in6_getifaddr
from pyipp.ipp import VERSION as PyippVersion

from rich import print
from rich.console import Console
from rich.columns import Columns

from dementor import __version__ as DementorVersion
from dementor import logger, database, config
from dementor.config.session import SessionConfig
from dementor.config.toml import TomlConfig
from dementor.logger import dm_logger
from dementor.loader import ProtocolLoader
from dementor.paths import BANNER_PATH


def serve(
    interface: str,
    analyze_only: bool = False,
    config_path: str | None = None,
    session: SessionConfig | None = None,
    supress_output: bool = False,
    loop: asyncio.AbstractEventLoop | None = None,
    run_forever: bool = True,
    éxtra_options: dict | None = None,
) -> tuple | None:
    if config_path:
        try:
            config.init_from_file(config_path)
        except tomllib.TOMLDecodeError as e:
            dm_logger.error(f"Failed to load configuration file: {e}")
            return

    if session is None:
        session = SessionConfig()

    logger.init()
    logger.ProtocolLogger.init_logfile(session)

    if éxtra_options:
        for section, options in éxtra_options.items():
            if section not in config.dm_config:
                config.dm_config[section] = {}

            for key, value in options.items():
                config.dm_config[section][key] = value

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
    if not session.protocols:
        session.protocols = loader.get_protocols(session)

    for name, path in session.protocols.items():
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

    return (session, threads)


def stop_session(session: SessionConfig, threads=None) -> None:
    # 1. stop event loop
    session.loop.stop()

    # 2. close threads
    for thread in threads or []:
        del thread

    # 3. close database
    session.db.close()


_SkippedOption = typer.Option(parser=lambda _: _, hidden=True, expose_value=False)


def parse_options(options: List[str]) -> dict:
    result = {}
    for option in options:
        key, raw_value = option.split("=", 1)
        # Each definition is a key=value pair with an optional section prefix
        if key.count(".") > 1:
            dm_logger.warning(f"Invalid option definition: {option}")
            raise typer.Exit(1)

        append_value = key.endswith("+")
        key = key.removesuffix("+")
        if "." in key:
            section, key = key.rsplit(".", 1)
        else:
            section = "Dementor"

        match raw_value.strip().lower():
            case "true" | "on" | "yes":
                value = True
            case "false" | "off" | "no":
                value = False
            case _:
                raw_value = raw_value.strip()
                value = None
                if raw_value[0] == "[":
                    value = json.loads(raw_value)
                elif raw_value[0] not in ('"', "'"):
                    try:
                        value = int(raw_value)
                    except ValueError:
                        pass

                if value is None:
                    value = raw_value.removeprefix('"').removesuffix('"')

        if section not in result:
            result[section] = {}

        if append_value:
            if key not in result[section]:
                result[section][key] = []
            result[section][key].append(value)
        else:
            result[section][key] = value
    return result


# --- main
def main_print_banner(quiet_mode: bool) -> None:
    banner_file = pathlib.Path(BANNER_PATH)

    if not quiet_mode and not banner_file.exists():
        # fall back to small banner
        quiet_mode = True

    if quiet_mode:
        # only print out scapy and impacket versions
        print(
            f"[bold]Dementor[/bold] - Running with Scapy [white bold]v{ScapyVersion}[/] "
            f"and Impacket [white bold]v{ImpacketVersion}[/]\n",
        )
        return

    text = banner_file.read_text().format(
        dementor_version=DementorVersion,
        scapy_version=ScapyVersion,
        impacket_version=ImpacketVersion,
        aiosmtpd_version=AiosmtpdVersion,
        aioquic_version=AioquicVersion,
        pyipp_version=PyippVersion,
    )
    print(text)


def main_format_config(name: str, value: str) -> str:
    line = f"{name} [white]".ljust(45, ".")
    return f"{line}[/white] {value}"


# TODO: refactor this
def main_print_options(session: SessionConfig, interface):
    console = Console()
    console.rule(style="white", title="Dementor Configuration")
    analyze_only = r"[bold grey]\[Analyze Only][/bold grey]"
    on = r"[bold green]\[ON][/bold green]"
    off = r"[bold red]\[OFF][/bold red]"

    poisoners_lines = ["", "[bold]Poisoners:[/bold]"]
    # REVISIT: creation of poisoners list
    poisoners =("LLMNR", "MDNS", "NBTNS", "SSRP", "SSDP")
    for name in poisoners:
        attr_name = f"{name.lower()}_enabled"
        status = on if getattr(session, attr_name, False) else off
        if session.analysis:
            status = analyze_only

        poisoners_lines.append(main_format_config(name, status))

    poisoners_lines.append("\n[bold]Config:[/bold]")
    mode = (
        r"[bold red]\[Attack][/bold red]"
        if not session.analysis
        else r"[bold blue]\[Analysis][/bold blue]"
    )
    poisoners_lines.append(main_format_config("Mode", mode))
    poisoners_lines.append(main_format_config("Interface", interface))

    protocols_lines = ["", "[bold]Servers:[/bold]"]
    additional_protocols = ["KDC", "NBTDS", "WinRM"]
    protos = (list(session.protocols) or []) + additional_protocols
    for name in sorted(protos):
        if name.upper() in poisoners:
            continue

        attr_name = f"{name.lower()}_enabled"
        value = getattr(session, attr_name, None)
        if value is None:
            continue

        protocols_lines.append(main_format_config(name.upper(), on if value else off))

    columns = Columns(
        [
            "\n".join(protocols_lines),
            "\n".join(poisoners_lines),
        ],
        expand=True,
        align="left",
    )
    console.print(columns)
    console.print()
    console.rule(style="white", title="Log")
    console.print()


def main(
    interface: Annotated[
        str,
        typer.Option(
            "--interface",
            "-I",
            show_default=False,
            metavar="NAME",
            help="Network interface to use (required for poisoning)",
        ),
    ],
    analyze: Annotated[
        bool,
        typer.Option(
            "--analyze",
            "-A",
            help="Only analyze traffic, don't respond to requests",
        ),
    ] = False,
    config_path: Annotated[
        str,
        typer.Option(
            "--config",
            "-c",
            metavar="PATH",
            show_default=False,
            help="Path to a configuration file (otherwise standard path is used)",
        ),
    ] = None,
    options: Annotated[
        List[str],
        typer.Option(
            "--option",
            "-O",
            metavar="KEY=VALUE",
            show_default=False,
            help="Add an extra option to the global configuration file.",
        ),
    ] = None,
    verbose: Annotated[bool, _SkippedOption] = False,
    debug: Annotated[bool, _SkippedOption] = False,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet", "-q", help="Don't print banner at startup", show_default=False
        ),
    ] = False,
) -> None:
    main_print_banner(quiet)

    # prepare options
    extras = parse_options(options or [])
    if config_path:
        try:
            config.init_from_file(config_path)
        except tomllib.TOMLDecodeError as e:
            dm_logger.error(f"Failed to load configuration file: {e}")
            return

    logger.init()

    if extras:
        for section, options in extras.items():
            if section not in config.dm_config:
                config.dm_config[section] = {}

            for key, value in options.items():
                config.dm_config[section][key] = value

    loader = ProtocolLoader()
    session = SessionConfig()
    session.analysis = analyze
    session.protocols = loader.get_protocols(session)

    if not quiet:
        main_print_options(session, interface)

    logger.ProtocolLogger.init_logfile(session)
    serve(interface=interface, session=session, analyze_only=analyze)


def run_from_cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    run_from_cli()
