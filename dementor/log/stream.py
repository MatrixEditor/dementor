from collections import defaultdict
from io import IOBase
from pathlib import Path
from typing import Any, override

from dementor.config.toml import TomlConfig, Attribute as A
from dementor.log.logger import dm_logger

dm_streams = {}


class LoggingConfigExt(TomlConfig):
    _section_ = "Log"
    _fields_ = [
        A("log_capture_hosts", "CaptureHostsTo", None),
    ]


class LoggingStream:
    def __init__(self, stream: IOBase) -> None:
        self.fp = stream

    def close(self) -> None:
        if not self.fp.closed:
            self.fp.flush()
            self.fp.close()

    def write(self, data: str) -> None:
        line = f"{data}\n"
        self.fp.write(line.encode())
        self.fp.flush()

    def write_columns(self, *values: Any) -> None:
        line = "\t".join(map(str, values))
        self.write(line)

    def add(self, **kwargs: Any) -> None:
        pass


class LoggingFileStream(LoggingStream):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        super().__init__(self.path.open("wb"))

    def reopen(self) -> None:
        if not self.fp.closed:
            self.fp.close()

        self.fp = self.path.open("wb")


class HostsStream(LoggingFileStream):
    def __init__(self, path: str | Path) -> None:
        super().__init__(path)
        self.hosts = set()

    @override
    def add(self, **kwargs: Any) -> None:
        ip = kwargs.get("ip")
        if ip and ip not in self.hosts:
            self.write_columns(ip)
            self.hosts.add(ip)


def init_streams(session):
    config = TomlConfig.build_config(LoggingConfigExt)
    if config.log_capture_hosts:
        # relative and absolute paths are supported
        path: Path = session.resolve_path(config.log_capture_hosts)
        if not path.parent.exists():
            dm_logger.debug(f"Creating host log directory {path.parent}")
            path.parent.mkdir(parents=True, exist_ok=True)

        dm_streams["hosts"] = HostsStream(path)
        dm_logger.info(f"Logging hostnames to {path}")

    session.streams = dm_streams


def add_stream(name, stream):
    dm_streams[name] = stream


def close_streams(session):
    for stream in session.streams.values():
        stream.close()


def log_to(name: str, **kwargs):
    if name in dm_streams:
        dm_streams[name].add(**kwargs)


def log_host(ip: str):
    log_to("hosts", ip=ip)
