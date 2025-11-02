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
# pyright: reportUninitializedInstanceVariable=false
from collections import defaultdict
from io import IOBase
from pathlib import Path
from typing import Any, override

from dementor.config import util
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.log.logger import dm_logger

dm_streams = {}


class LoggingStream:
    _name_: str
    _config_cls_: type[TomlConfig]

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

    @classmethod
    def start(cls, session) -> None:
        config = TomlConfig.build_config(cls._config_cls_)
        path = config.path
        if path is not None:
            path = session.resolve_path(path)
            if not path.parent.exists():
                dm_logger.debug(f"Creating log directory {path.parent}")
                path.parent.mkdir(parents=True, exist_ok=True)

            dm_streams[cls._name_] = cls(path, config)


class LoggingFileStream(LoggingStream):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.exists():
            mode = "ab"
        else:
            mode = "wb"

        # make sure not error is thrown
        self.path.parent.mkdir(parents=True, exist_ok=True)
        super().__init__(self.path.open(mode))

    def reopen(self) -> None:
        if not self.fp.closed:
            self.fp.close()

        self.fp = self.path.open("wb")


class HostsStreamConfig(TomlConfig):
    _section_ = "Log.Stream.Hosts"
    _fields_ = [
        A("path", "Path", default_val=None),
        A("log_ipv4", "IPv4", default_val=True),
        A("log_ipv6", "IPv6", default_val=True),
    ]


class HostsStream(LoggingFileStream):
    _name_ = "hosts"
    _config_cls_ = HostsStreamConfig

    def __init__(self, path: str | Path, config: HostsStreamConfig) -> None:
        super().__init__(path)
        self.hosts = set()
        self.ipv4 = config.log_ipv4
        self.ipv6 = config.log_ipv6
        dm_logger.info(
            f"Logging host IPs to {path} (IPv4={self.ipv4}, IPv6={self.ipv6})"
        )

    @override
    def add(self, **kwargs: Any) -> None:
        ip = kwargs.get("ip")
        if ip and ip not in self.hosts:
            if not self.ipv4 and "." in ip:
                return

            if not self.ipv6 and ":" in ip:
                return

            self.write_columns(ip)
            self.hosts.add(ip)


class DNSNamesStreamConfig(TomlConfig):
    _section_ = "Log.Stream.DNS"
    _fields_ = [
        A("path", "Path", default_val=None),
        # reserved for future extensions
    ]


class DNSNamesStream(LoggingFileStream):
    _name_ = "dns"
    _config_cls_ = DNSNamesStreamConfig

    def __init__(self, path: str | Path, config: DNSNamesStreamConfig) -> None:
        super().__init__(path)
        self.hosts = defaultdict(set)
        dm_logger.info(f"Logging DNS names to {path}")

    @override
    def add(self, **kwargs: Any) -> None:
        name = kwargs.get("type")
        query = kwargs.get("name")
        if name and query:
            if query not in self.hosts[name]:
                self.write_columns(name, query)
                self.hosts[name].add(query)


class HashesStreamConfig(TomlConfig):
    _section_ = "Log.Stream.Hashes"
    _fields_ = [
        A("path", "Path", default_val=None),
        A("split", "Split", default_val=None),
        A("prefix", "FilePrefix", default_val=None),
        A("suffix", "FileSuffix", default_val=".txt"),
    ]


class HashStreams(LoggingFileStream):
    _name_ = "hashes"
    _config_cls_ = HashesStreamConfig

    def __init__(self, path: str | Path, config: HashesStreamConfig) -> None:
        super().__init__(path if not config.split else "/dev/null")
        self.config = config
        self.path = Path(path)
        self.start_time = util.now()
        dm_logger.info(f"Logging hashes to {path} (split files: {config.split})")

    @override
    def add(self, **kwargs: Any) -> None:
        hash_type = kwargs.get("type").upper()
        hash_value = kwargs.get("value")
        if hash_type and hash_value:
            if not self.config.split:
                self.write(f"{hash_type} {hash_value}")
            else:
                prefix = self.config.prefix or ""
                suffix = self.config.suffix
                if not prefix:
                    prefix = f"{hash_type}_{self.start_time}"
                else:
                    prefix = util.format_string(
                        prefix,
                        {
                            "hash_type": hash_type,
                            "time": self.start_time,
                        },
                    )

                target_path = Path(self.path) / f"{prefix}{suffix}"
                if not target_path.exists():
                    # create a new logging stream for that hash type
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    dm_streams[f"HASH_{hash_type}"] = LoggingFileStream(target_path)

                write_to(f"HASH_{hash_type}", str(hash_value))


def init_streams(session):
    HostsStream.start(session)
    DNSNamesStream.start(session)
    HashStreams.start(session)
    session.streams = dm_streams


def add_stream(name: str, stream: LoggingStream):
    dm_streams[name] = stream


def get_stream(name: str) -> LoggingStream | None:
    return dm_streams.get(name)


def close_streams(session):
    for stream in session.streams.values():
        stream.close()


def log_to(__name: str, /, **kwargs):
    if __name in dm_streams:
        dm_streams[__name].add(**kwargs)


def write_to(name: str, line: str):
    if name in dm_streams:
        dm_streams[name].write(line)


def log_host(ip: str):
    log_to("hosts", ip=ip)
