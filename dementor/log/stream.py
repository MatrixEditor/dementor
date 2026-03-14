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
# pyright: reportAny=false, reportExplicitAny=false
import typing

from collections import defaultdict
from io import IOBase
from pathlib import Path
from typing import Any, ClassVar, Generic, TypeVar
from typing_extensions import override

from dementor.config import util
from dementor.config.session import SessionConfig
from dementor.config.toml import TomlConfig, Attribute as A
from dementor.log.logger import dm_logger

_T = TypeVar("_T", bound="TomlConfig")

dm_streams: dict[str, "LoggingStream[Any]"] = {}
"""Global registry of active logging streams by name."""


class LoggingStream(Generic[_T]):
    """Abstract base class for streaming log output.

    Defines interface for writing structured or plain log entries to an output stream.
    Designed for both file and in-memory streams. Subclasses must implement `add()`.

    :ivar fp: File-like object for output (opened by subclass).
    :vartype fp: IOBase
    :cvar _name_: Unique identifier for this stream (e.g., `"hosts"`).
    :vartype _name_: str
    :cvar _config_cls_: Configuration class used to load stream settings.
    :vartype _config_cls_: type[TomlConfig]
    """

    _name_: str
    _config_cls_: type[_T]

    def __init__(self, stream: IOBase) -> None:
        """Initialize stream with a file-like object.

        :param stream: Opened file-like object (e.g., `io.TextIOWrapper`).
        :type stream: IOBase
        """
        self.fp: IOBase = stream

    def close(self) -> None:
        """Close the underlying stream and flush buffers."""
        if not self.fp.closed:
            self.fp.flush()
            self.fp.close()

    def write(self, data: str) -> None:
        """Write a line to the stream with newline and flush.

        Automatically encodes string to bytes for binary streams.

        :param data: Line to write (without newline).
        :type data: str
        """
        line = f"{data}\n"
        self.fp.write(line.encode())
        self.fp.flush()

    def write_columns(self, *values: Any, sep: str | None = None) -> None:
        """Write tab-separated columns to stream.

        Useful for structured output (e.g., CSV-like logs).

        :param values: Values to write as columns.
        :type values: Any
        """
        line = (sep or "\t").join(map(str, values))
        self.write(line)

    def add(self, **kwargs: Any) -> None:
        """Add a structured log entry.

        Must be overridden by subclasses to handle specific data formats.

        :param kwargs: Contextual data (e.g., `ip`, `type`, `value`).
        """

    @classmethod
    def start(cls, session: SessionConfig) -> None:
        """Initialize and register this stream type from config.

        Loads config from TOML, resolves path via session, creates directory if needed,
        and registers instance in `dm_streams`.

        :param session: Session configuration for path resolution.
        :type session: SessionConfig
        """
        config = TomlConfig.build_config(cls._config_cls_)
        path = getattr(config, "path", None)
        if path is not None and issubclass(cls, LoggingFileStream):
            path = session.resolve_path(path)
            if not path.parent.exists():
                dm_logger.debug(f"Creating log directory {path.parent}")
                path.parent.mkdir(parents=True, exist_ok=True)

            dm_streams[cls._name_] = cls(path, config)


class LoggingFileStream(LoggingStream[_T]):
    """
    Extension of :class:`LoggingStream` that opens a regular file.

    The file is opened in **append-binary** mode (``ab``) when it already
    exists, otherwise in **write-binary** mode (``wb``).  The parent directory
    is created automatically.

    :param path: Destination file path.
    :type path: str | pathlib.Path
    """

    def __init__(self, path: str | Path, config: _T) -> None:
        """Initialize file stream.

        Opens file in binary append mode if exists, binary write mode otherwise.

        :param path: Path to log file.
        :type path: str | Path
        """
        self.path: Path = Path(path)
        mode = "ab" if self.path.exists() else "wb"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.config: _T = config
        super().__init__(self.path.open(mode))

    def reopen(self) -> None:
        """Close the current file handle (if open) and reopen it in ``wb`` mode."""
        if not self.fp.closed:
            self.fp.close()

        self.fp: IOBase = self.path.open("wb")


class HostsStreamConfig(TomlConfig):
    """Configuration for host IP logging stream.

    Controls whether IPv4 and IPv6 addresses are logged.
    """

    _section_: ClassVar[str] = "Log.Stream.Hosts"
    _fields_: ClassVar[list[A]] = [
        A("path", "Path", default_val=None),
        A("log_ipv4", "IPv4", default_val=True),
        A("log_ipv6", "IPv6", default_val=True),
    ]

    if typing.TYPE_CHECKING:
        path: str
        log_ipv4: bool
        log_ipv6: bool


class HostsStream(LoggingFileStream[HostsStreamConfig]):
    """Log unique host IP addresses to a file.

    Filters by IPv4/IPv6 based on config. Prevents duplicates.

    :cvar _name_: Stream identifier (`"hosts"`).
    :cvar _config_cls_: Config class (`HostsStreamConfig`).
    :ivar hosts: Set of already logged IPs.
    :vartype hosts: set[str]
    :ivar ipv4: Whether to log IPv4 addresses.
    :vartype ipv4: bool
    :ivar ipv6: Whether to log IPv6 addresses.
    :vartype ipv6: bool
    """

    _name_: str = "hosts"
    _config_cls_: type[HostsStreamConfig] = HostsStreamConfig

    def __init__(self, path: str | Path, config: HostsStreamConfig) -> None:
        """Initialize host IP logger.

        :param path: Path to output file.
        :type path: str | Path
        :param config: Loaded configuration.
        :type config: HostsStreamConfig
        """
        super().__init__(path, config)
        self.hosts: set[str] = set()
        self.ipv4: bool = config.log_ipv4
        self.ipv6: bool = config.log_ipv6
        dm_logger.info(f"Logging host IPs to {path} (IPv4={self.ipv4}, IPv6={self.ipv6})")

    @override
    def add(self, **kwargs: Any) -> None:
        """
        Add a new IP address to the log.

        The address is written only once; subsequent attempts are ignored.
        IPv4/IPv6 filtering follows the configuration.

        :param ip: IP address to log.
        :type ip: str, optional
        """
        ip = kwargs.get("ip")
        if ip and ip not in self.hosts:
            if not self.ipv4 and "." in ip:
                return
            if not self.ipv6 and ":" in ip:
                return
            self.write_columns(ip)
            self.hosts.add(ip)


class DNSNamesStreamConfig(TomlConfig):
    """Configuration for DNS query logging stream."""

    _section_: ClassVar[str] = "Log.Stream.DNS"
    _fields_: ClassVar[list[A]] = [
        A("path", "Path", default_val=None),
        # reserved for future extensions
    ]


class DNSNamesStream(LoggingFileStream[DNSNamesStreamConfig]):
    """Log unique DNS query names by type.

    Stores queries in a nested dict: `{record_type: {query}}`.

    :ivar hosts: Nested dict of DNS records by type.
    :vartype hosts: defaultdict[set]
    """

    _name_: str = "dns"
    _config_cls_: type[DNSNamesStreamConfig] = DNSNamesStreamConfig

    def __init__(self, path: str | Path, config: DNSNamesStreamConfig) -> None:
        """Initialize DNS query logger.

        :param path: Path to output file.
        :type path: str | Path
        :param config: Loaded configuration.
        :type config: DNSNamesStreamConfig
        """
        super().__init__(path, config)
        self.hosts: dict[str, set[str]] = defaultdict(set)
        dm_logger.info(f"Logging DNS names to {path}")

    @override
    def add(self, **kwargs: Any) -> None:
        """Add a DNS query if not previously logged.

        :param kwargs: Must contain `type` (e.g., `"A"`, `"AAAA"`) and `name` (domain).
        """
        name = kwargs.get("type")
        query = kwargs.get("name")
        if name and query and query not in self.hosts[name]:
            self.write_columns(name, query)
            self.hosts[name].add(query)


class HashesStreamConfig(TomlConfig):
    """Configuration for hash value logging stream.

    Supports single-file or per-hash-type split output with custom prefixes/suffixes.
    """

    _section_: ClassVar[str] = "Log.Stream.Hashes"
    _fields_: ClassVar[list[A]] = [
        A("path", "Path", default_val=None),
        A("split", "Split", default_val=None),
        A("prefix", "FilePrefix", default_val=None),
        A("suffix", "FileSuffix", default_val=".txt"),
    ]

    if typing.TYPE_CHECKING:
        path: str
        split: bool
        prefix: str
        suffix: str


class HashStreams(LoggingFileStream[HashesStreamConfig]):
    """Log credential hashes to file(s), optionally split by hash type.

    If `split=True`, creates separate files per hash type (e.g., `ntlm_2024-06-15-14-30-22.txt`).
    Uses `util.format_string` for dynamic prefix generation.

    :cvar _name_: Stream identifier (`"hashes"`).
    :cvar _config_cls_: Config class (`HashesStreamConfig`).
    :ivar config: Loaded configuration.
    :vartype config: HashesStreamConfig
    :ivar path: Base output path.
    :vartype path: Path
    :ivar start_time: Timestamp used for dynamic prefixes.
    :vartype start_time: str
    """

    _name_: str = "hashes"
    _config_cls_: type[HashesStreamConfig] = HashesStreamConfig

    def __init__(self, path: str | Path, config: HashesStreamConfig) -> None:
        """Initialize hash logger.

        :param path: Base path (or directory for split mode).
        :type path: str | Path
        :param config: Loaded configuration.
        :type config: HashesStreamConfig
        """
        super().__init__(path if not config.split else "/dev/null", config)
        self.path: Path = Path(path)
        self.start_time: str = util.now()
        dm_logger.info(f"Logging hashes to {path} (split files: {config.split})")

    @override
    def add(self, **kwargs: Any) -> None:
        """Add a hash value, optionally to a split file.

        :param kwargs: Must contain `type` (hash type, e.g., `"ntlm"`) and `value` (hash string).
        """
        hash_type = str(kwargs.get("type")).upper()
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
                    dm_streams[f"HASH_{hash_type}"] = LoggingFileStream(
                        path=target_path,
                        config=TomlConfig(),
                    )
                write_to(f"HASH_{hash_type}", str(hash_value))


def init_streams(session: SessionConfig):
    """Initialize all configured logging streams at startup.

    Calls `.start()` on each stream class to load config and register instances.

    :param session: Session configuration for path resolution.
    :type session: SessionConfig
    """
    HostsStream.start(session)
    DNSNamesStream.start(session)
    HashStreams.start(session)
    session.streams = dm_streams


def add_stream(name: str, stream: LoggingStream[_T]):
    """Manually register a stream instance.

    Useful for dynamic or custom streams.

    :param name: Unique stream identifier.
    :type name: str
    :param stream: Stream instance.
    :type stream: LoggingStream
    """
    dm_streams[name] = stream


def get_stream(name: str) -> LoggingStream[_T] | None:
    """Retrieve a stream by name.

    :param name: Stream identifier.
    :type name: str
    :return: Stream instance or `None` if not found.
    :rtype: LoggingStream | None
    """
    return dm_streams.get(name)


def close_streams(session: SessionConfig):
    """Close all active streams.

    Called during graceful shutdown.

    :param session: Session containing streams registry.
    :type session: SessionConfig
    """
    for stream in session.streams.values():
        stream.close()


def log_to(__name: str, /, **kwargs: Any):
    """Write structured data to a registered stream.

    :param __name: Stream name (e.g., `"hosts"`, `"hashes"`).
    :type __name: str
    :param kwargs: Data to pass to stream's `add()` method.
    """
    if __name in dm_streams:
        dm_streams[__name].add(**kwargs)


def write_to(name: str, line: str):
    """Write a raw line to a stream (no formatting).

    :param name: Stream name.
    :type name: str
    :param line: Raw string to write.
    :type line: str
    """
    if name in dm_streams:
        dm_streams[name].write(line)


def log_host(ip: str):
    """Convenience function to log a host IP to the `"hosts"` stream.

    :param ip: Normalized IP address.
    :type ip: str
    """
    log_to("hosts", ip=ip)
