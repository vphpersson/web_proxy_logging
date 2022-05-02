from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class BodyLogEntry:
    bytes: int
    content: Optional[str] = None
    decompressed_content: Optional[str] = None


@dataclass
class ResponseLogEntry:
    body: BodyLogEntry
    bytes: int
    headers: Optional[dict[str, str]]
    status_code: int
    mime_type: Optional[str] = None
    mime_type_content_type: Optional[list[str]] = None


@dataclass
class RequestLogEntry:
    bytes: int
    headers: Optional[dict[str, str]]
    method: str
    mime_type: Optional[str] = None
    mime_type_content_type: Optional[list[str]] = None
    body: Optional[BodyLogEntry] = None
    referrer: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class HttpLogEntry:
    request: RequestLogEntry
    response: ResponseLogEntry
    version: str


@dataclass
class UrlLogEntry:
    domain: str
    full: str
    original: str
    path: str
    port: int
    scheme: str
    subdomain: str
    top_level_domain: str
    query_keys: Optional[list[str]]
    query_values: Optional[list[str]]
    extension: Optional[str] = None
    fragment: Optional[str] = None
    password: Optional[str] = None
    username: Optional[str] = None
    query: Optional[str] = None


@dataclass
class ClientLogEntry:
    address: str
    ip: str
    port: int


@dataclass
class ServerLogEntry:
    address: str
    ip: Optional[str]
    port: Optional[int]


@dataclass
class UserAgentOSLogEntry:
    family: str
    version: str


@dataclass
class UserAgentDeviceLogEntry:
    name: str


@dataclass
class UserAgentLogEntry:
    original: str
    device: Optional[UserAgentDeviceLogEntry] = None
    name: Optional[str] = None
    os: Optional[UserAgentOSLogEntry] = None
    version: Optional[str] = None


# TODO: Consider `network.forwarded_ip`.
@dataclass
class NetworkLogEntry:
    protocol: str
    transport: Optional[str] = None
    type: Optional[str] = None


@dataclass
class EventLogEntry:
    created: datetime
    timezone: str
    start: Optional[datetime] = None
    end: Optional[datetime] = None


@dataclass
class LogEntry:
    http: HttpLogEntry
    url: UrlLogEntry
    client: ClientLogEntry
    server: ServerLogEntry
    network: NetworkLogEntry
    event: EventLogEntry
    user_agent: Optional[UserAgentLogEntry]
